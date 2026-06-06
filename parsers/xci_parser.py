"""
XCI / HFS0 Binary Parser
=========================
Parses Nintendo Switch XCI files (gamecard HFS0 containers).
XCI uses a layered HFS0 structure:
  - Root HFS0: contains Update, Normal, Secure partitions
  - Each partition is itself an HFS0 container

HFS0 Layout:
  Offset 0x00: Magic "HFS0" (4 bytes)
  Offset 0x04: Number of files (u32 LE)
  Offset 0x08: String table size (u32 LE)
  Offset 0x0C: Reserved (4 bytes)
  Offset 0x10: File table entries (24 bytes each)
  Offset 0x10 + N*24: String table
  Then: File data
"""

import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from parsers.nsp_parser import PFS0FileEntry


@dataclass
class HFS0Header:
    """Parsed HFS0 header."""
    magic: bytes
    num_files: int
    string_table_size: int
    reserved: bytes


@dataclass
class XCIPartition:
    """A partition within an XCI file."""
    name: str
    offset: int
    size: int
    hfs0_header: Optional[HFS0Header] = None
    entries: List[PFS0FileEntry] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class XCIParser:
    """Parse and analyze XCI (HFS0) files."""

    MAGIC = b"HFS0"
    ENTRY_SIZE = 24

    # Standard XCI partition names
    KNOWN_PARTITIONS = {"update", "normal", "secure"}

    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs",
        ".js", ".py", ".sh", ".msi", ".scr", ".com",
    }

    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        self.file_size = self.filepath.stat().st_size
        self.header: Optional[HFS0Header] = None
        self.partitions: List[XCIPartition] = []
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def parse(self) -> bool:
        """Parse the XCI file. Returns True on success."""
        try:
            with open(self.filepath, "rb") as f:
                return self._parse_stream(f)
        except Exception as e:
            self.errors.append(f"Failed to parse: {e}")
            return False

    def _parse_stream(self, f) -> bool:
        """Parse from an open file stream."""
        f.seek(0)
        header_data = f.read(16)
        if len(header_data) < 16:
            self.errors.append("File too small for HFS0 header")
            return False

        magic = header_data[0:4]
        num_files, string_table_size = struct.unpack_from("<II", header_data, 4)

        if magic != self.MAGIC:
            self.errors.append(
                f"Invalid magic: expected {self.MAGIC!r}, got {magic!r}"
            )
            return False

        self.header = HFS0Header(
            magic=magic,
            num_files=num_files,
            string_table_size=string_table_size,
            reserved=header_data[12:16],
        )

        # ── Sanity checks (mirrors NSP parser limits) ──
        if num_files > 10000:
            self.errors.append(
                f"Unreasonable file count: {num_files} (likely corrupt/malicious)"
            )
            return False

        if string_table_size > 10_000_000:
            self.errors.append(
                f"Unreasonable string table size: {string_table_size}"
            )
            return False

        # ── Read file table ──
        file_table_size = num_files * self.ENTRY_SIZE
        file_table_data = f.read(file_table_size)
        if len(file_table_data) < file_table_size:
            self.errors.append("Truncated file table")
            return False

        string_table_data = f.read(string_table_size)
        if len(string_table_data) < string_table_size:
            self.errors.append("Truncated string table")
            return False

        string_table = string_table_data.decode("utf-8", errors="replace")

        data_start = 16 + file_table_size + string_table_size

        # ── Parse partitions ──
        for i in range(num_files):
            entry_offset = i * self.ENTRY_SIZE
            offset, size, name_offset, _ = struct.unpack_from(
                "<QQII", file_table_data, entry_offset
            )

            # Resolve name
            name = ""
            if name_offset < len(string_table):
                end = string_table.find("\x00", name_offset)
                if end == -1:
                    end = len(string_table)
                name = string_table[name_offset:end]

            partition = XCIPartition(
                name=name,
                offset=offset,
                size=size,
            )

            # Validate partition name
            if name.lower() not in self.KNOWN_PARTITIONS:
                self.warnings.append(
                    f"Unusual partition name: '{name}' "
                    f"(expected one of {self.KNOWN_PARTITIONS})"
                )

            # Parse inner HFS0
            abs_offset = data_start + offset
            if abs_offset + size <= self.file_size:
                self._parse_inner_hfs0(f, partition, abs_offset)

            self.partitions.append(partition)

        return True

    def _parse_inner_hfs0(
        self, f, partition: XCIPartition, base_offset: int
    ):
        """Parse an inner HFS0 container within a partition."""
        f.seek(base_offset)
        header_data = f.read(16)

        if len(header_data) < 16:
            partition.errors.append("Truncated inner HFS0 header")
            return

        magic = header_data[0:4]
        if magic != self.MAGIC:
            partition.errors.append(
                f"Inner partition is not HFS0: got {magic!r}"
            )
            return

        num_files, string_table_size = struct.unpack_from("<II", header_data, 4)
        partition.hfs0_header = HFS0Header(
            magic=magic,
            num_files=num_files,
            string_table_size=string_table_size,
            reserved=header_data[12:16],
        )

        if num_files > 10000:
            partition.errors.append(
                f"Unreasonable file count in inner HFS0: {num_files}"
            )
            return
        if string_table_size > 10_000_000:
            partition.errors.append(
                f"Unreasonable string table size in inner HFS0: {string_table_size}"
            )
            return

        file_table_size = num_files * self.ENTRY_SIZE
        file_table_data = f.read(file_table_size)
        if len(file_table_data) < file_table_size:
            partition.errors.append("Truncated inner HFS0 file table")
            return
        string_table_data = f.read(string_table_size)
        if len(string_table_data) < string_table_size:
            partition.errors.append("Truncated inner HFS0 string table")
            return
        inner_string_table = string_table_data.decode("utf-8", errors="replace")

        inner_data_start = (
            base_offset + 16 + file_table_size + string_table_size
        )

        for i in range(num_files):
            entry_off = i * self.ENTRY_SIZE
            offset, size, name_offset, _ = struct.unpack_from(
                "<QQII", file_table_data, entry_off
            )

            entry = PFS0FileEntry(
                index=i, offset=offset, size=size, name_offset=name_offset
            )

            # Resolve name
            if name_offset < len(inner_string_table):
                end = inner_string_table.find("\x00", name_offset)
                if end == -1:
                    end = len(inner_string_table)
                entry.name = inner_string_table[name_offset:end]

            # Validate extension
            ext = Path(entry.name).suffix.lower() if entry.name else ""
            if ext in self.SUSPICIOUS_EXTENSIONS:
                entry.is_suspicious = True
                entry.suspicion_reasons.append(
                    f"Suspicious extension in XCI: {ext}"
                )

            # Compute hashes
            abs_file_offset = inner_data_start + offset
            if abs_file_offset + size <= self.file_size:
                f.seek(abs_file_offset)
                sha256 = hashlib.sha256()
                md5 = hashlib.md5()
                sha1 = hashlib.sha1()
                remaining = size
                while remaining > 0:
                    chunk = f.read(min(remaining, 65536))
                    if not chunk:
                        break
                    sha256.update(chunk)
                    md5.update(chunk)
                    sha1.update(chunk)
                    remaining -= len(chunk)
                entry.sha256 = sha256.hexdigest()
                entry.md5 = md5.hexdigest()
                entry.sha1 = sha1.hexdigest()
            else:
                entry.is_suspicious = True
                entry.suspicion_reasons.append(
                    "File data extends beyond container"
                )

            partition.entries.append(entry)
