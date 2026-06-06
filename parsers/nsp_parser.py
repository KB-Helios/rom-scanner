"""
NSP / PFS0 Binary Parser
========================
Parses Nintendo Switch NSP files (PFS0 container format).
Extracts file table, hashes each entry, and validates structure.

PFS0 Layout:
  Offset 0x00: Magic "PFS0" (4 bytes)
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


@dataclass
class PFS0FileEntry:
    """A single file entry inside a PFS0 container."""
    index: int
    offset: int
    size: int
    name_offset: int
    name: str = ""
    sha256: str = ""
    md5: str = ""
    sha1: str = ""
    is_suspicious: bool = False
    suspicion_reasons: List[str] = field(default_factory=list)


@dataclass
class PFS0Header:
    """Parsed PFS0 header."""
    magic: bytes
    num_files: int
    string_table_size: int
    reserved: bytes


class NSPParser:
    """Parse and analyze NSP (PFS0) files."""

    MAGIC = b"PFS0"
    ENTRY_SIZE = 24  # Each file table entry is 24 bytes

    # Known safe file extensions in NSP containers
    KNOWN_EXTENSIONS = {
        ".nca", ".cnmt.nca", ".nsp", ".tik", ".cert",
        ".xml", ".npdm", ".nstt", ".nacd",
    }

    # Suspicious extensions that shouldn't appear in a clean NSP
    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs",
        ".js", ".py", ".sh", ".msi", ".scr", ".com",
        ".hta", ".wsf", ".lnk", ".inf",
    }

    # Known Nintendo CA certificates (CNMT signatures)
    KNOWN_CERT_NAMES = {
        "NNCA00000003",  # Production CA
        "NNCA00000004",  # Dev CA
    }

    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        self.file_size = self.filepath.stat().st_size
        self.header: Optional[PFS0Header] = None
        self.entries: List[PFS0FileEntry] = []
        self.string_table: str = ""
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def parse(self) -> bool:
        """Parse the NSP file. Returns True on success."""
        try:
            with open(self.filepath, "rb") as f:
                return self._parse_stream(f)
        except Exception as e:
            self.errors.append(f"Failed to parse: {e}")
            return False

    def _parse_stream(self, f) -> bool:
        """Parse from an open file stream."""
        # ── Read header ──
        header_data = f.read(16)
        if len(header_data) < 16:
            self.errors.append("File too small to contain PFS0 header")
            return False

        magic = header_data[0:4]
        num_files, string_table_size = struct.unpack_from("<II", header_data, 4)
        reserved = header_data[12:16]

        if magic != self.MAGIC:
            self.errors.append(
                f"Invalid magic: expected {self.MAGIC!r}, got {magic!r}"
            )
            return False

        self.header = PFS0Header(
            magic=magic,
            num_files=num_files,
            string_table_size=string_table_size,
            reserved=reserved,
        )

        # ── Sanity checks ──
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

        # ── Read string table ──
        string_table_data = f.read(string_table_size)
        if len(string_table_data) < string_table_size:
            self.errors.append("Truncated string table")
            return False

        self.string_table = string_table_data.decode("utf-8", errors="replace")

        # ── Parse entries ──
        data_start = 16 + file_table_size + string_table_size

        for i in range(num_files):
            entry_offset = i * self.ENTRY_SIZE
            offset, size, name_offset, _ = struct.unpack_from(
                "<QQII", file_table_data, entry_offset
            )
            entry = PFS0FileEntry(
                index=i,
                offset=offset,
                size=size,
                name_offset=name_offset,
            )

            # Resolve name from string table
            if name_offset < len(self.string_table):
                end = self.string_table.find("\x00", name_offset)
                if end == -1:
                    end = len(self.string_table)
                entry.name = self.string_table[name_offset:end]

            self.entries.append(entry)

        # ── Validate & hash entries ──
        for entry in self.entries:
            self._validate_entry(entry, data_start, f)

        return True

    def _validate_entry(self, entry: PFS0FileEntry, data_start: int, f):
        """Validate a single file entry and compute its hashes."""
        abs_offset = data_start + entry.offset

        # Check: offset + size within file bounds
        if abs_offset + entry.size > self.file_size:
            entry.is_suspicious = True
            entry.suspicion_reasons.append(
                f"File data extends beyond container "
                f"(offset={abs_offset}, size={entry.size}, "
                f"container={self.file_size})"
            )
            return  # Can't hash if out of bounds

        # Check: empty name
        if not entry.name:
            entry.is_suspicious = True
            entry.suspicion_reasons.append("Empty filename")

        # Check: suspicious extension
        ext = Path(entry.name).suffix.lower() if entry.name else ""
        if ext in self.SUSPICIOUS_EXTENSIONS:
            entry.is_suspicious = True
            entry.suspicion_reasons.append(
                f"Suspicious extension: {ext} (should not appear in NSP)"
            )

        # Check: unusually large single file (could be payload hiding)
        if entry.size > self.file_size * 0.95 and len(self.entries) > 2:
            entry.suspicion_reasons.append(
                f"Single entry is {entry.size/self.file_size*100:.1f}% "
                f"of container — possible padding exploit"
            )

        # Check: zero-size files
        if entry.size == 0 and entry.name:
            entry.suspicion_reasons.append("Zero-size file entry")

        # ── Compute hashes ──
        f.seek(abs_offset)
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()

        remaining = entry.size
        while remaining > 0:
            chunk = f.read(min(remaining, 65536))
            if not chunk:
                entry.suspicion_reasons.append(
                    "Unexpected EOF while reading file data"
                )
                break
            sha256.update(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            remaining -= len(chunk)

        entry.sha256 = sha256.hexdigest()
        entry.md5 = md5.hexdigest()
        entry.sha1 = sha1.hexdigest()

        if entry.suspicion_reasons:
            entry.is_suspicious = True
