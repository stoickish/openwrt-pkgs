#!/usr/bin/env python3
"""Post-build script: patch the integrity HMAC into the jitterentropy-rustrngd binary.

Finds the JENTRNG_INTG_TAG tag in the binary, reads the embedded 32-byte HMAC key,
computes HMAC-SHA3-256 over all executable (.text) code regions, and overwrites the
32-byte placeholder with the computed digest.

Usage:
    python3 patch-integrity.py <binary_path>
"""

import hmac
import struct
import sys

INTEGRITY_TAG = b"JENTRNG_INTG_TAG"
PLACEHOLDER_BYTE = 0xEE

EI_MAGIC = b"\x7fELF"
EI_CLASS = 4
EI_DATA = 5

SHF_EXECINSTR = 0x4


def read_u16(data: bytes, offset: int, le: bool) -> int:
    fmt = "<H" if le else ">H"
    return struct.unpack_from(fmt, data, offset)[0]


def read_u32(data: bytes, offset: int, le: bool) -> int:
    fmt = "<I" if le else ">I"
    return struct.unpack_from(fmt, data, offset)[0]


def read_u64(data: bytes, offset: int, le: bool) -> int:
    fmt = "<Q" if le else ">Q"
    return struct.unpack_from(fmt, data, offset)[0]


class ElfInfo:
    def __init__(self, data: bytes):
        if len(data) < 64:
            raise ValueError("ELF file too small")
        if data[:4] != EI_MAGIC:
            raise ValueError("not an ELF file")

        self.is_64 = data[EI_CLASS] == 2
        self.le = data[EI_DATA] == 1

        if self.is_64:
            self.shoff = read_u64(data, 40, self.le)
            self.shentsize = read_u16(data, 58, self.le)
            self.shnum = read_u16(data, 60, self.le)
            self.shstrndx = read_u16(data, 62, self.le)
        else:
            self.shoff = read_u32(data, 32, self.le)
            self.shentsize = read_u16(data, 46, self.le)
            self.shnum = read_u16(data, 48, self.le)
            self.shstrndx = read_u16(data, 50, self.le)


class SectionInfo:
    def __init__(self, info: ElfInfo, data: bytes, idx: int):
        off = info.shoff + idx * info.shentsize

        if info.is_64:
            self.name_off = read_u32(data, off, info.le)
            self.flags = read_u64(data, off + 8, info.le)
            self.offset = read_u64(data, off + 24, info.le)
            self.size = read_u64(data, off + 32, info.le)
        else:
            self.name_off = read_u32(data, off, info.le)
            self.flags = read_u32(data, off + 8, info.le)
            self.offset = read_u32(data, off + 16, info.le)
            self.size = read_u32(data, off + 20, info.le)


def shstr_lookup(data: bytes, shstrtab: SectionInfo, off: int) -> bytes | None:
    start = shstrtab.offset + off
    if start >= len(data):
        return None
    try:
        end = data.index(0, start)
    except ValueError:
        end = len(data)
    return data[start:end]


def find_executable_sections(data: bytes, info: ElfInfo) -> list[tuple[int, int, bytes]]:
    if info.shstrndx >= info.shnum:
        raise ValueError("invalid shstrndx")

    shstrtab = SectionInfo(info, data, info.shstrndx)
    sections = []

    for idx in range(info.shnum):
        if idx == info.shstrndx:
            continue
        sec = SectionInfo(info, data, idx)
        if not (sec.flags & SHF_EXECINSTR):
            continue
        name = shstr_lookup(data, shstrtab, sec.name_off)
        if name is None:
            continue
        # Exclude PLT sections — the trampolines may change at load time
        # due to lazy binding resolution.  .text, .init, .fini are stable.
        if name.startswith(b".plt"):
            continue
        if sec.offset + sec.size > len(data):
            raise ValueError(f"section {name!r} extends beyond file")
        sections.append((sec.offset, sec.size, name))

    return sections


def find_tag_offset(data: bytes) -> int:
    offset = data.find(INTEGRITY_TAG)
    if offset == -1:
        raise ValueError(
            f"integrity tag {INTEGRITY_TAG!r} not found in binary"
        )
    return offset


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <binary_path>", file=sys.stderr)
        sys.exit(1)

    binary_path = sys.argv[1]

    with open(binary_path, "rb") as f:
        data = bytearray(f.read())

    info = ElfInfo(data)
    sections = find_executable_sections(data, info)

    if not sections:
        print("ERROR: no executable sections found", file=sys.stderr)
        sys.exit(1)

    tag_off = find_tag_offset(data)
    key_off = tag_off + 16
    hmac_off = tag_off + 48

    key = bytes(data[key_off : key_off + 32])

    placeholder = bytes(data[hmac_off : hmac_off + 32])
    expected_placeholder = bytes([PLACEHOLDER_BYTE] * 32)
    if placeholder != expected_placeholder:
        print(
            "WARNING: HMAC slot already contains non-placeholder data; re-patching",
            file=sys.stderr,
        )

    sections.sort(key=lambda s: s[0])
    code_data = b"".join(
        data[offset : offset + size] for offset, size, _name in sections
    )

    mac = hmac.new(key, code_data, "sha3_256").digest()

    data[hmac_off : hmac_off + 32] = mac

    with open(binary_path, "wb") as f:
        f.write(data)

    print(f"Patched integrity HMAC in {binary_path}")
    for offset, size, name in sections:
        print(f"  hashed {name.decode('ascii', errors='replace'):12s}  offset=0x{offset:08x}  size={size}")
    print(f"  tag at offset 0x{tag_off:08x}")
    print(f"  HMAC: {mac.hex()}")


if __name__ == "__main__":
    main()
