#!/usr/bin/env python3
"""Post-build script: patch the integrity HMAC into the jitterentropy-rustrngd binary.

Finds the JENTRNG_INTG_TAG tag in the binary, reads the embedded 32-byte HMAC key,
computes HMAC-SHA3-256 over all PT_LOAD segments with PF_X (executable),
and overwrites the 32-byte placeholder with the computed digest.

Uses program headers (not section headers) so the runtime check works on
stripped binaries.
"""

import hmac
import struct
import sys
from typing import Union

INTEGRITY_TAG = b"JENTRNG_INTG_TAG"
PLACEHOLDER_BYTE = 0xEE

EI_MAGIC = b"\x7fELF"
EI_CLASS = 4
EI_DATA = 5

PT_LOAD = 1
PF_X = 1


def read_u16(data: Union[bytes, bytearray], offset: int, le: bool) -> int:
    fmt = "<H" if le else ">H"
    return struct.unpack_from(fmt, data, offset)[0]


def read_u32(data: Union[bytes, bytearray], offset: int, le: bool) -> int:
    fmt = "<I" if le else ">I"
    return struct.unpack_from(fmt, data, offset)[0]


def read_u64(data: Union[bytes, bytearray], offset: int, le: bool) -> int:
    fmt = "<Q" if le else ">Q"
    return struct.unpack_from(fmt, data, offset)[0]


class ElfInfo:
    def __init__(self, data: Union[bytes, bytearray]):
        if len(data) < 64:
            raise ValueError("ELF file too small")
        if data[:4] != EI_MAGIC:
            raise ValueError("not an ELF file")

        self.is_64 = data[EI_CLASS] == 2
        self.le = data[EI_DATA] == 1

        if self.is_64:
            self.phoff = read_u64(data, 32, self.le)
            self.phentsize = read_u16(data, 54, self.le)
            self.phnum = read_u16(data, 56, self.le)
        else:
            self.phoff = read_u32(data, 28, self.le)
            self.phentsize = read_u16(data, 42, self.le)
            self.phnum = read_u16(data, 44, self.le)


def collect_exec_load_segments(data: Union[bytes, bytearray], info: ElfInfo) -> list[tuple[int, int]]:
    if info.phnum == 0 or info.phoff == 0:
        raise ValueError("no program headers")

    segments = []

    for idx in range(info.phnum):
        off = info.phoff + idx * info.phentsize
        if off + info.phentsize > len(data):
            raise ValueError(f"program header entry {idx} extends beyond file")

        p_type = read_u32(data, off, info.le)
        if p_type != PT_LOAD:
            continue

        if info.is_64:
            p_flags = read_u32(data, off + 4, info.le)
            p_offset = read_u64(data, off + 8, info.le)
            p_filesz = read_u64(data, off + 32, info.le)
        else:
            p_flags = read_u32(data, off + 24, info.le)
            p_offset = read_u32(data, off + 4, info.le)
            p_filesz = read_u32(data, off + 16, info.le)

        if not (p_flags & PF_X):
            continue

        if p_filesz == 0:
            continue
        if p_offset + p_filesz > len(data):
            raise ValueError(f"executable load segment {idx} extends beyond file")

        segments.append((p_offset, p_filesz))

    if not segments:
        raise ValueError("no executable load segments found")

    segments.sort(key=lambda s: s[0])
    return segments


def find_tag_offset(data: Union[bytes, bytearray]) -> int:
    offset = data.find(INTEGRITY_TAG)
    if offset == -1:
        raise ValueError(f"integrity tag {INTEGRITY_TAG!r} not found in binary")
    return offset


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <binary_path>", file=sys.stderr)
        sys.exit(1)

    binary_path = sys.argv[1]

    with open(binary_path, "rb") as f:
        data = bytearray(f.read())

    info = ElfInfo(data)
    segments = collect_exec_load_segments(data, info)

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

    code_data = b"".join(
        data[offset : offset + size] for offset, size in segments
    )

    mac = hmac.new(key, code_data, "sha3_256").digest()

    data[hmac_off : hmac_off + 32] = mac

    with open(binary_path, "wb") as f:
        f.write(data)

    print(f"Patched integrity HMAC in {binary_path}")
    for offset, size in segments:
        print(f"  hashed segment  offset=0x{offset:08x}  size={size}")
    print(f"  tag at offset 0x{tag_off:08x}")
    print(f"  HMAC: {mac.hex()}")


if __name__ == "__main__":
    main()
