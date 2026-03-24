#!/usr/bin/env python3
"""Generate smaller embedded JIT templates (DLL/HCK/PDB) for LLVM JITPDB.

Key features:
- Resize the template DLL .text capacity for requested code+data budget.
- Rebuild matching .hck (DllHackInfo binary layout).
- Trim template PDB to its MSF logical size (NumBlocks * BlockSize),
  avoiding bloated embedded arrays when the file has trailing slack.
- Optionally emit EMBEDDED_DLL.cpp / EMBEDDED_PDB.cpp style arrays.
"""

from __future__ import annotations
import argparse
import pathlib
import struct
from dataclasses import dataclass
from typing import List, Tuple

SEC_NAMES = (b".text", b".rdata", b".pdata", b".xdata")
SUB_PARENT = (-1, -1, -1, 1)
DIR_DEBUG = 6


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def w32(b: bytearray, o: int, v: int) -> None:
    struct.pack_into("<I", b, o, v & 0xFFFFFFFF)


def align_up(v: int, a: int) -> int:
    return (v + a - 1) // a * a if a else v


@dataclass
class Sec:
    name: bytes
    hdr: int
    vsz: int
    va: int
    raw: int
    ptr: int


@dataclass
class PE:
    buf: bytearray
    opt: int
    sec_align: int
    file_align: int
    dd_off: int
    dd_count: int
    secs: List[Sec]


def parse_pe(data: bytes) -> PE:
    if data[:2] != b"MZ":
        raise ValueError("not MZ")
    pe = u32(data, 0x3C)
    if data[pe:pe+4] != b"PE\0\0":
        raise ValueError("bad PE")
    coff = pe + 4
    nsec = u16(data, coff + 2)
    opt_sz = u16(data, coff + 16)
    opt = coff + 20
    magic = u16(data, opt)
    dd_rel = 112 if magic == 0x20B else 96

    sec_align = u32(data, opt + 32)
    file_align = u32(data, opt + 36)
    dd_count = u32(data, opt + dd_rel - 4)
    dd_off = opt + dd_rel

    secs: List[Sec] = []
    off = opt + opt_sz
    for i in range(nsec):
        h = off + i * 40
        secs.append(Sec(bytes(data[h:h+8]).rstrip(b"\0"), h, u32(data, h + 8), u32(data, h + 12), u32(data, h + 16), u32(data, h + 20)))

    return PE(bytearray(data), opt, sec_align, file_align, dd_off, dd_count, secs)


def find_sec(pe: PE, name: bytes) -> Sec:
    for s in pe.secs:
        if s.name == name:
            return s
    raise ValueError(f"missing section {name!r}")


def resize_text(pe: PE, code_size: int, data_size: int) -> None:
    text = find_sec(pe, b".text")
    old_raw = text.raw
    old_span = align_up(text.vsz, pe.sec_align)

    req = max(code_size + data_size, pe.file_align, 256)
    text.vsz = align_up(req, pe.sec_align)
    text.raw = align_up(text.vsz, pe.file_align)
    new_span = align_up(text.vsz, pe.sec_align)

    d_raw = text.raw - old_raw
    d_va = new_span - old_span
    text_end = text.ptr + old_raw

    if d_raw > 0:
        pe.buf[text_end:text_end] = b"\x00" * d_raw
    elif d_raw < 0:
        del pe.buf[text_end + d_raw:text_end]

    w32(pe.buf, text.hdr + 8, text.vsz)
    w32(pe.buf, text.hdr + 16, text.raw)

    after_text = False
    for s in pe.secs:
        if s is text:
            after_text = True
            continue
        if after_text:
            s.ptr += d_raw
            s.va += d_va
            w32(pe.buf, s.hdr + 20, s.ptr)
            w32(pe.buf, s.hdr + 12, s.va)

    for i in range(pe.dd_count):
        d = pe.dd_off + i * 8
        rva = u32(pe.buf, d)
        if rva and rva >= (text.va + old_span):
            w32(pe.buf, d, rva + d_va)

    w32(pe.buf, pe.opt + 4, text.raw)  # SizeOfCode
    init = sum(s.raw for s in pe.secs if s.name != b".text")
    w32(pe.buf, pe.opt + 8, init)      # SizeOfInitializedData

    last = 0
    for s in pe.secs:
        last = max(last, align_up(s.va + s.vsz, pe.sec_align))
    w32(pe.buf, pe.opt + 56, last)     # SizeOfImage


def find_rsds_file_offsets(pe: PE) -> Tuple[int, int]:
    dbg_rva = u32(pe.buf, pe.dd_off + DIR_DEBUG * 8)
    dbg_sz = u32(pe.buf, pe.dd_off + DIR_DEBUG * 8 + 4)
    if not dbg_rva or not dbg_sz:
        raise ValueError("missing debug dir")

    # RVA -> file
    def rva2off(rva: int) -> int:
        for s in pe.secs:
            span = max(s.vsz, s.raw)
            if s.va <= rva < s.va + span:
                return s.ptr + (rva - s.va)
        raise ValueError("RVA not mapped")

    d_off = rva2off(dbg_rva)
    for i in range(0, dbg_sz, 28):
        e = d_off + i
        typ = u32(pe.buf, e + 12)
        ptr = u32(pe.buf, e + 24)
        sz = u32(pe.buf, e + 16)
        if typ == 2 and sz >= 24 and pe.buf[ptr:ptr+4] == b"RSDS":
            return ptr + 4, ptr + 24
    raise ValueError("RSDS not found")


def build_hck(pe: PE, guid_pos: int, pdb_name_pos: int) -> bytes:
    vals: List[int] = list(SUB_PARENT)
    for n in SEC_NAMES:
        s = find_sec(pe, n)
        vals += [s.hdr, s.va, s.raw, s.ptr]
    # timestamp in COFF header: e_lfanew + 4 + 4
    pe_off = u32(pe.buf, 0x3C)
    vals += [pe_off + 8, pdb_name_pos, guid_pos]
    return b"".join(struct.pack("<i", v) for v in vals)


def trim_pdb_msf_logical_size(pdb: bytes) -> bytes:
    # MSF7 superblock starts right after 32-byte signature.
    if len(pdb) < 56:
        return pdb
    block_size = u32(pdb, 32)
    num_blocks = u32(pdb, 40)
    logical = block_size * num_blocks
    if block_size == 0 or num_blocks == 0:
        return pdb
    if logical <= len(pdb):
        return pdb[:logical]
    return pdb


def trim_pdb_msf_used_blocks(pdb: bytes) -> bytes:
    # Conservative MSF7 shrink: keep all blocks referenced by stream directory.
    # Superblock layout offsets (MSF 7.00):
    # block_size@32, free_block_map@36, num_blocks@40, dir_bytes@44, map_addr@52
    if len(pdb) < 56:
        return pdb

    block_size = u32(pdb, 32)
    free_block_map = u32(pdb, 36)
    num_blocks = u32(pdb, 40)
    dir_bytes = u32(pdb, 44)
    block_map_addr = u32(pdb, 52)
    if not block_size or not num_blocks:
        return pdb

    logical = block_size * num_blocks
    if logical > len(pdb):
        return pdb

    num_dir_blocks = align_up(dir_bytes, block_size) // block_size
    map_off = block_map_addr * block_size
    if map_off + num_dir_blocks * 4 > len(pdb):
        return pdb

    dir_blocks = [u32(pdb, map_off + i * 4) for i in range(num_dir_blocks)]
    dir_data = bytearray()
    for b in dir_blocks:
        off = b * block_size
        if off + block_size > len(pdb):
            return pdb
        dir_data.extend(pdb[off:off + block_size])
    dir_data = dir_data[:dir_bytes]
    if len(dir_data) < 4:
        return pdb

    used = {0, free_block_map, block_map_addr}
    used.update(dir_blocks)

    cur = 0
    n_streams = u32(dir_data, cur)
    cur += 4
    if len(dir_data) < 4 + n_streams * 4:
        return pdb
    sizes = [u32(dir_data, cur + i * 4) for i in range(n_streams)]
    cur += n_streams * 4

    for sz in sizes:
        if sz == 0xFFFFFFFF or sz == 0:
            continue
        nblk = align_up(sz, block_size) // block_size
        if cur + nblk * 4 > len(dir_data):
            return pdb
        for _ in range(nblk):
            used.add(u32(dir_data, cur))
            cur += 4

    max_used = max(used)
    new_blocks = max_used + 1
    if new_blocks >= num_blocks:
        return pdb

    out = bytearray(pdb[: new_blocks * block_size])
    w32(out, 40, new_blocks)  # NumBlocks
    return bytes(out)


def cpp_array(sym: str, payload: bytes) -> str:
    body = ",".join(f"0x{x:02X}" for x in payload)
    return (
        "#pragma warning(push, 0)\n"
        f"char {sym}[] = {{{body}}};\n"
        f"unsigned long long {sym}_SIZE = sizeof({sym});\n"
        "#pragma warning(pop)\n"
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dll", required=True)
    ap.add_argument("--pdb", required=True)
    ap.add_argument("--out-prefix", required=True)
    ap.add_argument("--code-size", type=int, required=True)
    ap.add_argument("--data-size", type=int, required=True)
    ap.add_argument("--emit-cpp", action="store_true")
    args = ap.parse_args()

    pe = parse_pe(pathlib.Path(args.dll).read_bytes())
    resize_text(pe, args.code_size, args.data_size)
    guid_pos, pdb_name_pos = find_rsds_file_offsets(pe)
    hck = build_hck(pe, guid_pos, pdb_name_pos)

    pdb_raw = pathlib.Path(args.pdb).read_bytes()
    pdb_trim = trim_pdb_msf_logical_size(pdb_raw)
    pdb_trim = trim_pdb_msf_used_blocks(pdb_trim)

    out = pathlib.Path(args.out_prefix)
    out.parent.mkdir(parents=True, exist_ok=True)
    out_dll = out.with_suffix(".dll")
    out_hck = out.with_suffix(".hck")
    out_pdb = out.with_suffix(".pdb")

    out_dll.write_bytes(bytes(pe.buf))
    out_hck.write_bytes(hck)
    out_pdb.write_bytes(pdb_trim)

    if args.emit_cpp:
        (out.parent / "EMBEDDED_DLL.generated.cpp").write_text(
            cpp_array("JITPDB_DLL", bytes(pe.buf)) + "\n" + cpp_array("JITPDB_HCK", hck),
            encoding="utf-8",
        )
        (out.parent / "EMBEDDED_PDB.generated.cpp").write_text(
            cpp_array("JITPDB_PDB", pdb_trim), encoding="utf-8"
        )

    print(f"dll: {out_dll} ({out_dll.stat().st_size} bytes)")
    print(f"hck: {out_hck} ({out_hck.stat().st_size} bytes)")
    print(f"pdb: {out_pdb} ({out_pdb.stat().st_size} bytes, trimmed from {len(pdb_raw)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
