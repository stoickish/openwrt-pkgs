use crate::hmac;
use std::mem;

pub const INTEGRITY_TAG: [u8; 16] = *b"JENTRNG_INTG_TAG";
pub const PLACEHOLDER_BYTE: u8 = 0xEE;

#[repr(C)]
pub struct IntegrityBlock {
    pub tag: [u8; 16],
    pub key: [u8; 32],
    pub hmac: [u8; 32],
}

const EI_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;

fn read_u16(data: &[u8], offset: usize, le: bool) -> u16 {
    let b = [data[offset], data[offset + 1]];
    if le {
        u16::from_le_bytes(b)
    } else {
        u16::from_be_bytes(b)
    }
}

fn read_u32(data: &[u8], offset: usize, le: bool) -> u32 {
    let b = [
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ];
    if le {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    }
}

fn read_u64(data: &[u8], offset: usize, le: bool) -> u64 {
    let b = [
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ];
    if le {
        u64::from_le_bytes(b)
    } else {
        u64::from_be_bytes(b)
    }
}

struct ElfInfo {
    phoff: u64,
    phentsize: u16,
    phnum: u16,
    ehsize: u16,
    is_64: bool,
    le: bool,
}

fn parse_elf_header(data: &[u8]) -> Result<ElfInfo, String> {
    if data.len() < 64 {
        return Err("ELF file too small".into());
    }
    if data[..4] != EI_MAGIC {
        return Err("not an ELF file".into());
    }

    let is_64 = data[EI_CLASS] == 2;
    let le = data[EI_DATA] == 1;

    let (phoff_off, phentsize_off, phnum_off, ehsize_off) = if is_64 {
        (32, 54, 56, 52)
    } else {
        (28, 42, 44, 40)
    };

    let phoff = if is_64 {
        read_u64(data, phoff_off, le)
    } else {
        read_u32(data, phoff_off, le) as u64
    };
    let phentsize = read_u16(data, phentsize_off, le);
    let phnum = read_u16(data, phnum_off, le);
    let ehsize = read_u16(data, ehsize_off, le);

    Ok(ElfInfo {
        phoff,
        phentsize,
        phnum,
        ehsize,
        is_64,
        le,
    })
}

fn find_tag_offset(data: &[u8]) -> Option<usize> {
    data.windows(INTEGRITY_TAG.len())
        .position(|w| w == INTEGRITY_TAG)
}

fn block_size() -> usize {
    mem::size_of::<IntegrityBlock>()
}

fn collect_hash_ranges(data: &[u8]) -> Result<Vec<(usize, usize)>, String> {
    let info = parse_elf_header(data)?;

    if info.phnum == 0 || info.phoff == 0 {
        return Err("no program headers".into());
    }

    let tag_off = find_tag_offset(data).ok_or("integrity tag not found in binary")?;
    let block_end = tag_off + block_size();
    let ehsize = info.ehsize as usize;

    let mut ranges = Vec::new();

    for idx in 0..info.phnum {
        let off = info.phoff as usize + (idx as usize) * (info.phentsize as usize);
        if off + info.phentsize as usize > data.len() {
            return Err(format!("program header entry {} extends beyond file", idx));
        }

        let p_type = read_u32(data, off, info.le);
        if p_type != PT_LOAD {
            continue;
        }

        let p_flags: u32 = if info.is_64 {
            read_u32(data, off + 4, info.le)
        } else {
            read_u32(data, off + 24, info.le)
        };
        if p_flags & PF_X == 0 {
            continue;
        }

        let (p_offset, p_filesz) = if info.is_64 {
            (
                read_u64(data, off + 8, info.le) as usize,
                read_u64(data, off + 32, info.le) as usize,
            )
        } else {
            (
                read_u32(data, off + 4, info.le) as usize,
                read_u32(data, off + 16, info.le) as usize,
            )
        };

        if p_filesz == 0 {
            continue;
        }
        if p_offset + p_filesz > data.len() {
            return Err(format!(
                "executable load segment {} extends beyond file",
                idx
            ));
        }

        let seg_start = p_offset;
        let seg_end = p_offset + p_filesz;

        let mut cuts: Vec<(usize, usize)> = Vec::new();

        if block_end > seg_start && tag_off < seg_end {
            cuts.push((tag_off.max(seg_start), block_end.min(seg_end)));
        }

        if ehsize > seg_start && 0 < seg_end {
            cuts.push((0usize.max(seg_start), ehsize.min(seg_end)));
        }

        cuts.sort();

        let mut pos = seg_start;
        for (c_start, c_end) in cuts {
            if c_start > pos {
                ranges.push((pos, c_start - pos));
            }
            pos = pos.max(c_end);
        }
        if pos < seg_end {
            ranges.push((pos, seg_end - pos));
        }
    }

    if ranges.is_empty() {
        return Err("no hashable data in executable load segments".into());
    }

    ranges.sort_by_key(|&(off, _)| off);
    Ok(ranges)
}

fn hex_fmt(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

fn err_msg(msg: &str) -> String {
    msg.into()
}

pub fn check_integrity(block: &IntegrityBlock) -> Result<(), String> {
    let placeholder: [u8; 32] = [PLACEHOLDER_BYTE; 32];
    if block.hmac == placeholder {
        return Err(err_msg(
            "integrity placeholder not patched — build incomplete",
        ));
    }

    let exe_data = std::fs::read("/proc/self/exe")
        .map_err(|e| format!("cannot read /proc/self/exe: {}", e))?;

    let ranges = collect_hash_ranges(&exe_data)?;
    let code_data: Vec<u8> = ranges
        .iter()
        .flat_map(|&(off, size)| exe_data[off..off + size].iter().copied())
        .collect();
    let computed = hmac::hmac_sha3_256(&block.key, &code_data);

    if block.hmac == computed {
        return Ok(());
    }

    let mut msg = format!(
        "computed HMAC does not match embedded value (key={}, embedded={}, computed={}, total_bytes={}, ranges=[",
        hex_fmt(&block.key),
        hex_fmt(&block.hmac),
        hex_fmt(&computed),
        code_data.len(),
    );
    for (i, &(off, size)) in ranges.iter().enumerate() {
        if i > 0 {
            msg.push_str(", ");
        }
        msg.push_str(&format!("0x{:x}+0x{:x}", off, size));
    }
    msg.push(']');
    Err(msg)
}
