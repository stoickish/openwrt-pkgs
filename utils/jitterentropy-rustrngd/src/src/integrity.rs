use crate::hmac;

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

    let (phoff_off, phentsize_off, phnum_off) = if is_64 { (32, 54, 56) } else { (28, 42, 44) };

    let phoff = if is_64 {
        read_u64(data, phoff_off, le)
    } else {
        read_u32(data, phoff_off, le) as u64
    };
    let phentsize = read_u16(data, phentsize_off, le);
    let phnum = read_u16(data, phnum_off, le);

    Ok(ElfInfo {
        phoff,
        phentsize,
        phnum,
        is_64,
        le,
    })
}

fn collect_exec_load_segments(data: &[u8]) -> Result<Vec<(usize, usize)>, String> {
    let info = parse_elf_header(data)?;

    if info.phnum == 0 || info.phoff == 0 {
        return Err("no program headers".into());
    }

    let mut segments = Vec::new();

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

        segments.push((p_offset, p_filesz));
    }

    if segments.is_empty() {
        return Err("no executable load segments found".into());
    }

    segments.sort_by_key(|&(off, _)| off);
    Ok(segments)
}

fn compute_text_hmac(key: &[u8], data: &[u8]) -> Result<[u8; 32], String> {
    let segments = collect_exec_load_segments(data)?;
    let code_data: Vec<u8> = segments
        .iter()
        .flat_map(|&(off, size)| data[off..off + size].iter().copied())
        .collect();
    Ok(hmac::hmac_sha3_256(key, &code_data))
}

pub fn check_integrity(block: &IntegrityBlock) -> Result<(), String> {
    let placeholder: [u8; 32] = [PLACEHOLDER_BYTE; 32];
    if block.hmac == placeholder {
        return Err("integrity placeholder not patched — build incomplete".into());
    }

    let exe_data = std::fs::read("/proc/self/exe")
        .map_err(|e| format!("cannot read /proc/self/exe: {}", e))?;

    let computed = compute_text_hmac(&block.key, &exe_data)?;

    if block.hmac != computed {
        return Err("integrity check failed: computed HMAC does not match embedded value".into());
    }

    Ok(())
}
