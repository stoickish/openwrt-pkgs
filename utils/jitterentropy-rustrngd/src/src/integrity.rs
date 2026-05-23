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
const SHF_EXECINSTR: u32 = 0x4;

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
    shoff: u64,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
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

    let (shoff, shentsize_off, shnum_off, shstrndx_off) = if is_64 {
        (40, 58, 60, 62)
    } else {
        (32, 46, 48, 50)
    };

    let shoff = if is_64 {
        read_u64(data, shoff, le)
    } else {
        read_u32(data, shoff, le) as u64
    };
    let shentsize = read_u16(data, shentsize_off, le);
    let shnum = read_u16(data, shnum_off, le);
    let shstrndx = read_u16(data, shstrndx_off, le);

    Ok(ElfInfo {
        shoff,
        shentsize,
        shnum,
        shstrndx,
        is_64,
        le,
    })
}

fn read_sect_hdr(info: &ElfInfo, data: &[u8], idx: u16) -> Result<SectionInfo, String> {
    let off = info.shoff as usize + (idx as usize) * (info.shentsize as usize);
    if off + info.shentsize as usize > data.len() {
        return Err("section header table entry extends beyond file".into());
    }

    if info.is_64 {
        Ok(SectionInfo {
            name_off: read_u32(data, off, info.le),
            flags: read_u64(data, off + 8, info.le),
            offset: read_u64(data, off + 24, info.le),
            size: read_u64(data, off + 32, info.le),
        })
    } else {
        Ok(SectionInfo {
            name_off: read_u32(data, off, info.le),
            flags: read_u32(data, off + 8, info.le) as u64,
            offset: read_u32(data, off + 16, info.le) as u64,
            size: read_u32(data, off + 20, info.le) as u64,
        })
    }
}

struct SectionInfo {
    name_off: u32,
    flags: u64,
    offset: u64,
    size: u64,
}

/// Look up a null-terminated string in the section header string table.
fn shstr_lookup<'a>(data: &'a [u8], shstrtab: &SectionInfo, off: u32) -> Option<&'a [u8]> {
    let base = shstrtab.offset as usize;
    let start = base + off as usize;
    if start >= data.len() {
        return None;
    }
    let end = data[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| start + p)
        .unwrap_or(data.len());
    Some(&data[start..end])
}

fn collect_exec_sections(data: &[u8]) -> Result<Vec<(usize, usize)>, String> {
    let info = parse_elf_header(data)?;

    if info.shstrndx >= info.shnum {
        return Err("invalid shstrndx".into());
    }
    let shstrtab = read_sect_hdr(&info, data, info.shstrndx)?;

    let mut sections = Vec::new();

    for idx in 0..info.shnum {
        if idx == info.shstrndx {
            continue;
        }
        let sec = read_sect_hdr(&info, data, idx)?;
        if sec.flags & SHF_EXECINSTR as u64 == 0 {
            continue;
        }
        let name = match shstr_lookup(data, &shstrtab, sec.name_off) {
            Some(n) => n,
            None => continue,
        };
        if name.starts_with(b".plt") {
            continue;
        }
        let offset = sec.offset as usize;
        let size = sec.size as usize;
        if offset + size > data.len() {
            return Err("section extends beyond file".into());
        }
        sections.push((offset, size));
    }

    if sections.is_empty() {
        return Err("no executable sections found".into());
    }

    sections.sort_by_key(|&(off, _)| off);
    Ok(sections)
}

fn compute_text_hmac(key: &[u8], data: &[u8]) -> Result<[u8; 32], String> {
    let sections = collect_exec_sections(data)?;
    let code_data: Vec<u8> = sections
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
        return Err(
            "integrity check failed: computed HMAC does not match embedded value".into(),
        );
    }

    Ok(())
}
