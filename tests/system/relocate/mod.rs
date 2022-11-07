use core::convert::TryInto;
use core::fmt::Debug;
use core::fmt::Display;
use core::mem::MaybeUninit;
use core::slice::from_raw_parts_mut;
use elf_utils::ElfByteOrder;
use elf_utils::ElfHdrData;
use elf_utils::ElfHdrOffsets;
use elf_utils::WithElfData;
use elf_utils::dynamic::Dynamic;
use elf_utils::dynamic::DynamicInfo;
use elf_utils::dynamic::DynamicInfoFullStrs;
use elf_utils::dynamic::DynamicOffsets;
use elf_utils::dynamic::Relocs;
use elf_utils::load::LoadBuf;
use elf_utils::load::LoadErr;
use elf_utils::prog_hdr::ProgHdrs;
use elf_utils::prog_hdr::ProgHdrData;
use elf_utils::prog_hdr::ProgHdrDataBufs;
use elf_utils::prog_hdr::ProgHdrDataFull;
use elf_utils::prog_hdr::ProgHdrDataRaw;
use elf_utils::prog_hdr::ProgHdrOffsets;
use elf_utils::prog_hdr::Segment;
use elf_utils::reloc::ArchReloc;
use elf_utils::reloc::BasicRelocParams;
use elf_utils::reloc::Rels;
use elf_utils::reloc::Relas;
use elf_utils::reloc::Reloc;
use elf_utils::reloc::RelDataRaw;
use elf_utils::reloc::RelOffsets;
use elf_utils::reloc::RelaDataRaw;
use elf_utils::reloc::RelaOffsets;
use elf_utils::section_hdr::SectionHdrs;
use elf_utils::section_hdr::SectionHdrOffsets;
use elf_utils::symtab::SymOffsets;

mod dynamic;

fn get_virt_size<'a, B, Offsets>(prog_hdrs: &ProgHdrs<'a, B, Offsets>) -> usize
    where Offsets: Debug + ProgHdrOffsets + DynamicOffsets,
          B: ElfByteOrder {
    let mut lo_virt_addr = 0xffffffffffffffff;
    let mut lo_offset = 0xffffffffffffffff;
    let mut hi_virt_addr = 0;

    for ent in prog_hdrs.iter() {
        match ent.try_into().expect("Expected success") {
            ProgHdrData::Load { content: Segment { offset, .. },
                                virt_addr, mem_size, .. } => {
                let offset: usize = offset.try_into()
                    .ok().expect("Expected success");
                let virt_addr: usize = virt_addr.try_into()
                    .ok().expect("Expected success");
                let mem_size: usize = mem_size.try_into()
                    .ok().expect("Expected success");

                if lo_offset > offset {
                    lo_offset = offset
                }

                if lo_virt_addr > virt_addr {
                    lo_virt_addr = virt_addr
                }

                if hi_virt_addr < virt_addr + mem_size {
                    hi_virt_addr = virt_addr + mem_size
                }
            },
            _ => {},
        }
    }

    hi_virt_addr
}


fn get_dynamic_ent<'a, B, Offsets>(prog_hdrs: &ProgHdrs<'a, B, Offsets>,
                                   data: &'a [u8]) -> Dynamic<'a, B, Offsets>
    where Offsets: Debug + ProgHdrOffsets + DynamicOffsets,
          B: ElfByteOrder {
    let mut dynamic = None;

    for ent in prog_hdrs.iter() {
        let prog_hdr_raw: ProgHdrDataRaw<Offsets> = ent.try_into()
            .expect("Expected success");
        let prog_hdr_bufs: ProgHdrDataBufs<'a, Offsets> =
            prog_hdr_raw.with_elf_data(data).expect("Expected success");
        let prog_hdr: ProgHdrDataFull<'a, B, Offsets> =
            prog_hdr_bufs.clone().try_into().expect("Expected success");

        match prog_hdr {
            ProgHdrData::Dynamic { content, .. } => {
                assert!(dynamic.is_none());
                dynamic = Some(content)
            },
            _ => {}
        }
    }

    dynamic.expect("Expected some")
}

fn load_segments<'a, B, Offsets>(prog_hdrs: &ProgHdrs<'a, B, Offsets>,
                                 data: &'a [u8], dst: &mut [u8])
    where Offsets: Debug + ProgHdrOffsets + DynamicOffsets,
          B: ElfByteOrder {
    for ent in prog_hdrs.iter() {
        let prog_hdr_raw: ProgHdrDataRaw<Offsets> = ent.try_into()
            .expect("Expected success");
        let prog_hdr_bufs: ProgHdrDataBufs<'a, Offsets> = prog_hdr_raw
            .with_elf_data(data).expect("Expected success");

        match prog_hdr_bufs {
            ProgHdrData::Load { virt_addr, mem_size, content, .. } => {
                let virt_addr: usize = virt_addr.try_into()
                    .ok().expect("Expected success");
                let mem_size: usize = mem_size.try_into()
                    .ok().expect("Expected some");
                let slice = &mut dst[virt_addr .. virt_addr + mem_size];
                let mut load_buf = LoadBuf::from_slice(slice);

                load_buf.load(&prog_hdr_bufs).ok().expect("Expected success");
            },
            _ => {}
        }
    }
}

fn process_rels<'a, B, Offsets, Rel>(rels: &Rels<'a, B, Offsets>,
                                     info: &DynamicInfoFullStrs<'a, B, Offsets>,
                                     data: &'a [u8], dst: &mut [u8],
                                     base: Offsets::Addr)
    where Offsets: 'a + Debug + DynamicOffsets + RelOffsets +
        RelaOffsets + SymOffsets,
          Rel: ArchReloc<'a, B, Offsets, Ent = RelDataRaw<Offsets>,
                         Params = BasicRelocParams<Offsets>> + Debug,
          Rel::RelocError: Display + Debug,
          Rel::LoadError: Display + Debug,
          B: 'a + ElfByteOrder {
    let params = BasicRelocParams::from_dynamic(base, info);

    rels.apply::<Rel>(dst, &params, info.symtab, info.strtab)
        .expect("Expected success");
}

fn process_relas<'a, B, Offsets, Rela>(relas: &Relas<'a, B, Offsets>,
                                       info: &DynamicInfoFullStrs<'a, B,
                                                                  Offsets>,
                                       data: &'a [u8], dst: &mut [u8],
                                       base: Offsets::Addr)
    where Offsets: 'a + Debug + DynamicOffsets + RelOffsets +
                   RelaOffsets + SymOffsets,
          Rela: ArchReloc<'a, B, Offsets, Ent = RelaDataRaw<Offsets>,
                          Params = BasicRelocParams<Offsets>> + Debug,
          Rela::RelocError: Display + Debug,
          Rela::LoadError: Display + Debug,
          B: 'a + ElfByteOrder {
    let params = BasicRelocParams::from_dynamic(base, info);

    relas.apply::<Rela>(dst, &params, info.symtab, info.strtab)
        .expect("Expected success");
}

fn process_relocs<'a, B, Offsets, Rel, Rela>(
        reloc: &Option<Relocs<Rels<'a, B, Offsets>,
                              Relas<'a, B, Offsets>>>,
        info: &DynamicInfoFullStrs<'a, B, Offsets>,
        data: &'a [u8], dst: &mut [u8],
        base: Offsets::Addr
    )
    where Offsets: 'a + Debug + DynamicOffsets + RelOffsets +
                   RelaOffsets + SymOffsets,
          Rela: ArchReloc<'a, B, Offsets, Ent = RelaDataRaw<Offsets>,
                          Params = BasicRelocParams<Offsets>> + Debug,
          Rel: ArchReloc<'a, B, Offsets, Ent = RelDataRaw<Offsets>,
                          Params = BasicRelocParams<Offsets>> + Debug,
          Rela::RelocError: Display + Debug,
          Rela::LoadError: Display + Debug,
          Rel::RelocError: Display + Debug,
          Rel::LoadError: Display + Debug,
          B: 'a + ElfByteOrder {
    match reloc {
        Some(Relocs::Rela(relas)) => {
            process_relas::<B, Offsets, Rela>(relas, info, data, dst, base);
        },
        Some(Relocs::Rel(rels)) => {
            process_rels::<B, Offsets, Rel>(rels, info, data, dst, base);
        },
        None => {}
    }
}

fn process_dynamic<'a, B, Offsets, Rel, Rela>(dynamic: &Dynamic<'a, B, Offsets>,
                                              data: &'a [u8], dst: &mut [u8],
                                              base: Offsets::Addr)
    where Offsets: 'a + Debug + DynamicOffsets + RelOffsets +
                   RelaOffsets + SymOffsets,
          Rela: ArchReloc<'a, B, Offsets, Ent = RelaDataRaw<Offsets>,
                          Params = BasicRelocParams<Offsets>> + Debug,
          Rel: ArchReloc<'a, B, Offsets, Ent = RelDataRaw<Offsets>,
                          Params = BasicRelocParams<Offsets>> + Debug,
          Rela::RelocError: Display + Debug,
          Rela::LoadError: Display + Debug,
          Rel::RelocError: Display + Debug,
          Rel::LoadError: Display + Debug,
          B: 'a + ElfByteOrder {
    let info = DynamicInfo::from_dynamic(dynamic, data)
        .expect("Expected success");

    process_relocs::<B, Offsets, Rel, Rela>(&info.jump_reloc, &info,
                                            data, dst, base);
    process_relocs::<B, Offsets, Rel, Rela>(&info.reloc, &info,
                                            data, dst, base);
}

fn load_prog_hdrs<'a, B, Offsets, Rel, Rela>(
        prog_hdrs: &ProgHdrs<'a, B, Offsets>,
        base: usize, data: &'a [u8]
    ) -> Vec<u8>
    where Offsets: 'a + Debug + ProgHdrOffsets + DynamicOffsets + RelOffsets +
                   RelaOffsets + SymOffsets,
          Rela: ArchReloc<'a, B, Offsets, Ent = RelaDataRaw<Offsets>,
                          Params = BasicRelocParams<Offsets>> + Debug,
          Rel: ArchReloc<'a, B, Offsets, Ent = RelDataRaw<Offsets>,
                          Params = BasicRelocParams<Offsets>> + Debug,
          Rela::RelocError: Display + Debug,
          Rela::LoadError: Display + Debug,
          Rel::RelocError: Display + Debug,
          Rel::LoadError: Display + Debug,
          B: 'a + ElfByteOrder {
    let virt_size = get_virt_size(prog_hdrs);
    let mut dst = vec![0; virt_size];
    let runtime_addr: Offsets::Addr = base.try_into()
        .ok().expect("Expected some");
    let dynamic = get_dynamic_ent(prog_hdrs, data);

    load_segments(prog_hdrs, data, &mut dst);
    process_dynamic::<B, Offsets, Rel, Rela>(&dynamic, data, &mut dst,
                                             runtime_addr);

    dst
}

pub fn load_and_reloc<'a, B, Offsets, Rel, Rela>(base: usize, data: &'a [u8]) ->
    Vec<u8>
    where Offsets: 'a + Debug + ElfHdrOffsets + ProgHdrOffsets +
                   SectionHdrOffsets + DynamicOffsets,
          Rela: ArchReloc<'a, B, Offsets, Ent = RelaDataRaw<Offsets>,
                          Params = BasicRelocParams<Offsets>> + Debug,
          Rel: ArchReloc<'a, B, Offsets, Ent = RelDataRaw<Offsets>,
                          Params = BasicRelocParams<Offsets>> + Debug,
          Rela::RelocError: Display + Debug,
          Rela::LoadError: Display + Debug,
          Rel::RelocError: Display + Debug,
          Rel::LoadError: Display + Debug,
          B: 'a + ElfByteOrder {
    let hdr = ElfHdrData::from_data(data).expect("Expected success");
    let prog_hdrs = hdr.prog_hdrs.expect("Expected some");

    load_prog_hdrs::<B, Offsets, Rel, Rela>(&prog_hdrs, base, data)
}
