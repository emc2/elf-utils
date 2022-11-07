use byteorder::ByteOrder;
use elf_utils::Elf;
use elf_utils::ElfByteOrder;
use elf_utils::ElfHdrDataBufs;
use elf_utils::ElfHdrDataHdrs;
use elf_utils::ElfHdrOffsets;
use elf_utils::ElfHdrDataRaw;
use elf_utils::WithElfData;
use elf_utils::dynamic::Dynamic;
use elf_utils::dynamic::DynamicEntData;
use elf_utils::dynamic::DynamicEntDataStr;
use elf_utils::dynamic::DynamicOffsets;
use elf_utils::hash::Hashtab;
use elf_utils::note::NoteData;
use elf_utils::note::Notes;
use elf_utils::prog_hdr::ProgHdrs;
use elf_utils::prog_hdr::ProgHdrOffsets;
use elf_utils::prog_hdr::ProgHdrDataRaw;
use elf_utils::reloc::RelDataStrSym;
use elf_utils::reloc::RelOffsets;
use elf_utils::reloc::Rels;
use elf_utils::reloc::RelaDataStrSym;
use elf_utils::reloc::RelaOffsets;
use elf_utils::reloc::Relas;
use elf_utils::section_hdr::SectionHdrs;
use elf_utils::section_hdr::SectionHdrData;
use elf_utils::section_hdr::SectionHdrDataBufs;
use elf_utils::section_hdr::SectionHdrDataRaw;
use elf_utils::section_hdr::SectionHdrDataRawStr;
use elf_utils::section_hdr::SectionHdrDataRefs;
use elf_utils::section_hdr::SectionHdrDataResolved;
use elf_utils::section_hdr::SectionHdrDataResolvedStrs;
use elf_utils::section_hdr::SectionHdrOffsets;
use elf_utils::section_hdr::SectionPos;
use elf_utils::section_hdr::SymsStrs;
use elf_utils::section_hdr::WithSectionHdrs;
use elf_utils::strtab::Strtab;
use elf_utils::strtab::WithStrtab;
use elf_utils::symtab::Symtab;
use elf_utils::symtab::SymData;
use elf_utils::symtab::SymDataRaw;
use elf_utils::symtab::SymDataStr;
use elf_utils::symtab::SymOffsets;
use elf_utils::symtab::WithSymtab;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt::Display;
use std::fmt::Debug;

mod dynamic;
mod executable;
mod relocatable;

fn traverse_elf_hdr<'a, B, Offsets>(data: &'a [u8],
                                    expected: &ElfHdrDataRaw<B, Offsets>) ->
    ElfHdrDataHdrs<'a, B, Offsets>
    where ElfHdrDataRaw<B, Offsets>: Display,
          Offsets: Debug + ElfHdrOffsets,
          B: ElfByteOrder {
    let elf: Elf<'a, B, Offsets> =
        Elf::try_from(data).expect("expected success");
    let hdr: ElfHdrDataRaw<B, Offsets> =
        elf.try_into().expect("expected success");

    println!("ELF header:\n\n{}\n", hdr);

    assert_eq!(hdr, *expected);

    let hdr: ElfHdrDataBufs<'a, B, Offsets> =
        hdr.with_elf_data(data).expect("expected success");

    hdr.try_into().expect("expected success")
}

fn traverse_prog_hdrs<'a, B, Offsets>(hdrs: ProgHdrs<'a, B, Offsets>,
                                      expected: &[ProgHdrDataRaw<Offsets>])
    where Offsets: Debug + ProgHdrOffsets,
          B: ByteOrder {
    assert_eq!(hdrs.num_hdrs(), expected.len());

    for i in 0 .. expected.len() {
        let data: ProgHdrDataRaw<Offsets> =
            hdrs.idx(i).expect("expected some")
            .try_into().expect("expected success");

        println!("{}\n", data);

        assert_eq!(data, expected[i]);
    }
}

fn traverse_section_hdrs<'a, B, Offsets>(
        hdrs: SectionHdrs<'a, B, Offsets>,
        data: &'a [u8], strtab: usize,
        bare: &[SectionHdrDataRaw<Offsets>],
        strs: &[SectionHdrDataRawStr<'_, Offsets>]
    ) where Offsets: 'a + Debug + SectionHdrOffsets,
            B: 'a + ByteOrder {
    assert_eq!(hdrs.num_hdrs(), bare.len());

    for i in 0 .. bare.len() {
        let data: SectionHdrDataRaw<Offsets> =
            hdrs.idx(i).expect("expected some")
            .try_into().expect("expected success");

        //println!("{}\n", data);

        assert_eq!(data, bare[i]);
    }

    let strtab_hdr: SectionHdrDataRaw<Offsets> =
        hdrs.idx(strtab).expect("expected some")
        .try_into().expect("expected success");
    let strtab_hdr_links: SectionHdrDataRefs<'a, B, Offsets> =
        strtab_hdr.with_section_hdrs(hdrs).expect("expected success");
    let strtab_data: SectionHdrDataBufs<'a, B, Offsets> =
        strtab_hdr_links.with_elf_data(data).expect("expected success");
    let strtab_typed: SectionHdrDataResolved<'a, B, Offsets> =
        strtab_data.try_into().expect("expected success");
    let strtab = match strtab_typed {
        SectionHdrData::Strtab { strs, .. } => strs,
        _ => panic!("Expected string table")
    };

    for i in 0 .. strs.len() {
        let data: SectionHdrDataRaw<Offsets> =
            hdrs.idx(i).expect("expected some")
            .try_into().expect("expected success");
        let with_str: SectionHdrDataRawStr<'a, Offsets> =
            data.with_strtab(strtab).expect("expected success")
            .try_into().expect("expected success");

        println!("{}\n", with_str);

        assert_eq!(with_str, strs[i]);
    }
}

fn traverse_symtab<'a, 'b, B, Offsets>(
        syms: Symtab<'a, B, Offsets>,
        strtab: Strtab<'a>,
        expected: &'b [SymData<&'b str, Offsets::Half, Offsets>]
    ) where Offsets: Debug + SectionHdrOffsets,
            B: ByteOrder {
    let mut iter = syms.iter();

    for i in 0 .. expected.len() {
        let sym: SymDataRaw<Offsets> =
            iter.next().expect("expected some")
            .try_into().expect("expected success");
        let sym: SymDataStr<'a, Offsets> =
            sym.with_strtab(strtab).expect("expected success")
            .try_into().expect("expected success");

        println!("{}\n", sym);

        assert_eq!(sym, expected[i]);
    }

    assert!(iter.next().is_none());
}

fn traverse_strtab<'a, 'b>(strs: Strtab<'a>, expected: &'b [(&'b str, usize)]) {
    let mut iter = strs.iter();

    for i in 0 .. expected.len() {
        let (str, offset): (Result<&'a str, &'a [u8]>, usize) =
            iter.next().expect("expected some");
        let str = str.expect("expected success");

        println!("  [{}] = \"{}\"", offset, str);

        assert_eq!((str, offset), expected[i]);
    }

    assert_eq!(iter.next(), None);
}

fn traverse_hash<'a, 'b, B, Offsets>(
        hash: Hashtab<'a, B, Offsets>,
        syms: Symtab<'a, B, Offsets>,
        strtab: Strtab<'a>,
        expected: &'b [SymData<&'b str, Offsets::Half, Offsets>]
    ) where Offsets: Debug + SectionHdrOffsets,
            B: ByteOrder {
    let mut iter = syms.iter();

    for _ in 0 .. expected.len() {
        let expected: SymData<Offsets::Word, Offsets::Half, Offsets> =
            iter.next().expect("expected some")
            .try_into().expect("expected success");
        let expected: SymData<&'a str, Offsets::Half, Offsets> =
            expected.clone().with_strtab(strtab).expect("expected success")
            .try_into().expect("expected success");

        match expected.name {
            Some(name) => {
                let sym = hash.lookup(name).expect("expected success")
                    .expect("expected some");
                let actual: SymData<Offsets::Word, Offsets::Half, Offsets> =
                    sym.try_into().expect("expected success");
                let actual: SymData<&'a str, Offsets::Half, Offsets> =
                    actual.clone().with_strtab(strtab)
                    .expect("expected success")
                    .try_into().expect("expected success");

                println!(" Symbol for \"{}\":\n{}\n", name, actual);

                assert_eq!(expected, actual);
            },
            None => {}
        }
    }

    assert!(iter.next().is_none());
}

fn traverse_notes<'a, 'b, B>(note: Notes<'a, B>, expected: &'b [NoteData<'b>])
    where B: ByteOrder {
    let mut iter = note.iter();

    for i in 0 .. expected.len() {
        let data: NoteData<'a> =
            iter.next().expect("expected some")
            .try_into().expect("expected success");

        println!("{}\n", data);

        assert_eq!(data, expected[i]);
    }

    assert!(iter.next().is_none());
}

fn traverse_dynamic<'a, 'b, B, Offsets>(
        dynamic: Dynamic<'a, B, Offsets>,
        strtab: Strtab<'a>,
        expected: &'b [DynamicEntDataStr<'b, Offsets>]
    ) where Offsets: Debug + DynamicOffsets,
            B: ByteOrder {
    let mut iter = dynamic.iter();

    for i in 0 .. expected.len() {
        let data: DynamicEntDataStr<'a, Offsets> =
            iter.next().expect("expected some")
            .with_strtab(strtab).expect("expected success")
            .try_into().expect("expected success");

        println!("  {}", data);

        assert_eq!(data, expected[i]);
    }

    println!();
    assert!(iter.next().is_none());
}

fn traverse_rels<'a, 'b, B, Offsets, ArchRel, Error>(
        rels: Rels<'a, B, Offsets>,
        symtab: Symtab<'a, B, Offsets>,
        strtab: Strtab<'a>,
        expected: &'b [ArchRel]
    ) where ArchRel: Display + Debug + Eq +
                     TryFrom<RelDataStrSym<'a, Offsets>, Error = Error>,
            Offsets: Debug + RelOffsets + SymOffsets,
            Error: Debug,
            B: 'a + ByteOrder,
            'a: 'b {
    let mut iter = rels.iter();

    for i in 0 .. expected.len() {
        let data: RelDataStrSym<'a, Offsets> =
            iter.next().expect("expected some")
            .with_symtab(symtab).expect("expected success")
            .with_strtab(strtab).expect("expected success")
            .try_into().expect("expected success");
        let actual: ArchRel = data.try_into().unwrap();

        println!("  {}", actual);

        assert_eq!(actual, expected[i]);
    }

    assert!(iter.next().is_none());
}

fn traverse_relas<'a, 'b, B, Offsets, ArchRela, Error>(
        relas: Relas<'a, B, Offsets>,
        symtab: Symtab<'a, B, Offsets>,
        strtab: Strtab<'a>,
        expected: &'b [ArchRela]
    ) where ArchRela: Display + Debug + Eq +
                      TryFrom<RelaDataStrSym<'a, Offsets>, Error = Error>,
            Offsets: Debug + RelaOffsets + SymOffsets,
            Error: Debug,
            B: 'a + ByteOrder,
            'a: 'b {
    let mut iter = relas.iter();

    for i in 0 .. expected.len() {
        let data: RelaDataStrSym<'a, Offsets> =
            iter.next().expect("expected some")
            .with_symtab(symtab).expect("expected success")
            .with_strtab(strtab).expect("expected success")
            .try_into().expect("expected success");
        let actual: ArchRela = data.try_into().unwrap();

        println!("  {}", actual);

        assert_eq!(actual, expected[i]);
    }

    assert!(iter.next().is_none());
}

fn traverse_section_contents<'a, 'b, B, Offsets, ArchRels, ArchRelas,
                             RelError, RelaError>(
        hdrs: SectionHdrs<'a, B, Offsets>,
        expected: &'b [SectionHdrData<Offsets, &'b str,
                                      Offsets::Word,
                                      SymsStrs<&'b [SymDataStr<'b, Offsets>],
                                               &'b [(&'b str, usize)]>,
                                      &'b [(&'b str, usize)],
                                      SectionPos<Offsets::Offset>,
                                      &'b [SymDataStr<'b, Offsets>],
                                      &'b [(&'b str, usize)],
                                      &'b [ArchRels],
                                      &'b [ArchRelas],
                                      SectionPos<Offsets::Offset>,
                                      &'b [DynamicEntDataStr<'b, Offsets>],
                                      &'b [NoteData<'b>]>],
        strtab: usize, data: &'a [u8]
    ) where ArchRelas: Display + Debug + Eq +
                       TryFrom<RelaDataStrSym<'a, Offsets>, Error = RelaError>,
            ArchRels: Display + Debug + Eq +
                      TryFrom<RelDataStrSym<'a, Offsets>, Error = RelError>,
            Offsets: 'a + Debug + SectionHdrOffsets,
            B: 'a + ByteOrder,
            RelaError: Debug,
            RelError: Debug,
            'a: 'b {
    let strtab_hdr: SectionHdrDataRaw<Offsets> =
        hdrs.idx(strtab).expect("expected some")
        .try_into().expect("expected success");
    let strtab_hdr_links: SectionHdrDataRefs<'a, B, Offsets> =
        strtab_hdr.with_section_hdrs(hdrs).expect("expected success");
    let strtab_data: SectionHdrDataBufs<'a, B, Offsets> =
        strtab_hdr_links.with_elf_data(data).expect("expected success");
    let strtab_typed: SectionHdrDataResolved<'a, B, Offsets> =
        strtab_data.try_into().expect("expected success");
    let strtab = match strtab_typed {
        SectionHdrData::Strtab { strs, .. } => strs,
        _ => panic!("Expected string table")
    };

    assert_eq!(hdrs.num_hdrs(), expected.len());

    println!("Printable sections:\n");

    for i in 0 .. hdrs.num_hdrs() {
        let hdr: SectionHdrDataRaw<Offsets> =
            hdrs.idx(i).expect("expected some")
            .try_into().expect("expected success");
        let hdr_links: SectionHdrDataRefs<'a, B, Offsets> =
            hdr.with_section_hdrs(hdrs).expect("expected success");
        let hdr_data: SectionHdrDataBufs<'a, B, Offsets> =
            hdr_links.with_elf_data(data).expect("expected success");
        let hdr_typed: SectionHdrDataResolved<'a, B, Offsets> =
            hdr_data.try_into().expect("expected success");
        let hdr: SectionHdrDataResolvedStrs<'a, B, Offsets> =
            hdr_typed.with_strtab(strtab).expect("expected success")
            .try_into().expect("expected success");

        match expected[i] {
            SectionHdrData::Null => {},
            SectionHdrData::ProgBits { .. } => {},
            SectionHdrData::Symtab { strtab: expected_strs,
                                     syms: expected, .. } => match hdr {
                SectionHdrData::Symtab { name, strtab: actual_strs,
                                         syms: actual, .. } => {
                    println!("Symtab section {}:\n", name);
                    traverse_symtab(actual, actual_strs, expected);
                    println!(" strings:\n");
                    traverse_strtab(actual_strs, expected_strs);
                    println!();
                },
                SectionHdrData::Null => {
                    panic!("Expected symtab section, got null instead");
                },
                SectionHdrData::ProgBits { name, .. } => {
                    panic!("Expected symtab section {}, got progbits instead",
                           name);
                },
                SectionHdrData::Strtab { name, .. } => {
                    panic!("Expected symtab section {}, got strtab instead",
                           name);
                },
                SectionHdrData::Rela { name, .. } => {
                    panic!("Expected symtab section {}, got rela instead",
                           name);
                },
                SectionHdrData::Hash { name, .. } => {
                    panic!("Expected symtab section {}, got hash instead",
                           name);
                },
                SectionHdrData::Dynamic { name, .. } => {
                    panic!("Expected symtab section {}, got dynamic instead",
                           name);
                },
                SectionHdrData::Note { name, .. } => {
                    panic!("Expected symtab section {}, got note instead",
                           name);
                },
                SectionHdrData::Nobits { name, .. } => {
                    panic!("Expected symtab section {}, got nobits instead",
                           name);
                },
                SectionHdrData::Rel { name, .. } => {
                    panic!("Expected symtab section {}, got rela instead",
                           name);
                },
                SectionHdrData::Dynsym { name, .. } => {
                    panic!("Expected symtab section {}, got dynsym instead",
                           name);
                },
                SectionHdrData::Unknown { name, .. } => {
                    panic!("Expected symtab section {}, got unknown instead",
                           name);
                }
            },
            SectionHdrData::Strtab { strs: expected, .. } => match hdr {
                SectionHdrData::Strtab { name, strs: actual, .. } => {
                    println!("Strtab section {}:\n", name);
                    traverse_strtab(actual, expected);
                    println!();
                },
                SectionHdrData::Null => {
                    panic!("Expected strtab section, got null instead");
                },
                SectionHdrData::ProgBits { name, .. } => {
                    panic!("Expected strtab section {}, got progbits instead",
                           name);
                },
                SectionHdrData::Symtab { name, .. } => {
                    panic!("Expected strtab section {}, got symtab instead",
                           name);
                },
                SectionHdrData::Rela { name, .. } => {
                    panic!("Expected strtab section {}, got rela instead",
                           name);
                },
                SectionHdrData::Hash { name, .. } => {
                    panic!("Expected strtab section {}, got hash instead",
                           name);
                },
                SectionHdrData::Dynamic { name, .. } => {
                    panic!("Expected strtab section {}, got dynamic instead",
                           name);
                },
                SectionHdrData::Note { name, .. } => {
                    panic!("Expected strtab section {}, got note instead",
                           name);
                },
                SectionHdrData::Nobits { name, .. } => {
                    panic!("Expected strtab section {}, got nobits instead",
                           name);
                },
                SectionHdrData::Rel { name, .. } => {
                    panic!("Expected strtab section {}, got rela instead",
                           name);
                },
                SectionHdrData::Dynsym { name, .. } => {
                    panic!("Expected strtab section {}, got dynsym instead",
                           name);
                },
                SectionHdrData::Unknown { name, .. } => {
                    panic!("Expected strtab section {}, got unknown instead",
                           name);
                }
            },
            SectionHdrData::Rela { name, relas: expected,
                                   symtab: SymsStrs { syms: expected_syms,
                                                      strs: expected_strs },
                                   .. } => match hdr {
                SectionHdrData::Rela { relas: actual,
                                       symtab: SymsStrs { syms: actual_syms,
                                                          strs: actual_strs },
                                       .. } => {
                    println!("Relocation section (explicit addends) {}:\n",
                             name);
                    traverse_relas(actual, actual_syms, actual_strs, expected);
                    println!(" symbols:\n");
                    traverse_symtab(actual_syms, actual_strs, expected_syms);
                    println!();
                    println!(" strings:\n");
                    traverse_strtab(actual_strs, expected_strs);
                    println!();
                    println!();
                },
                SectionHdrData::Null => {
                    panic!("Expected rela section, got null instead");
                },
                SectionHdrData::ProgBits { name, .. } => {
                    panic!("Expected rela section {}, got progbits instead",
                           name);
                },
                SectionHdrData::Symtab { name, .. } => {
                    panic!("Expected rela section {}, got symtab instead",
                           name);
                },
                SectionHdrData::Strtab { name, .. } => {
                    panic!("Expected rela section {}, got strtab instead",
                           name);
                },
                SectionHdrData::Hash { name, .. } => {
                    panic!("Expected rela section {}, got hash instead",
                           name);
                },
                SectionHdrData::Dynamic { name, .. } => {
                    panic!("Expected rela section {}, got dynamic instead",
                           name);
                },
                SectionHdrData::Note { name, .. } => {
                    panic!("Expected rela section {}, got note instead",
                           name);
                },
                SectionHdrData::Nobits { name, .. } => {
                    panic!("Expected rela section {}, got nobits instead",
                           name);
                },
                SectionHdrData::Rel { name, .. } => {
                    panic!("Expected rela section {}, got rela instead",
                           name);
                },
                SectionHdrData::Dynsym { name, .. } => {
                    panic!("Expected rela section {}, got dynsym instead",
                           name);
                },
                SectionHdrData::Unknown { name, .. } => {
                    panic!("Expected rela section {}, got unknown instead",
                           name);
                }
            },
            SectionHdrData::Hash { symtab: SymsStrs { syms: expected, .. },
                                   .. } => match hdr {
                SectionHdrData::Hash { name, symtab: SymsStrs { syms, strs },
                                       hash, .. } => {
                    println!("Hash section {}:\n", name);
                    traverse_hash(hash, syms, strs, expected);
                    println!();
                },
                SectionHdrData::Null => {
                    panic!("Expected hash section, got null instead");
                },
                SectionHdrData::ProgBits { name, .. } => {
                    panic!("Expected hash section {}, got progbits instead",
                           name);
                },
                SectionHdrData::Symtab { name, .. } => {
                    panic!("Expected hash section {}, got symtab instead",
                           name);
                },
                SectionHdrData::Strtab { name, .. } => {
                    panic!("Expected hash section {}, got strtab instead",
                           name);
                },
                SectionHdrData::Rela { name, .. } => {
                    panic!("Expected hash section {}, got rela instead",
                           name);
                },
                SectionHdrData::Dynamic { name, .. } => {
                    panic!("Expected hash section {}, got dynamic instead",
                           name);
                },
                SectionHdrData::Note { name, .. } => {
                    panic!("Expected hash section {}, got note instead",
                           name);
                },
                SectionHdrData::Nobits { name, .. } => {
                    panic!("Expected hash section {}, got nobits instead",
                           name);
                },
                SectionHdrData::Rel { name, .. } => {
                    panic!("Expected hash section {}, got rela instead",
                           name);
                },
                SectionHdrData::Dynsym { name, .. } => {
                    panic!("Expected hash section {}, got dynsym instead",
                           name);
                },
                SectionHdrData::Unknown { name, .. } => {
                    panic!("Expected hash section {}, got unknown instead",
                           name);
                }
            },
            SectionHdrData::Dynamic { strtab: expected_strs,
                                      dynamic: expected, .. } => match hdr {
                SectionHdrData::Dynamic { name, strtab: actual_strs,
                                          dynamic: actual, .. } => {
                    println!("Dynamic section {}:\n", name);
                    traverse_dynamic(actual, actual_strs, expected);
                    println!(" strings:\n");
                    traverse_strtab(actual_strs, expected_strs);
                    println!();
                },
                SectionHdrData::Null => {
                    panic!("Expected dynamic section, got null instead");
                },
                SectionHdrData::ProgBits { name, .. } => {
                    panic!("Expected dynamic section {}, got progbits instead",
                           name);
                },
                SectionHdrData::Symtab { name, .. } => {
                    panic!("Expected dynamic section {}, got symtab instead",
                           name);
                },
                SectionHdrData::Strtab { name, .. } => {
                    panic!("Expected dynamic section {}, got strtab instead",
                           name);
                },
                SectionHdrData::Rela { name, .. } => {
                    panic!("Expected dynamic section {}, got rela instead",
                           name);
                },
                SectionHdrData::Hash { name, .. } => {
                    panic!("Expected dynamic section {}, got hash instead",
                           name);
                },
                SectionHdrData::Note { name, .. } => {
                    panic!("Expected dynamic section {}, got note instead",
                           name);
                },
                SectionHdrData::Nobits { name, .. } => {
                    panic!("Expected dynamic section {}, got nobits instead",
                           name);
                },
                SectionHdrData::Rel { name, .. } => {
                    panic!("Expected dynamic section {}, got rela instead",
                           name);
                },
                SectionHdrData::Dynsym { name, .. } => {
                    panic!("Expected dynamic section {}, got dynsym instead",
                           name);
                },
                SectionHdrData::Unknown { name, .. } => {
                    panic!("Expected dynamic section {}, got unknown instead",
                           name);
                }
            },
            SectionHdrData::Note { note: expected, .. } => match hdr {
                SectionHdrData::Note { name, note: actual, .. } => {
                    println!("Note section {}:\n", name);
                    traverse_notes(actual, expected)
                },
                SectionHdrData::Null => {
                    panic!("Expected note section, got null instead");
                },
                SectionHdrData::ProgBits { name, .. } => {
                    panic!("Expected note section {}, got progbits instead",
                           name);
                },
                SectionHdrData::Symtab { name, .. } => {
                    panic!("Expected note section {}, got symtab instead",
                           name);
                },
                SectionHdrData::Strtab { name, .. } => {
                    panic!("Expected note section {}, got strtab instead",
                           name);
                },
                SectionHdrData::Rela { name, .. } => {
                    panic!("Expected note section {}, got rela instead",
                           name);
                },
                SectionHdrData::Hash { name, .. } => {
                    panic!("Expected note section {}, got hash instead",
                           name);
                },
                SectionHdrData::Dynamic { name, .. } => {
                    panic!("Expected note section {}, got dynamic instead",
                           name);
                },
                SectionHdrData::Nobits { name, .. } => {
                    panic!("Expected note section {}, got nobits instead",
                           name);
                },
                SectionHdrData::Rel { name, .. } => {
                    panic!("Expected note section {}, got rela instead",
                           name);
                },
                SectionHdrData::Dynsym { name, .. } => {
                    panic!("Expected note section {}, got dynsym instead",
                           name);
                },
                SectionHdrData::Unknown { name, .. } => {
                    panic!("Expected note section {}, got unknown instead",
                           name);
                },
            },
            SectionHdrData::Nobits { .. } => {},
            SectionHdrData::Rel { rels: expected,
                                  symtab: SymsStrs { syms: expected_syms,
                                                     strs: expected_strs },
                                  .. } => match hdr {
                SectionHdrData::Rel { name, rels: actual,
                                      symtab: SymsStrs { syms: actual_syms,
                                                         strs: actual_strs },
                                      .. } => {
                    println!("Relocation section (implicit addends) {}:\n",
                             name);
                    traverse_rels(actual, actual_syms, actual_strs, expected);
                    println!(" symbols:\n");
                    traverse_symtab(actual_syms, actual_strs, expected_syms);
                    println!();
                    println!(" strings:\n");
                    traverse_strtab(actual_strs, expected_strs);
                    println!();
                    println!();
                },
                SectionHdrData::Null => {
                    panic!("Expected rel section, got null instead");
                },
                SectionHdrData::ProgBits { name, .. } => {
                    panic!("Expected rel section {}, got progbits instead",
                           name);
                },
                SectionHdrData::Symtab { name, .. } => {
                    panic!("Expected rel section {}, got symtab instead",
                           name);
                },
                SectionHdrData::Strtab { name, .. } => {
                    panic!("Expected rel section {}, got strtab instead",
                           name);
                },
                SectionHdrData::Hash { name, .. } => {
                    panic!("Expected rel section {}, got hash instead",
                           name);
                },
                SectionHdrData::Dynamic { name, .. } => {
                    panic!("Expected rel section {}, got dynamic instead",
                           name);
                },
                SectionHdrData::Note { name, .. } => {
                    panic!("Expected rel section {}, got note instead",
                           name);
                },
                SectionHdrData::Nobits { name, .. } => {
                    panic!("Expected rel section {}, got nobits instead",
                           name);
                },
                SectionHdrData::Rela { name, .. } => {
                    panic!("Expected rel section {}, got rela instead",
                           name);
                },
                SectionHdrData::Dynsym { name, .. } => {
                    panic!("Expected rel section {}, got dynsym instead",
                           name);
                },
                SectionHdrData::Unknown { name, .. } => {
                    panic!("Expected rel section {}, got unknown instead",
                           name);
                }
            },
            SectionHdrData::Dynsym { strtab: expected_strs,
                                     syms: expected, .. } => match hdr {
                SectionHdrData::Dynsym { name, strtab: actual_strs,
                                         syms: actual, .. } => {
                    println!("Dynsym section {}:\n", name);
                    traverse_symtab(actual, actual_strs, expected);
                    println!(" strings:\n");
                    traverse_strtab(actual_strs, expected_strs);
                    println!();
                },
                SectionHdrData::Null => {
                    panic!("Expected dynsym section, got null instead");
                },
                SectionHdrData::ProgBits { name, .. } => {
                    panic!("Expected dynsym section {}, got progbits instead",
                           name);
                },
                SectionHdrData::Symtab { name, .. } => {
                    panic!("Expected dynsym section {}, got symtab instead",
                           name);
                },
                SectionHdrData::Strtab { name, .. } => {
                    panic!("Expected dynsym section {}, got strtab instead",
                           name);
                },
                SectionHdrData::Rela { name, .. } => {
                    panic!("Expected dynsym section {}, got rela instead",
                           name);
                },
                SectionHdrData::Hash { name, .. } => {
                    panic!("Expected dynsym section {}, got hash instead",
                           name);
                },
                SectionHdrData::Dynamic { name, .. } => {
                    panic!("Expected dynsym section {}, got dynamic instead",
                           name);
                },
                SectionHdrData::Note { name, .. } => {
                    panic!("Expected dynsym section {}, got note instead",
                           name);
                },
                SectionHdrData::Nobits { name, .. } => {
                    panic!("Expected dynsym section {}, got nobits instead",
                           name);
                },
                SectionHdrData::Rel { name, .. } => {
                    panic!("Expected dynsym section {}, got rela instead",
                           name);
                },
                SectionHdrData::Unknown { name, .. } => {
                    panic!("Expected dynsym section {}, got unknown instead",
                           name);
                }
            },
            SectionHdrData::Unknown { .. } => {},
        }
    }
}

pub fn traverse_elf_file<'a, 'b, B, Offsets, ArchRels, ArchRelas,
                         RelError, RelaError>(
        data: &'a [u8],
        header_data: &'b ElfHdrDataRaw<B, Offsets>,
        prog_hdrs: Option<&'b [ProgHdrDataRaw<Offsets>]>,
        section_hdrs_bare: &'b [SectionHdrDataRaw<Offsets>],
        section_hdrs_strs: &'b [SectionHdrDataRawStr<'b, Offsets>],
        expected: &'b [SectionHdrData<Offsets, &'b str,
                                      Offsets::Word,
                                      SymsStrs<&'b [SymDataStr<'b, Offsets>],
                                               &'b [(&'b str, usize)]>,
                                      &'b [(&'b str, usize)],
                                      SectionPos<Offsets::Offset>,
                                      &'b [SymDataStr<'b, Offsets>],
                                      &'b [(&'b str, usize)],
                                      &'b [ArchRels],
                                      &'b [ArchRelas],
                                      SectionPos<Offsets::Offset>,
                                      &'b [DynamicEntDataStr<'b, Offsets>],
                                      &'b [NoteData<'b>]>]
    ) where ElfHdrDataRaw<B, Offsets>: Display,
            ArchRelas: Display + Debug + Eq +
                       TryFrom<RelaDataStrSym<'a, Offsets>, Error = RelaError>,
            ArchRels: Display + Debug + Eq +
                      TryFrom<RelDataStrSym<'a, Offsets>, Error = RelError>,
            Offsets: 'a + Debug + ElfHdrOffsets,
            B: 'a + ElfByteOrder,
            RelaError: Debug,
            RelError: Debug {
    let hdr = traverse_elf_hdr(data, header_data);

    match prog_hdrs {
        Some(prog_hdrs) => {
            println!("Program headers:\n");

            traverse_prog_hdrs(hdr.prog_hdrs.expect("expected some"),
                               &prog_hdrs);
        },
        None => assert!(hdr.prog_hdrs.is_none())
    }

    println!("Section headers:\n");

    traverse_section_hdrs(hdr.section_hdrs, data,
                          hdr.section_hdr_strtab.into() as usize,
                          section_hdrs_bare, section_hdrs_strs);

    traverse_section_contents(hdr.section_hdrs, expected,
                              hdr.section_hdr_strtab.into() as usize, data);
}
