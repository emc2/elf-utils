use byteorder::LittleEndian;
use core::convert::TryFrom;
use core::convert::TryInto;
use elf_utils::Elf32;
use elf_utils::reloc::RelData;
use elf_utils::reloc::Rels;
use elf_utils::reloc::x86::X86Reloc;
use elf_utils::reloc::x86::X86RelocError;

const X86_RELS_SIZE: usize = 208;

const X86_RELS: [u8; X86_RELS_SIZE] = [
    0x15, 0x00, 0x00, 0x00, 0x01, 0x61, 0x00, 0x00,
    0x1e, 0x00, 0x00, 0x00, 0x01, 0x61, 0x00, 0x00,
    0x2d, 0x00, 0x00, 0x00, 0x01, 0x53, 0x00, 0x00,
    0x39, 0x00, 0x00, 0x00, 0x02, 0x60, 0x00, 0x00,
    0x51, 0x00, 0x00, 0x00, 0x01, 0x5a, 0x00, 0x00,
    0x69, 0x00, 0x00, 0x00, 0x01, 0x5c, 0x00, 0x00,
    0x6f, 0x00, 0x00, 0x00, 0x01, 0x5b, 0x00, 0x00,
    0xfc, 0x00, 0x00, 0x00, 0x01, 0x5b, 0x00, 0x00,
    0x07, 0x01, 0x00, 0x00, 0x02, 0x5f, 0x00, 0x00,
    0x22, 0x01, 0x00, 0x00, 0x02, 0x63, 0x00, 0x00,
    0x2b, 0x01, 0x00, 0x00, 0x02, 0x62, 0x00, 0x00,
    0x40, 0x01, 0x00, 0x00, 0x01, 0x53, 0x00, 0x00,
    0x4d, 0x01, 0x00, 0x00, 0x01, 0x3e, 0x00, 0x00,
    0x52, 0x01, 0x00, 0x00, 0x02, 0x60, 0x00, 0x00,
    0x5a, 0x01, 0x00, 0x00, 0x01, 0x59, 0x00, 0x00,
    0x5f, 0x01, 0x00, 0x00, 0x01, 0x58, 0x00, 0x00,
    0x98, 0x01, 0x00, 0x00, 0x01, 0x59, 0x00, 0x00,
    0xb7, 0x01, 0x00, 0x00, 0x02, 0x5e, 0x00, 0x00,
    0xbc, 0x01, 0x00, 0x00, 0x01, 0x57, 0x00, 0x00,
    0xc1, 0x01, 0x00, 0x00, 0x01, 0x56, 0x00, 0x00,
    0xf8, 0x01, 0x00, 0x00, 0x01, 0x57, 0x00, 0x00,
    0x25, 0x02, 0x00, 0x00, 0x01, 0x55, 0x00, 0x00,
    0x2a, 0x02, 0x00, 0x00, 0x01, 0x54, 0x00, 0x00,
    0x42, 0x02, 0x00, 0x00, 0x02, 0x5d, 0x00, 0x00,
    0x57, 0x02, 0x00, 0x00, 0x01, 0x55, 0x00, 0x00,
    0x7c, 0x02, 0x00, 0x00, 0x02, 0x51, 0x00, 0x00
];

const X86_NUM_RELS: usize = 26;

const X86_RELS_CONTENTS: [X86Reloc<u32>; X86_NUM_RELS] = [
    X86Reloc::Abs32 { offset: 0x15, sym: 97, addend: 0 },
    X86Reloc::Abs32 { offset: 0x1e, sym: 97, addend: 0 },
    X86Reloc::Abs32 { offset: 0x2d, sym: 83, addend: 0 },
    X86Reloc::PC32 { offset: 0x39, sym: 96, addend: 0 },
    X86Reloc::Abs32 { offset: 0x51, sym: 90, addend: 0 },
    X86Reloc::Abs32 { offset: 0x69, sym: 92, addend: 0 },
    X86Reloc::Abs32 { offset: 0x6f, sym: 91, addend: 0 },
    X86Reloc::Abs32 { offset: 0xfc, sym: 91, addend: 0 },
    X86Reloc::PC32 { offset: 0x107, sym: 95, addend: 0 },
    X86Reloc::PC32 { offset: 0x122, sym: 99, addend: 0 },
    X86Reloc::PC32 { offset: 0x12b, sym: 98, addend: 0 },
    X86Reloc::Abs32 { offset: 0x140, sym: 83, addend: 0 },
    X86Reloc::Abs32 { offset: 0x14d, sym: 62, addend: 0 },
    X86Reloc::PC32 { offset: 0x152, sym: 96, addend: 0 },
    X86Reloc::Abs32 { offset: 0x15a, sym: 89, addend: 0 },
    X86Reloc::Abs32 { offset: 0x15f, sym: 88, addend: 0 },
    X86Reloc::Abs32 { offset: 0x198, sym: 89, addend: 0 },
    X86Reloc::PC32 { offset: 0x1b7, sym: 94, addend: 0 },
    X86Reloc::Abs32 { offset: 0x1bc, sym: 87, addend: 0 },
    X86Reloc::Abs32 { offset: 0x1c1, sym: 86, addend: 0 },
    X86Reloc::Abs32 { offset: 0x1f8, sym: 87, addend: 0 },
    X86Reloc::Abs32 { offset: 0x225, sym: 85, addend: 0 },
    X86Reloc::Abs32 { offset: 0x22a, sym: 84, addend: 0 },
    X86Reloc::PC32 { offset: 0x242, sym: 93, addend: 0 },
    X86Reloc::Abs32 { offset: 0x257, sym: 85, addend: 0 },
    X86Reloc::PC32 { offset: 0x27c, sym: 81, addend: 0 },
];

#[test]
fn test_Rels_from_bytes_iter() {
    let rels: Rels<'_, LittleEndian, Elf32> =
        Rels::try_from(&X86_RELS[0..]).expect("Expected success");
    let mut iter = rels.iter();

    for expect in X86_RELS_CONTENTS.iter() {
        let rel = iter.next();

        assert!(rel.is_some());

        let raw: RelData<u32, Elf32> = rel.unwrap().into();
        let data: Result<X86Reloc<u32>, X86RelocError> = raw.try_into();

        assert!(data.is_ok());

        let actual = data.unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(iter.next().is_none());
}

#[test]
fn test_Rels_from_bytes_idx() {
    let rels: Rels<'_, LittleEndian, Elf32> =
        Rels::try_from(&X86_RELS[0..]).expect("Expected success");
    let mut iter = rels.iter();

    for i in 0 .. X86_NUM_RELS {
        let expect = &X86_RELS_CONTENTS[i];
        let rel = rels.idx(i);

        assert!(rel.is_some());

        let raw: RelData<u32, Elf32> = rel.unwrap().into();
        let data: Result<X86Reloc<u32>, X86RelocError> = raw.try_into();

        assert!(data.is_ok());

        let actual = data.unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(rels.idx(X86_RELS_CONTENTS.len()).is_none());
}

/*
#[test]
fn test_Rels_create_iter() {
    let mut buf = [0; X86_RELS_SIZE];
    let rels: Result<(Rels<'_, LittleEndian, u32>, &'_ mut [u8]), ()> =
        Rels::create_split(&mut buf[0..], X86_RELS_CONTENTS.iter());

    assert!(rels.is_ok());

    let (rels, buf) = rels.expect("Expected success");

    assert_eq!(buf.len(), 0);

    let mut iter = rels.iter();

    for expect in X86_RELS_CONTENTS.iter() {
        let sym = iter.next();

        assert!(sym.is_some());

        let data = sym.unwrap().into().try_into();

        assert!(data.is_ok())

        let actual = datax.unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(iter.next().is_none());
}

#[test]
fn test_Rels_create_idx() {
    let mut buf = [0; X86_RELS_SIZE];
    let rels: Result<(Rels<'_, LittleEndian, u32>, &'_ mut [u8]), ()> =
        Rels::create_split(&mut buf[0..], X86_RELS_CONTENTS.iter());

    assert!(rels.is_ok());

    let (rels, buf) = rels.expect("Expected success");

    assert_eq!(buf.len(), 0);

    for i in 0 .. X86_RELS_CONTENTS.len() {
        let expect = &X86_RELS_CONTENTS[i];
        let sym = rels.idx(i);

        assert!(sym.is_some());

        let data = sym.unwrap().into().try_into();

        assert!(data.is_ok())

        let actual = datax.unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(rels.idx(X86_RELS_CONTENTS.len()).is_none());
}
*/
