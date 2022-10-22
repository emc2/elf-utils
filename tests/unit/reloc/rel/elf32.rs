use byteorder::LittleEndian;
use core::convert::TryFrom;
use elf_utils::Elf32;
use elf_utils::reloc::RelData;
use elf_utils::reloc::Rels;
use elf_utils::reloc::RelsError;

const ELF32_RELS_SIZE: usize = 208;

const ELF32_RELS: [u8; ELF32_RELS_SIZE] = [
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

const ELF32_NUM_RELS: usize = 26;

const ELF32_RELS_CONTENTS_BARE: [RelData<u32, Elf32>; ELF32_NUM_RELS] = [
    RelData { offset: 0x15, sym: 97, kind: 1 },
    RelData { offset: 0x1e, sym: 97, kind: 1 },
    RelData { offset: 0x2d, sym: 83, kind: 1 },
    RelData { offset: 0x39, sym: 96, kind: 2 },
    RelData { offset: 0x51, sym: 90, kind: 1 },
    RelData { offset: 0x69, sym: 92, kind: 1 },
    RelData { offset: 0x6f, sym: 91, kind: 1 },
    RelData { offset: 0xfc, sym: 91, kind: 1 },
    RelData { offset: 0x107, sym: 95, kind: 2 },
    RelData { offset: 0x122, sym: 99, kind: 2 },
    RelData { offset: 0x12b, sym: 98, kind: 2 },
    RelData { offset: 0x140, sym: 83, kind: 1 },
    RelData { offset: 0x14d, sym: 62, kind: 1 },
    RelData { offset: 0x152, sym: 96, kind: 2 },
    RelData { offset: 0x15a, sym: 89, kind: 1 },
    RelData { offset: 0x15f, sym: 88, kind: 1 },
    RelData { offset: 0x198, sym: 89, kind: 1 },
    RelData { offset: 0x1b7, sym: 94, kind: 2 },
    RelData { offset: 0x1bc, sym: 87, kind: 1 },
    RelData { offset: 0x1c1, sym: 86, kind: 1 },
    RelData { offset: 0x1f8, sym: 87, kind: 1 },
    RelData { offset: 0x225, sym: 85, kind: 1 },
    RelData { offset: 0x22a, sym: 84, kind: 1 },
    RelData { offset: 0x242, sym: 93, kind: 2 },
    RelData { offset: 0x257, sym: 85, kind: 1 },
    RelData { offset: 0x27c, sym: 81, kind: 2 },
];

#[test]
fn test_Rels_from_bytes_just_right() {
    let rels: Result<Rels<'_, LittleEndian, Elf32>, RelsError> =
        Rels::try_from(&ELF32_RELS[0..]);

    assert!(rels.is_ok());
}

#[test]
fn test_Rels_from_bytes_too_small() {
    let rels: Result<Rels<'_, LittleEndian, Elf32>, RelsError> =
        Rels::try_from(&ELF32_RELS[0 .. ELF32_RELS.len() - 1]);

    assert!(rels.is_err());
}

#[test]
fn test_Rels_from_bytes_num_syms() {
    let rels: Rels<'_, LittleEndian, Elf32> =
        Rels::try_from(&ELF32_RELS[0..]).expect("Expected success");

    assert_eq!(rels.num_relocs(), ELF32_NUM_RELS);
}

#[test]
fn test_Rels_from_bytes_iter_len() {
    let rels: Rels<'_, LittleEndian, Elf32> =
        Rels::try_from(&ELF32_RELS[0..]).expect("Expected success");
    let mut iter = rels.iter();

    for i in 0 .. ELF32_NUM_RELS {
        assert_eq!(iter.len(), ELF32_NUM_RELS - i);
        assert!(iter.next().is_some());
    }

    assert!(iter.next().is_none());
}

#[test]
fn test_Rels_from_bytes_just_right_mut() {
    let mut buf = ELF32_RELS.clone();
    let rels: Result<Rels<'_, LittleEndian, Elf32>, RelsError> =
        Rels::try_from(&mut buf[0..]);

    assert!(rels.is_ok());
}

#[test]
fn test_Rels_from_bytes_too_small_mut() {
    let mut buf = ELF32_RELS.clone();
    let rels: Result<Rels<'_, LittleEndian, Elf32>, RelsError> =
        Rels::try_from(&mut buf[0 .. ELF32_RELS.len() - 1]);

    assert!(rels.is_err());
}

#[test]
fn test_Rels_from_bytes_num_syms_mut() {
    let mut buf = ELF32_RELS.clone();
    let rels: Rels<'_, LittleEndian, Elf32> =
        Rels::try_from(&mut buf[0..]).expect("Expected success");

    assert_eq!(rels.num_relocs(), ELF32_NUM_RELS);
}

#[test]
fn test_Rels_from_bytes_iter_len_mut() {
    let mut buf = ELF32_RELS.clone();
    let rels: Rels<'_, LittleEndian, Elf32> =
        Rels::try_from(&mut buf[0..]).expect("Expected success");
    let iter = rels.iter();

    assert_eq!(iter.len(), ELF32_NUM_RELS);
}

#[test]
fn test_Rels_from_bytes_iter() {
    let rels: Rels<'_, LittleEndian, Elf32> =
        Rels::try_from(&ELF32_RELS[0..]).expect("Expected success");
    let mut iter = rels.iter();

    for expect in ELF32_RELS_CONTENTS_BARE.iter() {
        let rel = iter.next();

        assert!(rel.is_some());

        let actual = rel.unwrap().into();

        assert_eq!(expect, &actual)
    }

    assert!(iter.next().is_none());
}

#[test]
fn test_Rels_from_bytes_idx() {
    let rels: Rels<'_, LittleEndian, Elf32> =
        Rels::try_from(&ELF32_RELS[0..]).expect("Expected success");
    let mut iter = rels.iter();

    for i in 0 .. ELF32_NUM_RELS {
        let expect = &ELF32_RELS_CONTENTS_BARE[i];
        let rel = rels.idx(i);

        assert!(rel.is_some());

        let actual = rel.unwrap().into();

        assert_eq!(expect, &actual)
    }

    assert!(rels.idx(ELF32_RELS_CONTENTS_BARE.len()).is_none());
}

#[test]
fn test_Rels_create_just_right() {
    let mut buf = [0; ELF32_RELS_SIZE];
    let rels: Result<(Rels<'_, LittleEndian, Elf32>, &'_ mut [u8]), ()> =
        Rels::create_split(&mut buf[0..], ELF32_RELS_CONTENTS_BARE.iter());

    assert!(rels.is_ok());

    let (rels, buf) = rels.expect("Expected success");

    assert_eq!(buf.len(), 0);
}

#[test]
fn test_Rels_create_too_big() {
    let mut buf = [0; ELF32_RELS_SIZE + 1];
    let rels: Result<(Rels<'_, LittleEndian, Elf32>, &'_ mut [u8]), ()> =
        Rels::create_split(&mut buf[0..], ELF32_RELS_CONTENTS_BARE.iter());

    assert!(rels.is_ok());

    let (rels, buf) = rels.expect("Expected success");

    assert_eq!(buf.len(), 1);
}

#[test]
fn test_Rels_create_too_small() {
    let mut buf = [0; ELF32_RELS_SIZE - 1];
    let rels: Result<(Rels<'_, LittleEndian, Elf32>, &'_ mut [u8]), ()> =
        Rels::create_split(&mut buf[0..], ELF32_RELS_CONTENTS_BARE.iter());

    assert!(rels.is_err());
}

#[test]
fn test_Rels_create_iter() {
    let mut buf = [0; ELF32_RELS_SIZE];
    let rels: Result<(Rels<'_, LittleEndian, Elf32>, &'_ mut [u8]), ()> =
        Rels::create_split(&mut buf[0..], ELF32_RELS_CONTENTS_BARE.iter());

    assert!(rels.is_ok());

    let (rels, buf) = rels.expect("Expected success");

    assert_eq!(buf.len(), 0);

    let mut iter = rels.iter();

    for expect in ELF32_RELS_CONTENTS_BARE.iter() {
        let sym = iter.next();

        assert!(sym.is_some());

        let actual = sym.unwrap().into();

        assert_eq!(expect, &actual)
    }

    assert!(iter.next().is_none());
}

#[test]
fn test_Rels_create_idx() {
    let mut buf = [0; ELF32_RELS_SIZE];
    let rels: Result<(Rels<'_, LittleEndian, Elf32>, &'_ mut [u8]), ()> =
        Rels::create_split(&mut buf[0..], ELF32_RELS_CONTENTS_BARE.iter());

    assert!(rels.is_ok());

    let (rels, buf) = rels.expect("Expected success");

    assert_eq!(buf.len(), 0);

    for i in 0 .. ELF32_RELS_CONTENTS_BARE.len() {
        let expect = &ELF32_RELS_CONTENTS_BARE[i];
        let sym = rels.idx(i);

        assert!(sym.is_some());

        let actual = sym.unwrap().into();

        assert_eq!(expect, &actual)
    }

    assert!(rels.idx(ELF32_RELS_CONTENTS_BARE.len()).is_none());
}
