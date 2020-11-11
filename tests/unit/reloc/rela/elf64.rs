use byteorder::LittleEndian;
use core::convert::TryFrom;
use elf_utils::Elf64;
use elf_utils::reloc::RelaData;
use elf_utils::reloc::Relas;

const ELF64_RELAS_SIZE: usize = 600;

const ELF64_RELAS: [u8; ELF64_RELAS_SIZE] = [
    0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00,
    0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00,
    0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00,
    0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00,
    0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xca, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xdf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00,
    0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xfb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x26, 0x00, 0x00, 0x00,
    0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00,
    0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x2a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x3b, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x30, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00,
    0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x45, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x4a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x92, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0b, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xac, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
    0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xb1, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0b, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x37, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x3c, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x5e, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00,
    0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x79, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0b, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00,
    0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
];

const ELF64_NUM_RELAS: usize = 25;

const ELF64_RELAS_CONTENTS_BARE: [RelaData<u32, Elf64>; ELF64_NUM_RELAS] = [
    RelaData { offset: 0x22, sym: 36, kind: 2, addend: -5 },
    RelaData { offset: 0x2c, sym: 36, kind: 2, addend: -4 },
    RelaData { offset: 0x42, sym: 21, kind: 10, addend: 0 },
    RelaData { offset: 0x4f, sym: 35, kind: 4, addend: -4 },
    RelaData { offset: 0x63, sym: 28, kind: 2, addend: -4 },
    RelaData { offset: 0x7a, sym: 29, kind: 10, addend: 0 },
    RelaData { offset: 0x80, sym: 30, kind: 10, addend: 0 },
    RelaData { offset: 0xca, sym: 29, kind: 10, addend: 0 },
    RelaData { offset: 0xdf, sym: 33, kind: 4, addend: -4 },
    RelaData { offset: 0xfb, sym: 38, kind: 4, addend: -4 },
    RelaData { offset: 0x102, sym: 37, kind: 4, addend: -4 },
    RelaData { offset: 0x12a, sym: 21, kind: 10, addend: 0 },
    RelaData { offset: 0x13b, sym: 4, kind: 10, addend: 560 },
    RelaData { offset: 0x140, sym: 35, kind: 4, addend: -4 },
    RelaData { offset: 0x145, sym: 27, kind: 10, addend: 0 },
    RelaData { offset: 0x14a, sym: 26, kind: 10, addend: 0 },
    RelaData { offset: 0x192, sym: 27, kind: 11, addend: 0 },
    RelaData { offset: 0x1ac, sym: 32, kind: 4, addend: -4 },
    RelaData { offset: 0x1b1, sym: 25, kind: 10, addend: 0 },
    RelaData { offset: 0x1b7, sym: 24, kind: 10, addend: 0 },
    RelaData { offset: 0x202, sym: 25, kind: 11, addend: 0 },
    RelaData { offset: 0x237, sym: 23, kind: 10, addend: 0 },
    RelaData { offset: 0x23c, sym: 22, kind: 10, addend: 0 },
    RelaData { offset: 0x25e, sym: 31, kind: 4, addend: -4 },
    RelaData { offset: 0x279, sym: 23, kind: 11, addend: -8 },
];

#[test]
fn test_Relas_from_bytes_just_right() {
    let relas: Result<Relas<'_, LittleEndian, Elf64>, ()> =
        Relas::try_from(&ELF64_RELAS[0..]);

    assert!(relas.is_ok());
}

#[test]
fn test_Relas_from_bytes_too_small() {
    let relas: Result<Relas<'_, LittleEndian, Elf64>, ()> =
        Relas::try_from(&ELF64_RELAS[0 .. ELF64_RELAS.len() - 1]);

    assert!(relas.is_err());
}

#[test]
fn test_Relas_from_bytes_num_syms() {
    let relas: Relas<'_, LittleEndian, Elf64> =
        Relas::try_from(&ELF64_RELAS[0..]).expect("Expected success");

    assert_eq!(relas.num_relocs(), ELF64_NUM_RELAS);
}

#[test]
fn test_Relas_from_bytes_iter_len() {
    let relas: Relas<'_, LittleEndian, Elf64> =
        Relas::try_from(&ELF64_RELAS[0..]).expect("Expected success");
    let iter = relas.iter();

    assert_eq!(iter.len(), ELF64_NUM_RELAS);
}

#[test]
fn test_Relas_from_bytes_just_right_mut() {
    let mut buf = ELF64_RELAS.clone();
    let relas: Result<Relas<'_, LittleEndian, Elf64>, ()> =
        Relas::try_from(&mut buf[0..]);

    assert!(relas.is_ok());
}

#[test]
fn test_Relas_from_bytes_too_small_mut() {
    let mut buf = ELF64_RELAS.clone();
    let relas: Result<Relas<'_, LittleEndian, Elf64>, ()> =
        Relas::try_from(&mut buf[0 .. ELF64_RELAS.len() - 1]);

    assert!(relas.is_err());
}

#[test]
fn test_Relas_from_bytes_num_syms_mut() {
    let mut buf = ELF64_RELAS.clone();
    let relas: Relas<'_, LittleEndian, Elf64> =
        Relas::try_from(&mut buf[0..]).expect("Expected success");

    assert_eq!(relas.num_relocs(), ELF64_NUM_RELAS);
}

#[test]
fn test_Relas_from_bytes_iter_len_mut() {
    let mut buf = ELF64_RELAS.clone();
    let relas: Relas<'_, LittleEndian, Elf64> =
        Relas::try_from(&mut buf[0..]).expect("Expected success");
    let iter = relas.iter();

    assert_eq!(iter.len(), ELF64_NUM_RELAS);
}

#[test]
fn test_Relas_from_bytes_iter() {
    let relas: Relas<'_, LittleEndian, Elf64> =
        Relas::try_from(&ELF64_RELAS[0..]).expect("Expected success");
    let mut iter = relas.iter();
    for expect in ELF64_RELAS_CONTENTS_BARE.iter() {
        let rela = iter.next();

        assert!(rela.is_some());

        let actual = rela.unwrap().into();

        assert_eq!(expect, &actual)
    }

    assert!(iter.next().is_none());
}

#[test]
fn test_Relas_from_bytes_idx() {
    let relas: Relas<'_, LittleEndian, Elf64> =
        Relas::try_from(&ELF64_RELAS[0..]).expect("Expected success");
    let mut iter = relas.iter();

    for i in 0 .. ELF64_NUM_RELAS {
        let expect = &ELF64_RELAS_CONTENTS_BARE[i];
        let rela = relas.idx(i);

        assert!(rela.is_some());

        let actual = rela.unwrap().into();

        assert_eq!(expect, &actual)
    }

    assert!(relas.idx(ELF64_RELAS_CONTENTS_BARE.len()).is_none());
}

#[test]
fn test_Relas_create_just_right() {
    let mut buf = [0; ELF64_RELAS_SIZE];
    let relas: Result<(Relas<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        Relas::create_split(&mut buf[0..], ELF64_RELAS_CONTENTS_BARE.iter());

    assert!(relas.is_ok());

    let (relas, buf) = relas.expect("Expected success");

    assert_eq!(buf.len(), 0);
}

#[test]
fn test_Relas_create_too_big() {
    let mut buf = [0; ELF64_RELAS_SIZE + 1];
    let relas: Result<(Relas<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        Relas::create_split(&mut buf[0..], ELF64_RELAS_CONTENTS_BARE.iter());

    assert!(relas.is_ok());

    let (relas, buf) = relas.expect("Expected success");

    assert_eq!(buf.len(), 1);
}

#[test]
fn test_Relas_create_too_small() {
    let mut buf = [0; ELF64_RELAS_SIZE - 1];
    let relas: Result<(Relas<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        Relas::create_split(&mut buf[0..], ELF64_RELAS_CONTENTS_BARE.iter());

    assert!(relas.is_err());
}

#[test]
fn test_Relas_create_iter() {
    let mut buf = [0; ELF64_RELAS_SIZE];
    let relas: Result<(Relas<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        Relas::create_split(&mut buf[0..], ELF64_RELAS_CONTENTS_BARE.iter());

    assert!(relas.is_ok());

    let (relas, buf) = relas.expect("Expected success");

    assert_eq!(buf.len(), 0);

    let mut iter = relas.iter();

    for expect in ELF64_RELAS_CONTENTS_BARE.iter() {
        let sym = iter.next();

        assert!(sym.is_some());

        let actual = sym.unwrap().into();

        assert_eq!(expect, &actual)
    }

    assert!(iter.next().is_none());
}

#[test]
fn test_Relas_create_idx() {
    let mut buf = [0; ELF64_RELAS_SIZE];
    let relas: Result<(Relas<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        Relas::create_split(&mut buf[0..], ELF64_RELAS_CONTENTS_BARE.iter());

    assert!(relas.is_ok());

    let (relas, buf) = relas.expect("Expected success");

    assert_eq!(buf.len(), 0);

    for i in 0 .. ELF64_RELAS_CONTENTS_BARE.len() {
        let expect = &ELF64_RELAS_CONTENTS_BARE[i];
        let sym = relas.idx(i);

        assert!(sym.is_some());

        let actual = sym.unwrap().into();

        assert_eq!(expect, &actual)
    }

    assert!(relas.idx(ELF64_RELAS_CONTENTS_BARE.len()).is_none());
}