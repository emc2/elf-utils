use byteorder::ByteOrder;
use byteorder::LittleEndian;
use core::convert::TryFrom;
use core::convert::TryInto;
use elf_utils::Elf64;
use elf_utils::dynamic::Dynamic;
use elf_utils::dynamic::DynamicEntData;
use elf_utils::dynamic::DynamicError;

const ELF64_DYNAMIC_SIZE: usize = 272;

const ELF64_DYNAMIC: [u8; ELF64_DYNAMIC_SIZE] = [
    0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xa0, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf9, 0xff, 0xff, 0x6f, 0x00, 0x00, 0x00, 0x00,
    0xbc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x88, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xcc, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xc0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf5, 0xfe, 0xff, 0x6f, 0x00, 0x00, 0x00, 0x00,
    0x28, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf4, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x18, 0xd0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf0, 0xff, 0xff, 0x6f, 0x00, 0x00, 0x00, 0x00,
    0xf8, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xfc, 0xff, 0xff, 0x6f, 0x00, 0x00, 0x00, 0x00,
    0x2c, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xfd, 0xff, 0xff, 0x6f, 0x00, 0x00, 0x00, 0x00,
    0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
];

const ELF64_NUM_DYNAMIC_ENTS: usize = 17;

const ELF64_DYNAMIC_ENTS: [DynamicEntData<u64, u64, Elf64>;
                           ELF64_NUM_DYNAMIC_ENTS] = [
    DynamicEntData::Flags { flags: 0x2 },
    DynamicEntData::Rela { tab: 0x990 },
    DynamicEntData::RelaSize { size: 4512 },
    DynamicEntData::RelaEntSize { size: 24 },
    DynamicEntData::Unknown { tag: 0x6ffffff9, info: 188 },
    DynamicEntData::Symtab { tab: 0x288 },
    DynamicEntData::SymtabEntSize { size: 24 },
    DynamicEntData::Strtab { tab: 0x7cc },
    DynamicEntData::StrtabSize { size: 448 },
    DynamicEntData::Unknown { tag: 0x6ffffef5, info: 0x628 },
    DynamicEntData::Hash { tab: 0x6f4 },
    DynamicEntData::FiniArray { arr: 0x1d018 },
    DynamicEntData::FiniArraySize { size: 8 },
    DynamicEntData::Unknown { tag: 0x6ffffff0, info: 0x4f8 },
    DynamicEntData::Unknown { tag: 0x6ffffffc, info: 0x52c },
    DynamicEntData::Unknown { tag: 0x6ffffffd, info: 0x9 },
    DynamicEntData::None
];

#[test]
fn test_Dynamic_from_bytes_just_right() {
    let dynamic: Result<Dynamic<'_, LittleEndian, Elf64>, DynamicError> =
        Dynamic::try_from(&ELF64_DYNAMIC[0..]);

    assert!(dynamic.is_ok());
}

#[test]
fn test_Dynamic_from_bytes_too_small() {
    let dynamic: Result<Dynamic<'_, LittleEndian, Elf64>, DynamicError> =
        Dynamic::try_from(&ELF64_DYNAMIC[0 .. ELF64_DYNAMIC.len() - 1]);

    assert!(dynamic.is_err());
}

#[test]
fn test_Dynamic_from_bytes_num_ents() {
    let dynamic: Dynamic<'_, LittleEndian, Elf64> =
        Dynamic::try_from(&ELF64_DYNAMIC[0..]).expect("Expected success");

    assert_eq!(dynamic.num_ents(), ELF64_NUM_DYNAMIC_ENTS);
}

#[test]
fn test_Dynamic_from_bytes_iter_len() {
    let dynamic: Dynamic<'_, LittleEndian, Elf64> =
        Dynamic::try_from(&ELF64_DYNAMIC[0..]).expect("Expected success");
    let iter = dynamic.iter();

    assert_eq!(iter.len(), ELF64_NUM_DYNAMIC_ENTS);
}

#[test]
fn test_Dynamic_from_bytes_just_right_mut() {
    let mut buf = ELF64_DYNAMIC.clone();
    let dynamic: Result<Dynamic<'_, LittleEndian, Elf64>, DynamicError> =
        Dynamic::try_from(&mut buf[0..]);

    assert!(dynamic.is_ok());
}

#[test]
fn test_Dynamic_from_bytes_too_small_mut() {
    let mut buf = ELF64_DYNAMIC.clone();
    let dynamic: Result<Dynamic<'_, LittleEndian, Elf64>, DynamicError> =
        Dynamic::try_from(&mut buf[0 .. ELF64_DYNAMIC.len() - 1]);

    assert!(dynamic.is_err());
}

#[test]
fn test_Dynamic_from_bytes_num_syms_mut() {
    let mut buf = ELF64_DYNAMIC.clone();
    let dynamic: Dynamic<'_, LittleEndian, Elf64> =
        Dynamic::try_from(&mut buf[0..]).expect("Expected success");

    assert_eq!(dynamic.num_ents(), ELF64_NUM_DYNAMIC_ENTS);
}

#[test]
fn test_Dynamic_from_bytes_iter_len_mut() {
    let mut buf = ELF64_DYNAMIC.clone();
    let dynamic: Dynamic<'_, LittleEndian, Elf64> =
        Dynamic::try_from(&mut buf[0..]).expect("Expected success");
    let iter = dynamic.iter();

    assert_eq!(iter.len(), ELF64_NUM_DYNAMIC_ENTS);
}

#[test]
fn test_Dynamic_from_bytes_iter() {
    let dynamic: Dynamic<'_, LittleEndian, Elf64> =
        Dynamic::try_from(&ELF64_DYNAMIC[0..]).expect("Expected success");
    let mut iter = dynamic.iter();

    for expect in ELF64_DYNAMIC_ENTS.iter() {
        let sym = iter.next();

        assert!(sym.is_some());

        let data = sym.unwrap().try_into();

        assert!(data.is_ok());

        let actual = data.unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(iter.next().is_none());
}

#[test]
fn test_Dynamic_from_bytes_idx() {
    let dynamic: Dynamic<'_, LittleEndian, Elf64> =
        Dynamic::try_from(&ELF64_DYNAMIC[0..]).expect("Expected success");
    let mut iter = dynamic.iter();

    for i in 0 .. ELF64_DYNAMIC_ENTS.len() {
        let expect = &ELF64_DYNAMIC_ENTS[i];
        let sym = dynamic.idx(i);

        assert!(sym.is_some());

        let data = sym.unwrap().try_into();

        assert!(data.is_ok());

        let actual = data.unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(dynamic.idx(ELF64_DYNAMIC_ENTS.len()).is_none());
}

#[test]
fn test_Dynamic_create_just_right() {
    let mut buf = [0; ELF64_DYNAMIC_SIZE];
    let dynamic: Result<(Dynamic<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        Dynamic::create_split(&mut buf[0..],
                              ELF64_DYNAMIC_ENTS.iter().map(|x| *x));

    assert!(dynamic.is_ok());

    let (dynamic, buf) = dynamic.expect("Expected success");

    assert_eq!(buf.len(), 0);
}

#[test]
fn test_Dynamic_create_too_big() {
    let mut buf = [0; ELF64_DYNAMIC_SIZE + 1];
    let dynamic: Result<(Dynamic<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        Dynamic::create_split(&mut buf[0..],
                              ELF64_DYNAMIC_ENTS.iter().map(|x| *x));

    assert!(dynamic.is_ok());

    let (dynamic, buf) = dynamic.expect("Expected success");

    assert_eq!(buf.len(), 1);
}

#[test]
fn test_Dynamic_create_too_small() {
    let mut buf = [0; ELF64_DYNAMIC_SIZE - 1];
    let dynamic: Result<(Dynamic<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        Dynamic::create_split(&mut buf[0..],
                              ELF64_DYNAMIC_ENTS.iter().map(|x| *x));

    assert!(dynamic.is_err());
}

#[test]
fn test_Dynamic_create_iter() {
    let mut buf = [0; ELF64_DYNAMIC_SIZE];
    let dynamic: Result<(Dynamic<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        Dynamic::create_split(&mut buf[0..],
                              ELF64_DYNAMIC_ENTS.iter().map(|x| *x));

    assert!(dynamic.is_ok());

    let (dynamic, buf) = dynamic.expect("Expected success");

    assert_eq!(buf.len(), 0);

    let mut iter = dynamic.iter();

    for expect in ELF64_DYNAMIC_ENTS.iter() {
        let sym = iter.next();

        assert!(sym.is_some());

        let data = sym.unwrap().try_into();

        assert!(data.is_ok());

        let actual = data.unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(iter.next().is_none());
}

#[test]
fn test_Dynamic_create_idx() {
    let mut buf = [0; ELF64_DYNAMIC_SIZE];
    let dynamic: Result<(Dynamic<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        Dynamic::create_split(&mut buf[0..],
                              ELF64_DYNAMIC_ENTS.iter().map(|x| *x));

    assert!(dynamic.is_ok());

    let (dynamic, buf) = dynamic.expect("Expected success");

    assert_eq!(buf.len(), 0);

    for i in 0 .. ELF64_DYNAMIC_ENTS.len() {
        let expect = &ELF64_DYNAMIC_ENTS[i];
        let sym = dynamic.idx(i);

        assert!(sym.is_some());

        let data = sym.unwrap().try_into();

        assert!(data.is_ok());

        let actual = data.unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(dynamic.idx(ELF64_DYNAMIC_ENTS.len()).is_none());
}
