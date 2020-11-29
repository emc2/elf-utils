use byteorder::LittleEndian;
use core::convert::TryFrom;
use core::convert::TryInto;
use elf_utils::Elf64;
use elf_utils::hash::Hashtab;
use elf_utils::hash::HashtabMut;
use elf_utils::hash::HashtabError;
use elf_utils::strtab::Strtab;
use elf_utils::strtab::WithStrtab;
use elf_utils::symtab::SymData;
use elf_utils::symtab::Symtab;

const ELF_SYMTAB_BYTES: usize = 384;

const ELF_SYMTAB: [u8; ELF_SYMTAB_BYTES] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x16, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x25, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x2a, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x4c, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x53, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x61, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x6f, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x74, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x82, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x11, 0x00, 0x17, 0x00,
    0x80, 0x3e, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x1d, 0x00, 0x00, 0x00, 0x11, 0x00, 0x19, 0x00,
    0xf8, 0x3e, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x3e, 0x00, 0x00, 0x00, 0x11, 0x00, 0x19, 0x00,
    0x10, 0x3f, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x68, 0x00, 0x00, 0x00, 0x11, 0x00, 0x19, 0x00,
    0x08, 0x3f, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
];

const ELF_STRTAB_BYTES: usize = 156;

const ELF_STRTAB: [u8; ELF_STRTAB_BYTES] = [
    0x00, 0x5f, 0x5f, 0x70, 0x72, 0x6f, 0x67, 0x6e,
    0x61, 0x6d, 0x65, 0x00, 0x5f, 0x69, 0x6e, 0x69,
    0x74, 0x5f, 0x74, 0x6c, 0x73, 0x00, 0x61, 0x74,
    0x65, 0x78, 0x69, 0x74, 0x00, 0x65, 0x6e, 0x76,
    0x69, 0x72, 0x6f, 0x6e, 0x00, 0x65, 0x78, 0x69,
    0x74, 0x00, 0x5f, 0x4a, 0x76, 0x5f, 0x52, 0x65,
    0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x43, 0x6c,
    0x61, 0x73, 0x73, 0x65, 0x73, 0x00, 0x5f, 0x5f,
    0x73, 0x74, 0x64, 0x65, 0x72, 0x72, 0x70, 0x00,
    0x65, 0x72, 0x72, 0x00, 0x66, 0x77, 0x72, 0x69,
    0x74, 0x65, 0x00, 0x67, 0x65, 0x74, 0x64, 0x6f,
    0x6d, 0x61, 0x69, 0x6e, 0x6e, 0x61, 0x6d, 0x65,
    0x00, 0x67, 0x65, 0x74, 0x6f, 0x70, 0x74, 0x00,
    0x6f, 0x70, 0x74, 0x69, 0x6e, 0x64, 0x00, 0x70,
    0x75, 0x74, 0x73, 0x00, 0x73, 0x65, 0x74, 0x64,
    0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x6e, 0x61, 0x6d,
    0x65, 0x00, 0x73, 0x74, 0x72, 0x6c, 0x65, 0x6e,
    0x00, 0x6c, 0x69, 0x62, 0x63, 0x2e, 0x73, 0x6f,
    0x2e, 0x37, 0x00, 0x46, 0x42, 0x53, 0x44, 0x5f,
    0x31, 0x2e, 0x30, 0x00
];

const ELF_HASH_BYTES: usize = 136;

const ELF_HASH: [u8; ELF_HASH_BYTES] = [
    0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
    0x0f, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00
];

const ELF_HASH_BAD_CHAINS: [u8; ELF_HASH_BYTES] = [
    0x10, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00,
    0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
    0x0f, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00
];

const ELF_HASH_BAD_HASHES: [u8; ELF_HASH_BYTES] = [
    0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
    0x0f, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00
];

#[test]
fn test_Hashtab_from_slice_ok() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF_SYMTAB[0..]).expect("Expected success");
    let hash: Result<Hashtab<'_, LittleEndian, Elf64>, HashtabError> =
        Hashtab::from_slice(&ELF_HASH[0..], strtab, symtab);

    assert!(hash.is_ok());
}

#[test]
fn test_Hashtab_from_slice_too_short_7() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF_SYMTAB[0..]).expect("Expected success");
    let hash: Result<Hashtab<'_, LittleEndian, Elf64>, HashtabError> =
        Hashtab::from_slice(&ELF_HASH[0..7], strtab, symtab);

    assert_eq!(hash.err(), Some(HashtabError::TooShort));
}

#[test]
fn test_Hashtab_from_slice_too_short() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF_SYMTAB[0..]).expect("Expected success");
    let hash: Result<Hashtab<'_, LittleEndian, Elf64>, HashtabError> =
        Hashtab::from_slice(&ELF_HASH[0 .. ELF_HASH.len() - 1], strtab, symtab);

    assert_eq!(hash.err(), Some(HashtabError::TooShort));
}

#[test]
fn test_Hashtab_from_slice_bad_chains() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF_SYMTAB[0..]).expect("Expected success");
    let hash: Result<Hashtab<'_, LittleEndian, Elf64>, HashtabError> =
        Hashtab::from_slice(&ELF_HASH_BAD_CHAINS[0..], strtab, symtab);

    assert_eq!(hash.err(), Some(HashtabError::BadChains {
        expected: 0x10, actual: 0x11,
    }));
}

#[test]
fn test_Hashtab_from_slice_bad_hashes() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF_SYMTAB[0..]).expect("Expected success");
    let hash: Result<Hashtab<'_, LittleEndian, Elf64>, HashtabError> =
        Hashtab::from_slice(&ELF_HASH_BAD_HASHES[0..], strtab, symtab);

    assert_eq!(hash.err(), Some(HashtabError::BadHashes));
}

#[test]
fn test_Hashtab_from_slice_lookup_syms() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF_SYMTAB[0..]).expect("Expected success");
    let hash: Hashtab<'_, LittleEndian, Elf64> =
        Hashtab::from_slice(&ELF_HASH[0..], strtab, symtab)
        .expect("Expected success");

    for sym in symtab.iter() {
        let expected: SymData<u32, u16, Elf64> = sym.try_into().unwrap();
        let named: SymData<Result<&'static str, &'static [u8]>, u16, Elf64> =
            expected.clone().with_strtab(strtab).unwrap();

        match named.name {
            Some(name) => {
                let lookup = hash.lookup(name);

                assert!(lookup.is_ok());

                let res = lookup.unwrap();

                assert!(res.is_some());

                let actual: SymData<u32, u16, Elf64> =
                    res.unwrap().try_into().unwrap();

                assert_eq!(actual, expected);
            },
            _ => {}
        }
    }
}

#[test]
fn test_Hashtab_from_slice_bad_lookup() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF_SYMTAB[0..]).expect("Expected success");
    let hash: Hashtab<'_, LittleEndian, Elf64> =
        Hashtab::from_slice(&ELF_HASH[0..], strtab, symtab)
        .expect("Expected success");

    let lookup = hash.lookup("SIR NOT APPEARING IN THIS OBJECT");

    assert!(lookup.is_ok());

    let res = lookup.unwrap();

    assert!(res.is_none());
}

#[test]
fn test_Hashtab_from_slice_empty_str_lookup() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF_SYMTAB[0..]).expect("Expected success");
    let hash: Hashtab<'_, LittleEndian, Elf64> =
        Hashtab::from_slice(&ELF_HASH[0..], strtab, symtab)
        .expect("Expected success");

    let lookup = hash.lookup("");

    assert!(lookup.is_ok());

    let res = lookup.unwrap();

    assert!(res.is_none());
}

#[test]
fn test_Hashtab_create_is_ok() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF_SYMTAB[0..]).expect("Expected success");
    let mut buf = [0; ELF_HASH_BYTES];
    let result: Result<(Hashtab<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        Hashtab::create_split(&mut buf[0..], strtab, symtab, symtab.num_syms());

    assert!(result.is_ok());

    let (hash, rest) = result.unwrap();

    assert_eq!(rest.len(), 0);
}

#[test]
fn test_Hashtab_create_too_small() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF_SYMTAB[0..]).expect("Expected success");
    let mut buf = [0; ELF_HASH_BYTES - 1];
    let result: Result<(Hashtab<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        Hashtab::create_split(&mut buf[0..], strtab, symtab, symtab.num_syms());

    assert!(result.is_err());
}

#[test]
fn test_Hashtab_create_too_big() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF_SYMTAB[0..]).expect("Expected success");
    let mut buf = [0; ELF_HASH_BYTES + 1];
    let result: Result<(Hashtab<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        Hashtab::create_split(&mut buf[0..], strtab, symtab, symtab.num_syms());

    assert!(result.is_ok());

    let (hash, rest) = result.unwrap();

    assert_eq!(rest.len(), 1);
}

#[test]
fn test_Hashtab_create_lookup_syms() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF_SYMTAB[0..]).expect("Expected success");
    let mut buf = [0; ELF_HASH_BYTES];
    let hash: Hashtab<'_, LittleEndian, Elf64> =
        Hashtab::create(&mut buf[0..], strtab, symtab,
                        symtab.num_syms()).unwrap();

    for sym in symtab.iter() {
        let expected: SymData<u32, u16, Elf64> = sym.try_into().unwrap();
        let named: SymData<Result<&'static str, &'static [u8]>, u16, Elf64> =
            expected.clone().with_strtab(strtab).unwrap();

        match named.name {
            Some(name) => {
                let lookup = hash.lookup(name);

                assert!(lookup.is_ok());

                let res = lookup.unwrap();

                assert!(res.is_some());

                let actual: SymData<u32, u16, Elf64> =
                    res.unwrap().try_into().unwrap();

                assert_eq!(actual, expected);
            },
            _ => {}
        }
    }
}

#[test]
fn test_HashtabMut_from_slice_ok() {
    let mut buf = ELF_HASH.clone();
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF_SYMTAB[0..]).expect("Expected success");
    let hash: Result<HashtabMut<'_, LittleEndian, Elf64>, HashtabError> =
        HashtabMut::from_slice(&mut buf[0..], strtab, symtab);

    assert!(hash.is_ok());
}

#[test]
fn test_HashtabMut_from_slice_too_short_7() {
    let mut buf = ELF_HASH.clone();
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF_SYMTAB[0..]).expect("Expected success");
    let hash: Result<HashtabMut<'_, LittleEndian, Elf64>, HashtabError> =
        HashtabMut::from_slice(&mut buf[0..7], strtab, symtab);

    assert_eq!(hash.err(), Some(HashtabError::TooShort));
}

#[test]
fn test_HashtabMut_from_slice_too_short() {
    let mut buf = ELF_HASH.clone();
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF_SYMTAB[0..]).expect("Expected success");
    let hash: Result<HashtabMut<'_, LittleEndian, Elf64>, HashtabError> =
        HashtabMut::from_slice(&mut buf[0 .. ELF_HASH.len() - 1],
                               strtab, symtab);

    assert_eq!(hash.err(), Some(HashtabError::TooShort));
}

#[test]
fn test_HashtabMut_from_slice_bad_chains() {
    let mut buf = ELF_HASH_BAD_CHAINS.clone();
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF_SYMTAB[0..]).expect("Expected success");
    let hash: Result<HashtabMut<'_, LittleEndian, Elf64>, HashtabError> =
        HashtabMut::from_slice(&mut buf[0..], strtab, symtab);

    assert_eq!(hash.err(), Some(HashtabError::BadChains {
        expected: 0x10, actual: 0x11,
    }));
}

#[test]
fn test_HashtabMut_from_slice_bad_hashes() {
    let mut buf = ELF_HASH_BAD_HASHES.clone();
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF_SYMTAB[0..]).expect("Expected success");
    let hash: Result<HashtabMut<'_, LittleEndian, Elf64>, HashtabError> =
        HashtabMut::from_slice(&mut buf[0..], strtab, symtab);

    assert_eq!(hash.err(), Some(HashtabError::BadHashes));
}

#[test]
fn test_HashtabMut_from_slice_lookup_syms() {
    let mut buf = ELF_HASH.clone();
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF_SYMTAB[0..]).expect("Expected success");
    let hash: HashtabMut<'_, LittleEndian, Elf64> =
        HashtabMut::from_slice(&mut buf[0..], strtab, symtab)
        .expect("Expected success");

    for sym in symtab.iter() {
        let expected: SymData<u32, u16, Elf64> = sym.try_into().unwrap();
        let named: SymData<Result<&'static str, &'static [u8]>, u16, Elf64> =
            expected.clone().with_strtab(strtab).unwrap();

        match named.name {
            Some(name) => {
                let lookup = hash.lookup(name);

                assert!(lookup.is_ok());

                let res = lookup.unwrap();

                assert!(res.is_some());

                let actual: SymData<u32, u16, Elf64> =
                    res.unwrap().try_into().unwrap();

                assert_eq!(actual, expected);
            },
            _ => {}
        }
    }
}

#[test]
fn test_HashtabMut_from_slice_bad_lookup() {
    let mut buf = ELF_HASH.clone();
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF_SYMTAB[0..]).expect("Expected success");
    let hash: HashtabMut<'_, LittleEndian, Elf64> =
        HashtabMut::from_slice(&mut buf[0..], strtab, symtab)
        .expect("Expected success");

    let lookup = hash.lookup("SIR NOT APPEARING IN THIS OBJECT");

    assert!(lookup.is_ok());

    let res = lookup.unwrap();

    assert!(res.is_none());
}

#[test]
fn test_HashtabMut_from_slice_empty_str_lookup() {
    let mut buf = ELF_HASH.clone();
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF_SYMTAB[0..]).expect("Expected success");
    let hash: HashtabMut<'_, LittleEndian, Elf64> =
        HashtabMut::from_slice(&mut buf[0..], strtab, symtab)
        .expect("Expected success");

    let lookup = hash.lookup("");

    assert!(lookup.is_ok());

    let res = lookup.unwrap();

    assert!(res.is_none());
}

#[test]
fn test_HashtabMut_create_is_ok() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF_SYMTAB[0..]).expect("Expected success");
    let mut buf = [0; ELF_HASH_BYTES];
    let result: Result<(HashtabMut<'_, LittleEndian, Elf64>,
                        &'_ mut [u8]), ()> =
        HashtabMut::create_split(&mut buf[0..], strtab,
                                 symtab, symtab.num_syms());

    assert!(result.is_ok());

    let (hash, rest) = result.unwrap();

    assert_eq!(rest.len(), 0);
}

#[test]
fn test_HashtabMut_create_too_small() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF_SYMTAB[0..]).expect("Expected success");
    let mut buf = [0; ELF_HASH_BYTES - 1];
    let result: Result<(HashtabMut<'_, LittleEndian, Elf64>,
                        &'_ mut [u8]), ()> =
        HashtabMut::create_split(&mut buf[0..], strtab,
                                 symtab, symtab.num_syms());

    assert!(result.is_err());
}

#[test]
fn test_HashtabMut_create_too_big() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF_SYMTAB[0..]).expect("Expected success");
    let mut buf = [0; ELF_HASH_BYTES + 1];
    let result: Result<(HashtabMut<'_, LittleEndian, Elf64>,
                        &'_ mut [u8]), ()> =
        HashtabMut::create_split(&mut buf[0..], strtab,
                                 symtab, symtab.num_syms());

    assert!(result.is_ok());

    let (hash, rest) = result.unwrap();

    assert_eq!(rest.len(), 1);
}

#[test]
fn test_HashtabMut_create_lookup_syms() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_STRTAB[0..]).expect("Expected success");
    let symtab: Symtab<'_, LittleEndian, Elf64> =
        Symtab::try_from(&ELF_SYMTAB[0..]).expect("Expected success");
    let mut buf = [0; ELF_HASH_BYTES];
    let hash: HashtabMut<'_, LittleEndian, Elf64> =
        HashtabMut::create(&mut buf[0..], strtab, symtab,
                        symtab.num_syms()).unwrap();

    for sym in symtab.iter() {
        let expected: SymData<u32, u16, Elf64> = sym.try_into().unwrap();
        let named: SymData<Result<&'static str, &'static [u8]>, u16, Elf64> =
            expected.clone().with_strtab(strtab).unwrap();

        match named.name {
            Some(name) => {
                let lookup = hash.lookup(name);

                assert!(lookup.is_ok());

                let res = lookup.unwrap();

                assert!(res.is_some());

                let actual: SymData<u32, u16, Elf64> =
                    res.unwrap().try_into().unwrap();

                assert_eq!(actual, expected);
            },
            _ => {}
        }
    }
}
