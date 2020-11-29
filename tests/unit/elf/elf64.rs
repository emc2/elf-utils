use byteorder::LittleEndian;
use core::convert::TryFrom;
use core::convert::TryInto;
use core::marker::PhantomData;
use elf_utils::Elf;
use elf_utils::Elf64;
use elf_utils::ElfArch;
use elf_utils::ElfABI;
use elf_utils::ElfClass;
use elf_utils::ElfError;
use elf_utils::ElfHdrData;
use elf_utils::ElfHdrDataError;
use elf_utils::ElfKind;
use elf_utils::ElfMut;
use elf_utils::ElfMux;
use elf_utils::ElfTable;

const ELF64_EXEC_ELF_HDR: [u8; 64] = [
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x09,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x40, 0xb9, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x98, 0x7c, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
    0x0b, 0x00, 0x40, 0x00, 0x1f, 0x00, 0x1e, 0x00
];

const ELF64_REL_ELF_HDR: [u8; 64] = [
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x09,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x38, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x40, 0x00, 0x1a, 0x00, 0x18, 0x00
];

const ELF64_DYNAMIC_ELF_HDR: [u8; 64] = [
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x09,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
    0xd0, 0xd9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0xf4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
    0x0a, 0x00, 0x40, 0x00, 0x1f, 0x00, 0x1e, 0x00
];

const ELF64_EXEC_ELF_HDR_BAD_MAGIC0: [u8; 64] = [
    0x00, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x09,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x40, 0xb9, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x98, 0x7c, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
    0x0b, 0x00, 0x40, 0x00, 0x1f, 0x00, 0x1e, 0x00
];

const ELF64_EXEC_ELF_HDR_BAD_MAGIC1: [u8; 64] = [
    0x7f, 0x00, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x09,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x40, 0xb9, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x98, 0x7c, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
    0x0b, 0x00, 0x40, 0x00, 0x1f, 0x00, 0x1e, 0x00
];

const ELF64_EXEC_ELF_HDR_BAD_MAGIC2: [u8; 64] = [
    0x7f, 0x45, 0x00, 0x46, 0x02, 0x01, 0x01, 0x09,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x40, 0xb9, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x98, 0x7c, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
    0x0b, 0x00, 0x40, 0x00, 0x1f, 0x00, 0x1e, 0x00
];

const ELF64_EXEC_ELF_HDR_BAD_MAGIC3: [u8; 64] = [
    0x7f, 0x45, 0x4c, 0x00, 0x02, 0x01, 0x01, 0x09,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x40, 0xb9, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x98, 0x7c, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
    0x0b, 0x00, 0x40, 0x00, 0x1f, 0x00, 0x1e, 0x00
];

const ELF64_EXEC_ELF_HDR_BAD_VERSION: [u8; 64] = [
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x05, 0x09,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x40, 0xb9, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x98, 0x7c, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
    0x0b, 0x00, 0x40, 0x00, 0x1f, 0x00, 0x1e, 0x00
];

const ELF64_EXEC_ELF_HDR_BAD_ENDIANNESS: [u8; 64] = [
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x05, 0x01, 0x09,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x40, 0xb9, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x98, 0x7c, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
    0x0b, 0x00, 0x40, 0x00, 0x1f, 0x00, 0x1e, 0x00
];

const ELF64_EXEC_ELF_HDR_BAD_CLASS: [u8; 64] = [
    0x7f, 0x45, 0x4c, 0x46, 0x05, 0x01, 0x01, 0x09,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x40, 0xb9, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x98, 0x7c, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
    0x0b, 0x00, 0x40, 0x00, 0x1f, 0x00, 0x1e, 0x00
];

const ELF64_EXEC_HEADER_DATA: ElfHdrData<LittleEndian, Elf64,
                                         ElfTable<Elf64>,
                                         ElfTable<Elf64>, u16> =
    ElfHdrData {
        byteorder: PhantomData, abi: ElfABI::FreeBSD, abi_version: 0,
        kind: ElfKind::Executable, arch: ElfArch::X86_64,
        entry: 0x20b940, flags: 0, section_hdr_strtab: 30,
        prog_hdrs: Some(ElfTable { offset: 64, num_ents: 11 }),
        section_hdrs: ElfTable { offset: 162968, num_ents: 31 }
};

const ELF64_DYNAMIC_HEADER_DATA: ElfHdrData<LittleEndian, Elf64,
                                            ElfTable<Elf64>,
                                            ElfTable<Elf64>, u16> =
    ElfHdrData {
        byteorder: PhantomData, abi: ElfABI::FreeBSD, abi_version: 0,
        kind: ElfKind::Dynamic, arch: ElfArch::X86_64,
        entry: 0xd9d0, flags: 0, section_hdr_strtab: 30,
        prog_hdrs: Some(ElfTable { offset: 64, num_ents: 10 }),
        section_hdrs: ElfTable { offset: 128016, num_ents: 31 }
};

const ELF64_REL_HEADER_DATA: ElfHdrData<LittleEndian, Elf64,
                                        ElfTable<Elf64>,
                                        ElfTable<Elf64>, u16> =
    ElfHdrData {
        byteorder: PhantomData, abi: ElfABI::FreeBSD, abi_version: 0,
        kind: ElfKind::Relocatable, arch: ElfArch::X86_64,
        entry: 0, flags: 0, section_hdr_strtab: 24, prog_hdrs: None,
        section_hdrs: ElfTable { offset: 12088, num_ents: 26 }
};

#[test]
fn test_Elf_from_exec_hdr() {
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(&ELF64_EXEC_ELF_HDR[0..]);

    assert!(elf.is_ok());
}

#[test]
fn test_Elf_from_rel_hdr() {
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(&ELF64_REL_ELF_HDR[0..]);

    assert!(elf.is_ok());
}

#[test]
fn test_Elf_from_dynamic_hdr() {
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(&ELF64_DYNAMIC_ELF_HDR[0..]);

    assert!(elf.is_ok());
}

#[test]
fn test_ElfMux_from_exec_hdr() {
    let mut buf: [u8; 164952] = [0; 164952];

    &mut buf[0..64].copy_from_slice(&ELF64_EXEC_ELF_HDR[0..]);

    let elf = ElfMux::try_from(&buf[0..]).expect("Expected success");

    let hdr = match elf {
        ElfMux::Elf64LE(hdr) => hdr,
        ElfMux::Elf64BE(_) => panic!("Expected little-endian"),
        ElfMux::Elf32LE(_) => panic!("Expected 64-bit"),
        ElfMux::Elf32BE(_) => panic!("Expected 64-bit little-endian")
    };

    let hdr: ElfHdrData<LittleEndian, Elf64, ElfTable<Elf64>,
                        ElfTable<Elf64>, u16> =
        hdr.try_into().expect("expected success");

    assert_eq!(hdr, ELF64_EXEC_HEADER_DATA);
}

#[test]
fn test_ElfMux_from_rel_hdr() {
    let mut buf: [u8; 13752] = [0; 13752];

    &mut buf[0..64].copy_from_slice(&ELF64_REL_ELF_HDR[0..]);

    let elf = ElfMux::try_from(&buf[0..]).expect("Expected success");

    let hdr = match elf {
        ElfMux::Elf64LE(hdr) => hdr,
        ElfMux::Elf64BE(_) => panic!("Expected little-endian"),
        ElfMux::Elf32LE(_) => panic!("Expected 64-bit"),
        ElfMux::Elf32BE(_) => panic!("Expected 64-bit little-endian")
    };

    let hdr: ElfHdrData<LittleEndian, Elf64, ElfTable<Elf64>,
                        ElfTable<Elf64>, u16> =
        hdr.try_into().expect("expected success");

    assert_eq!(hdr, ELF64_REL_HEADER_DATA);
}

#[test]
fn test_ElfMux_from_dynamic_hdr() {
    let mut buf: [u8; 130000] = [0; 130000];

    &mut buf[0..64].copy_from_slice(&ELF64_DYNAMIC_ELF_HDR[0..]);

    let elf = ElfMux::try_from(&buf[0..]).expect("Expected success");

    let hdr = match elf {
        ElfMux::Elf64LE(hdr) => hdr,
        ElfMux::Elf64BE(_) => panic!("Expected little-endian"),
        ElfMux::Elf32LE(_) => panic!("Expected 64-bit"),
        ElfMux::Elf32BE(_) => panic!("Expected 64-bit little-endian")
    };

    let hdr: ElfHdrData<LittleEndian, Elf64, ElfTable<Elf64>,
                        ElfTable<Elf64>, u16> =
        hdr.try_into().expect("expected success");

    assert_eq!(hdr, ELF64_DYNAMIC_HEADER_DATA);
}

#[test]
fn test_ElfHdr_create_rel_just_right() {
    let mut buf: [u8; 64] = [0; 64];

    let res = Elf::create_split(&mut buf[0..], ELF64_REL_HEADER_DATA);

    assert!(res.is_ok());

    let (elf, rest) = res.unwrap();

    assert_eq!(rest.len(), 0);
}

#[test]
fn test_ElfHdr_create_rel_too_big() {
    let mut buf: [u8; 65] = [0; 65];

    let res = Elf::create_split(&mut buf[0..], ELF64_REL_HEADER_DATA);

    assert!(res.is_ok());

    let (elf, rest) = res.unwrap();

    assert_eq!(rest.len(), 1);
}

#[test]
fn test_ElfHdr_create_rel_too_small() {
    let mut buf: [u8; 63] = [0; 63];

    let res = Elf::create_split(&mut buf[0..], ELF64_REL_HEADER_DATA);

    assert!(res.is_err());
}

#[test]
fn test_ElfMux_create_exec_hdr() {
    let mut buf: [u8; 64] = [0; 64];

    let res = Elf::create_split(&mut buf[0..], ELF64_EXEC_HEADER_DATA);

    assert!(res.is_ok());

    let (elf, _) = res.unwrap();

    let hdr: ElfHdrData<LittleEndian, Elf64, ElfTable<Elf64>,
                        ElfTable<Elf64>, u16> =
        elf.try_into().expect("expected success");

    assert_eq!(hdr, ELF64_EXEC_HEADER_DATA);
}

#[test]
fn test_ElfMux_create_rel_hdr() {
    let mut buf: [u8; 64] = [0; 64];

    let res = Elf::create_split(&mut buf[0..], ELF64_REL_HEADER_DATA);

    assert!(res.is_ok());

    let (elf, _) = res.unwrap();

    let hdr: ElfHdrData<LittleEndian, Elf64, ElfTable<Elf64>,
                        ElfTable<Elf64>, u16> =
        elf.try_into().expect("expected success");

    assert_eq!(hdr, ELF64_REL_HEADER_DATA);
}

#[test]
fn test_ElfMux_create_dynamic_hdr() {
    let mut buf: [u8; 64] = [0; 64];

    let res = Elf::create_split(&mut buf[0..], ELF64_DYNAMIC_HEADER_DATA);

    assert!(res.is_ok());

    let (elf, _) = res.unwrap();

    let hdr: ElfHdrData<LittleEndian, Elf64, ElfTable<Elf64>,
                        ElfTable<Elf64>, u16> =
        elf.try_into().expect("expected success");

    assert_eq!(hdr, ELF64_DYNAMIC_HEADER_DATA);
}

#[test]
fn test_Elf_from_hdr_39_bytes() {
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(&ELF64_EXEC_ELF_HDR[0 .. ELF64_EXEC_ELF_HDR.len() - 1]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::TooShort));
}

#[test]
fn test_Elf_from_hdr_no_ehsize() {
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(&ELF64_EXEC_ELF_HDR[0 .. 51]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::TooShort));
}

#[test]
fn test_Elf_from_hdr_15_bytes() {
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(&ELF64_EXEC_ELF_HDR[0 .. 15]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::TooShort));
}

#[test]
fn test_Elf_from_hdr_5_bytes() {
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(&ELF64_EXEC_ELF_HDR[0 .. 5]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::TooShort));
}

#[test]
fn test_Elf_from_hdr_bad_magic0() {
    let slice = &ELF64_EXEC_ELF_HDR_BAD_MAGIC0[0..];
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(slice);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadMagic));
}

#[test]
fn test_Elf_from_hdr_bad_magic1() {
    let slice = &ELF64_EXEC_ELF_HDR_BAD_MAGIC1[0..];
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(slice);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadMagic));
}

#[test]
fn test_Elf_from_hdr_bad_magic2() {
    let slice = &ELF64_EXEC_ELF_HDR_BAD_MAGIC2[0..];
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(slice);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadMagic));
}

#[test]
fn test_Elf_from_hdr_bad_magic3() {
    let slice = &ELF64_EXEC_ELF_HDR_BAD_MAGIC3[0..];
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(slice);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadMagic));
}

#[test]
fn test_Elf_from_hdr_bad_version() {
    let slice = &ELF64_EXEC_ELF_HDR_BAD_VERSION[0..];
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(slice);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadVersion(0x05)));
}

#[test]
fn test_Elf_from_hdr_bad_endianness() {
    let slice = &ELF64_EXEC_ELF_HDR_BAD_ENDIANNESS[0..];
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(slice);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadEndian(0x05)));
}

#[test]
fn test_Elf_from_hdr_bad_class() {
    let slice = &ELF64_EXEC_ELF_HDR_BAD_CLASS[0..];
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(slice);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadClass(0x05)));
}

#[test]
fn test_Elf_from_exec_hdr_mut() {
    let mut buf = ELF64_EXEC_ELF_HDR.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(&mut buf[0..]);

    assert!(elf.is_ok());
}

#[test]
fn test_Elf_from_rel_hdr_mut() {
    let mut buf = ELF64_REL_ELF_HDR.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(&mut buf[0..]);

    assert!(elf.is_ok());
}

#[test]
fn test_Elf_from_dynamic_hdr_mut() {
    let mut buf = ELF64_DYNAMIC_ELF_HDR.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(&mut buf[0..]);

    assert!(elf.is_ok());
}

#[test]
fn test_Elf_from_hdr_39_bytes_mut() {
    let mut buf = ELF64_EXEC_ELF_HDR.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(&mut buf[0 .. ELF64_EXEC_ELF_HDR.len() - 1]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::TooShort));
}

#[test]
fn test_Elf_from_hdr_no_ehsize_mut() {
    let mut buf = ELF64_EXEC_ELF_HDR.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(&mut buf[0 .. 51]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::TooShort));
}

#[test]
fn test_Elf_from_hdr_15_bytes_mut() {
    let mut buf = ELF64_EXEC_ELF_HDR.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(&mut buf[0 .. 15]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::TooShort));
}

#[test]
fn test_Elf_from_hdr_5_bytes_mut() {
    let mut buf = ELF64_EXEC_ELF_HDR.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(&mut buf[0 .. 5]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::TooShort));
}

#[test]
fn test_Elf_from_hdr_bad_magic0_mut() {
    let mut buf = ELF64_EXEC_ELF_HDR_BAD_MAGIC0.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadMagic));
}

#[test]
fn test_Elf_from_hdr_bad_magic1_mut() {
    let mut buf = ELF64_EXEC_ELF_HDR_BAD_MAGIC1.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadMagic));
}

#[test]
fn test_Elf_from_hdr_bad_magic2_mut() {
    let mut buf = ELF64_EXEC_ELF_HDR_BAD_MAGIC2.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadMagic));
}

#[test]
fn test_Elf_from_hdr_bad_magic3_mut() {
    let mut buf = ELF64_EXEC_ELF_HDR_BAD_MAGIC3.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadMagic));
}

#[test]
fn test_Elf_from_hdr_bad_version_mut() {
    let mut buf = ELF64_EXEC_ELF_HDR_BAD_VERSION.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadVersion(0x05)));
}

#[test]
fn test_Elf_from_hdr_bad_endianness_mut() {
    let mut buf = ELF64_EXEC_ELF_HDR_BAD_ENDIANNESS.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadEndian(0x05)));
}

#[test]
fn test_Elf_from_hdr_bad_class_mut() {
    let mut buf = ELF64_EXEC_ELF_HDR_BAD_CLASS.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf64>, ElfError> =
        Elf::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadClass(0x05)));
}

#[test]
fn test_ElfMut_from_exec_hdr() {
    let mut buf = ELF64_EXEC_ELF_HDR.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf64>, ElfError> =
        ElfMut::try_from(&mut buf[0..]);

    assert!(elf.is_ok());
}

#[test]
fn test_ElfMut_from_rel_hdr() {
    let mut buf = ELF64_REL_ELF_HDR.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf64>, ElfError> =
        ElfMut::try_from(&mut buf[0..]);

    assert!(elf.is_ok());
}

#[test]
fn test_ElfMut_from_dynamic_hdr() {
    let mut buf = ELF64_DYNAMIC_ELF_HDR.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf64>, ElfError> =
        ElfMut::try_from(&mut buf[0..]);

    assert!(elf.is_ok());
}

#[test]
fn test_ElfMux_from_exec_hdr_mut() {
    let mut buf: [u8; 164952] = [0; 164952];

    &mut buf[0..64].copy_from_slice(&ELF64_EXEC_ELF_HDR[0..]);

    let elf = ElfMux::try_from(&buf[0..]).expect("Expected success");

    let hdr = match elf {
        ElfMux::Elf64LE(hdr) => hdr,
        ElfMux::Elf64BE(_) => panic!("Expected little-endian"),
        ElfMux::Elf32LE(_) => panic!("Expected 64-bit"),
        ElfMux::Elf32BE(_) => panic!("Expected 64-bit little-endian")
    };

    let ElfHdrData { abi, abi_version, kind, arch, entry, flags, .. } =
        hdr.try_into().expect("expected success");

    assert_eq!(abi, ElfABI::FreeBSD);
    assert_eq!(abi_version, 0);
    assert_eq!(kind, ElfKind::Executable);
    assert_eq!(arch, ElfArch::X86_64);
    assert_eq!(entry, 0x20b940);
    assert_eq!(flags, 0);
}

#[test]
fn test_ElfMux_from_rel_hdr_mut() {
    let mut buf: [u8; 13752] = [0; 13752];

    &mut buf[0..64].copy_from_slice(&ELF64_REL_ELF_HDR[0..]);

    let elf = ElfMux::try_from(&buf[0..]).expect("Expected success");

    let hdr = match elf {
        ElfMux::Elf64LE(hdr) => hdr,
        ElfMux::Elf64BE(_) => panic!("Expected little-endian"),
        ElfMux::Elf32LE(_) => panic!("Expected 64-bit"),
        ElfMux::Elf32BE(_) => panic!("Expected 64-bit little-endian")
    };

    let ElfHdrData { abi, abi_version, kind, arch, entry, flags, .. } =
        hdr.try_into().expect("expected success");

    assert_eq!(abi, ElfABI::FreeBSD);
    assert_eq!(abi_version, 0);
    assert_eq!(kind, ElfKind::Relocatable);
    assert_eq!(arch, ElfArch::X86_64);
    assert_eq!(entry, 0);
    assert_eq!(flags, 0);
}

#[test]
fn test_ElfMux_from_dynamic_hdr_mut() {
    let mut buf: [u8; 130000] = [0; 130000];

    &mut buf[0..64].copy_from_slice(&ELF64_DYNAMIC_ELF_HDR[0..]);

    let elf = ElfMux::try_from(&buf[0..]).expect("Expected success");

    let hdr = match elf {
        ElfMux::Elf64LE(hdr) => hdr,
        ElfMux::Elf64BE(_) => panic!("Expected little-endian"),
        ElfMux::Elf32LE(_) => panic!("Expected 64-bit"),
        ElfMux::Elf32BE(_) => panic!("Expected 64-bit little-endian")
    };

    let ElfHdrData { abi, abi_version, kind, arch, entry, flags, .. } =
        hdr.try_into().expect("expected success");

    assert_eq!(abi, ElfABI::FreeBSD);
    assert_eq!(abi_version, 0);
    assert_eq!(kind, ElfKind::Dynamic);
    assert_eq!(arch, ElfArch::X86_64);
    assert_eq!(entry, 0xd9d0);
    assert_eq!(flags, 0);
}
/*
#[test]
fn test_ElfHdr_from_exec_ElfHdrMut() {
    let mut buf = ELF64_EXEC_ELF_HDR.clone();
    let elf = ElfMut::try_from(&mut buf[0..])
        .expect("Expected success");
    let res = elf.try_into();

    assert!(res.is_ok());

    let hdr: ElfHdrData<LittleEndian, Elf64, (), ()> =
        match res.expect("Expected success") {
            ElfHdr::Elf64LE(hdr) => {
                let hdr_mut: ElfHdrMut<'_, LittleEndian, u64, (), ()> =
                    hdr.into();

                hdr_mut.into()
            },
            ElfHdr::Elf64BE(_) => panic!("Expected little-endian"),
            ElfHdr::Elf32LE(_) => panic!("Expected 64-bit"),
            ElfHdr::Elf32BE(_) => panic!("Expected 64-bit little-endian")
        };

    let ElfHdrData { abi, abi_version, kind, arch, entry, flags, .. } = hdr;

    assert_eq!(abi, ElfABI::FreeBSD);
    assert_eq!(abi_version, 0);
    assert_eq!(kind, ElfKind::Executable);
    assert_eq!(arch, ElfArch::X86_64);
    assert_eq!(entry, 0x20b940);
    assert_eq!(flags, 0);
}

#[test]
fn test_ElfHdr_from_rel_hdr_ElfHdrMut() {
    let mut buf = ELF64_REL_ELF_HDR.clone();
    let elf = ElfMut::try_from(&mut buf[0..])
        .expect("Expected success");
    let res = elf.try_into();

    assert!(res.is_ok());

    let hdr: ElfHdrData<LittleEndian, Elf64, (), ()> =
        match res.expect("Expected success") {
            ElfHdr::Elf64LE(hdr) => hdr,
            ElfHdr::Elf64BE(_) => panic!("Expected little-endian"),
            ElfHdr::Elf32LE(_) => panic!("Expected 64-bit"),
            ElfHdr::Elf32BE(_) => panic!("Expected 64-bit little-endian")
        };

    let ElfHdrData { abi, abi_version, kind, arch, entry, flags, .. } = hdr;

    assert_eq!(abi, ElfABI::FreeBSD);
    assert_eq!(abi_version, 0);
    assert_eq!(kind, ElfKind::Relocatable);
    assert_eq!(arch, ElfArch::X86_64);
    assert_eq!(entry, 0);
    assert_eq!(flags, 0);
}

#[test]
fn test_ElfHdr_from_dynamic_hdr_ElfHdrMut() {
    let mut buf = ELF64_DYNAMIC_ELF_HDR.clone();
    let elf = ElfMut::try_from(&mut buf[0..])
        .expect("Expected success");
    let res = elf.try_into();

    assert!(res.is_ok());

    let hdr: ElfHdrData<LittleEndian, Elf64, (), ()> =
        match res.expect("Expected success") {
            ElfHdr::Elf64LE(hdr) => hdr,
            ElfHdr::Elf64BE(_) => panic!("Expected little-endian"),
            ElfHdr::Elf32LE(_) => panic!("Expected 64-bit"),
            ElfHdr::Elf32BE(_) => panic!("Expected 64-bit little-endian")
        };

    let ElfHdrData { abi, abi_version, kind, arch, entry, flags, .. } = hdr;

    assert_eq!(abi, ElfABI::FreeBSD);
    assert_eq!(abi_version, 0);
    assert_eq!(kind, ElfKind::Dynamic);
    assert_eq!(arch, ElfArch::X86_64);
    assert_eq!(entry, 0xd9d0);
    assert_eq!(flags, 0);
}
*/
#[test]
fn test_ElfMut_from_hdr_39_bytes() {
    let mut buf = ELF64_EXEC_ELF_HDR.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf64>, ElfError> =
        ElfMut::try_from(&mut buf[0 .. ELF64_EXEC_ELF_HDR.len() - 1]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::TooShort));
}

#[test]
fn test_ElfMut_from_hdr_no_ehsize() {
    let mut buf = ELF64_EXEC_ELF_HDR.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf64>, ElfError> =
        ElfMut::try_from(&mut buf[0 .. 51]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::TooShort));
}

#[test]
fn test_ElfMut_from_hdr_15_bytes() {
    let mut buf = ELF64_EXEC_ELF_HDR.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf64>, ElfError> =
        ElfMut::try_from(&mut buf[0 .. 15]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::TooShort));
}

#[test]
fn test_ElfMut_from_hdr_5_bytes() {
    let mut buf = ELF64_EXEC_ELF_HDR.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf64>, ElfError> =
        ElfMut::try_from(&mut buf[0 .. 5]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::TooShort));
}

#[test]
fn test_ElfMut_from_hdr_bad_magic0() {
    let mut buf = ELF64_EXEC_ELF_HDR_BAD_MAGIC0.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf64>, ElfError> =
        ElfMut::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadMagic));
}

#[test]
fn test_ElfMut_from_hdr_bad_magic1() {
    let mut buf = ELF64_EXEC_ELF_HDR_BAD_MAGIC1.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf64>, ElfError> =
        ElfMut::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadMagic));
}

#[test]
fn test_ElfMut_from_hdr_bad_magic2() {
    let mut buf = ELF64_EXEC_ELF_HDR_BAD_MAGIC2.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf64>, ElfError> =
        ElfMut::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadMagic));
}

#[test]
fn test_ElfMut_from_hdr_bad_magic3() {
    let mut buf = ELF64_EXEC_ELF_HDR_BAD_MAGIC3.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf64>, ElfError> =
        ElfMut::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadMagic));
}

#[test]
fn test_ElfMut_from_hdr_bad_version() {
    let mut buf = ELF64_EXEC_ELF_HDR_BAD_VERSION.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf64>, ElfError> =
        ElfMut::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadVersion(0x05)));
}

#[test]
fn test_ElfMut_from_hdr_bad_endianness() {
    let mut buf = ELF64_EXEC_ELF_HDR_BAD_ENDIANNESS.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf64>, ElfError> =
        ElfMut::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadEndian(0x05)));
}

#[test]
fn test_ElfMut_from_hdr_bad_class() {
    let mut buf = ELF64_EXEC_ELF_HDR_BAD_CLASS.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf64>, ElfError> =
        ElfMut::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadClass(0x05)));
}
