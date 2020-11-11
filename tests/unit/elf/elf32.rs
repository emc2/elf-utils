use byteorder::LittleEndian;
use core::convert::TryFrom;
use core::convert::TryInto;
use core::marker::PhantomData;
use elf_utils::Elf;
use elf_utils::Elf32;
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

const ELF32_DYNAMIC_ELF_HDR: [u8; 52] = [
    0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x09,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x50, 0xb6, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
    0x5c, 0xd4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x34, 0x00, 0x20, 0x00, 0x0a, 0x00, 0x28, 0x00,
    0x1f, 0x00, 0x1e, 0x00,
];

const ELF32_REL_ELF_HDR: [u8; 52] = [
    0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x09,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00,
    0x1e, 0x00, 0x1b, 0x00
];

const ELF32_DYNAMIC_ELF_HDR_BAD_MAGIC0: [u8; 52] = [
    0x00, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x09,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x50, 0xb6, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
    0x5c, 0xd4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x34, 0x00, 0x20, 0x00, 0x0a, 0x00, 0x28, 0x00,
    0x1f, 0x00, 0x1e, 0x00,
];

const ELF32_DYNAMIC_ELF_HDR_BAD_MAGIC1: [u8; 52] = [
    0x7f, 0x00, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x09,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x50, 0xb6, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
    0x5c, 0xd4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x34, 0x00, 0x20, 0x00, 0x0a, 0x00, 0x28, 0x00,
    0x1f, 0x00, 0x1e, 0x00,
];

const ELF32_DYNAMIC_ELF_HDR_BAD_MAGIC2: [u8; 52] = [
    0x7f, 0x45, 0x00, 0x46, 0x01, 0x01, 0x01, 0x09,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x50, 0xb6, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
    0x5c, 0xd4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x34, 0x00, 0x20, 0x00, 0x0a, 0x00, 0x28, 0x00,
    0x1f, 0x00, 0x1e, 0x00,
];

const ELF32_DYNAMIC_ELF_HDR_BAD_MAGIC3: [u8; 52] = [
    0x7f, 0x45, 0x4c, 0x00, 0x01, 0x01, 0x01, 0x09,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x50, 0xb6, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
    0x5c, 0xd4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x34, 0x00, 0x20, 0x00, 0x0a, 0x00, 0x28, 0x00,
    0x1f, 0x00, 0x1e, 0x00,
];

const ELF32_DYNAMIC_ELF_HDR_BAD_VERSION: [u8; 52] = [
    0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x05, 0x09,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x50, 0xb6, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
    0x5c, 0xd4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x34, 0x00, 0x20, 0x00, 0x0a, 0x00, 0x28, 0x00,
    0x1f, 0x00, 0x1e, 0x00,
];

const ELF32_DYNAMIC_ELF_HDR_BAD_ENDIANNESS: [u8; 52] = [
    0x7f, 0x45, 0x4c, 0x46, 0x01, 0x05, 0x01, 0x09,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x50, 0xb6, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
    0x5c, 0xd4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x34, 0x00, 0x20, 0x00, 0x0a, 0x00, 0x28, 0x00,
    0x1f, 0x00, 0x1e, 0x00,
];

const ELF32_DYNAMIC_ELF_HDR_BAD_CLASS: [u8; 52] = [
    0x7f, 0x45, 0x4c, 0x46, 0x05, 0x01, 0x01, 0x09,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x50, 0xb6, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
    0x5c, 0xd4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x34, 0x00, 0x20, 0x00, 0x0a, 0x00, 0x28, 0x00,
    0x1f, 0x00, 0x1e, 0x00,
];

const ELF32_DYNAMIC_HEADER_DATA: ElfHdrData<LittleEndian, Elf32,
                                            ElfTable<Elf32>,
                                            ElfTable<Elf32>, u16> =
    ElfHdrData {
        byteorder: PhantomData, abi: ElfABI::FreeBSD, abi_version: 0,
        kind: ElfKind::Dynamic, arch: ElfArch::I386,
        entry: 0xb650, flags: 0, section_hdr_strtab: 30,
        prog_hdrs: Some(ElfTable { offset: 52, num_ents: 10 }),
        section_hdrs: ElfTable { offset: 119900, num_ents: 31 }
};

const ELF32_REL_HEADER_DATA: ElfHdrData<LittleEndian, Elf32,
                                        ElfTable<Elf32>,
                                        ElfTable<Elf32>, u16> =
    ElfHdrData {
        byteorder: PhantomData, abi: ElfABI::FreeBSD, abi_version: 0,
        kind: ElfKind::Relocatable, arch: ElfArch::I386,
        entry: 0, flags: 0, section_hdr_strtab: 27, prog_hdrs: None,
        section_hdrs: ElfTable { offset: 9736, num_ents: 30 }
};

#[test]
fn test_Elf_from_rel_hdr() {
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
        Elf::try_from(&ELF32_REL_ELF_HDR[0..]);

    assert!(elf.is_ok());
}

#[test]
fn test_Elf_from_dynamic_hdr() {
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
         Elf::try_from(&ELF32_DYNAMIC_ELF_HDR[0..]);

    assert!(elf.is_ok());
}

#[test]
fn test_ElfHdr_from_rel_hdr() {
    let elf = ElfMux::try_from(&ELF32_REL_ELF_HDR[0..][0..])
        .expect("Expected success");

    let hdr = match elf {
        ElfMux::Elf64LE(_) => panic!("Expected 32-bit"),
        ElfMux::Elf64BE(_) => panic!("Expected 32-bit little-endian"),
        ElfMux::Elf32LE(hdr) => hdr,
        ElfMux::Elf32BE(_) => panic!("Expected little-endian")
    };

    let hdr: ElfHdrData<LittleEndian, Elf32, ElfTable<Elf32>,
                        ElfTable<Elf32>, u16> =
        hdr.try_into().expect("expected success");

    assert_eq!(hdr, ELF32_REL_HEADER_DATA);
}

#[test]
fn test_ElfHdr_from_dynamic_hdr() {
    let elf = ElfMux::try_from(&ELF32_DYNAMIC_ELF_HDR[0..])
        .expect("Expected success");

    let hdr = match elf {
        ElfMux::Elf64LE(_) => panic!("Expected 32-bit"),
        ElfMux::Elf64BE(_) => panic!("Expected 32-bit little-endian"),
        ElfMux::Elf32LE(hdr) => hdr,
        ElfMux::Elf32BE(_) => panic!("Expected little-endian")
    };

    let hdr: ElfHdrData<LittleEndian, Elf32, ElfTable<Elf32>,
                        ElfTable<Elf32>, u16> =
        hdr.try_into().expect("expected success");

    assert_eq!(hdr, ELF32_DYNAMIC_HEADER_DATA);
}

#[test]
fn test_ElfHdr_create_rel_just_right() {
    let mut buf: [u8; 52] = [0; 52];

    let res = Elf::create_split(&mut buf[0..], ELF32_REL_HEADER_DATA);

    assert!(res.is_ok());

    let (elf, rest) = res.unwrap();

    assert_eq!(rest.len(), 0);
}

#[test]
fn test_ElfHdr_create_rel_too_big() {
    let mut buf: [u8; 53] = [0; 53];

    let res = Elf::create_split(&mut buf[0..], ELF32_REL_HEADER_DATA);

    assert!(res.is_ok());

    let (elf, rest) = res.unwrap();

    assert_eq!(rest.len(), 1);
}

#[test]
fn test_ElfHdr_create_rel_too_small() {
    let mut buf: [u8; 51] = [0; 51];

    let res = Elf::create_split(&mut buf[0..], ELF32_REL_HEADER_DATA);

    assert!(res.is_err());
}

#[test]
fn test_ElfHdr_create_rel_hdr() {
    let mut buf: [u8; 52] = [0; 52];

    let res = Elf::create_split(&mut buf[0..], ELF32_REL_HEADER_DATA);

    assert!(res.is_ok());

    let (elf, _) = res.unwrap();

    let hdr: ElfHdrData<LittleEndian, Elf32, ElfTable<Elf32>,
                        ElfTable<Elf32>, u16> =
        elf.try_into().expect("expected success");

    assert_eq!(hdr, ELF32_REL_HEADER_DATA);
}

#[test]
fn test_ElfHdr_create_dynamic_hdr() {
    let mut buf: [u8; 52] = [0; 52];

    let res = Elf::create_split(&mut buf[0..], ELF32_DYNAMIC_HEADER_DATA);

    assert!(res.is_ok());

    let (elf, _) = res.unwrap();

    let hdr: ElfHdrData<LittleEndian, Elf32, ElfTable<Elf32>,
                        ElfTable<Elf32>, u16> =
        elf.try_into().expect("expected success");

    assert_eq!(hdr, ELF32_DYNAMIC_HEADER_DATA);
}

#[test]
fn test_Elf_from_hdr_33_bytes() {
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
        Elf::try_from(&ELF32_DYNAMIC_ELF_HDR[0 ..
                                             ELF32_DYNAMIC_ELF_HDR.len() - 1]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::TooShort));
}

#[test]
fn test_Elf_from_hdr_no_ehsize() {
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
        Elf::try_from(&ELF32_DYNAMIC_ELF_HDR[0 .. 39]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::TooShort));
}

#[test]
fn test_Elf_from_hdr_15_bytes() {
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
        Elf::try_from(&ELF32_DYNAMIC_ELF_HDR[0 .. 15]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::TooShort));
}

#[test]
fn test_Elf_from_hdr_5_bytes() {
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
        Elf::try_from(&ELF32_DYNAMIC_ELF_HDR[0 .. 5]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::TooShort));
}

#[test]
fn test_Elf_from_hdr_bad_magic0() {
    let slice = &ELF32_DYNAMIC_ELF_HDR_BAD_MAGIC0[0..];
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
        Elf::try_from(slice);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadMagic));
}

#[test]
fn test_Elf_from_hdr_bad_magic1() {
    let slice = &ELF32_DYNAMIC_ELF_HDR_BAD_MAGIC1[0..];
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
        Elf::try_from(slice);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadMagic));
}

#[test]
fn test_Elf_from_hdr_bad_magic2() {
    let slice = &ELF32_DYNAMIC_ELF_HDR_BAD_MAGIC2[0..];
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
        Elf::try_from(slice);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadMagic));
}

#[test]
fn test_Elf_from_hdr_bad_magic3() {
    let slice = &ELF32_DYNAMIC_ELF_HDR_BAD_MAGIC3[0..];
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
        Elf::try_from(slice);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadMagic));
}

#[test]
fn test_Elf_from_hdr_bad_version() {
    let slice = &ELF32_DYNAMIC_ELF_HDR_BAD_VERSION[0..];
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
        Elf::try_from(slice);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadVersion(0x05)));
}

#[test]
fn test_Elf_from_hdr_bad_endianness() {
    let slice = &ELF32_DYNAMIC_ELF_HDR_BAD_ENDIANNESS[0..];
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
        Elf::try_from(slice);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadEndian(0x05)));
}

#[test]
fn test_Elf_from_hdr_bad_class() {
    let slice = &ELF32_DYNAMIC_ELF_HDR_BAD_CLASS[0..];
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
        Elf::try_from(slice);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadClass(0x05)));
}

#[test]
fn test_Elf_from_rel_hdr_mut() {
    let mut buf = ELF32_REL_ELF_HDR.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
        Elf::try_from(&mut buf[0..]);

    assert!(elf.is_ok());
}

#[test]
fn test_Elf_from_dynamic_hdr_mut() {
    let mut buf = ELF32_DYNAMIC_ELF_HDR.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
        Elf::try_from(&mut buf[0..]);

    assert!(elf.is_ok());
}

#[test]
fn test_Elf_from_hdr_33_bytes_mut() {
    let mut buf = ELF32_DYNAMIC_ELF_HDR.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
        Elf::try_from(&mut buf[0 .. ELF32_DYNAMIC_ELF_HDR.len() - 1]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::TooShort));
}

#[test]
fn test_Elf_from_hdr_no_ehsize_mut() {
    let mut buf = ELF32_DYNAMIC_ELF_HDR.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
        Elf::try_from(&mut buf[0 .. 39]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::TooShort));
}

#[test]
fn test_Elf_from_hdr_15_bytes_mut() {
    let mut buf = ELF32_DYNAMIC_ELF_HDR.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
        Elf::try_from(&mut buf[0 .. 15]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::TooShort));
}

#[test]
fn test_Elf_from_hdr_5_bytes_mut() {
    let mut buf = ELF32_DYNAMIC_ELF_HDR.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
        Elf::try_from(&mut buf[0 .. 5]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::TooShort));
}

#[test]
fn test_Elf_from_hdr_bad_magic0_mut() {
    let mut buf = ELF32_DYNAMIC_ELF_HDR_BAD_MAGIC0.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
        Elf::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadMagic));
}

#[test]
fn test_Elf_from_hdr_bad_magic1_mut() {
    let mut buf = ELF32_DYNAMIC_ELF_HDR_BAD_MAGIC1.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
        Elf::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadMagic));
}

#[test]
fn test_Elf_from_hdr_bad_magic2_mut() {
    let mut buf = ELF32_DYNAMIC_ELF_HDR_BAD_MAGIC2.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
        Elf::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadMagic));
}

#[test]
fn test_Elf_from_hdr_bad_magic3_mut() {
    let mut buf = ELF32_DYNAMIC_ELF_HDR_BAD_MAGIC3.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
        Elf::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadMagic));
}

#[test]
fn test_Elf_from_hdr_bad_version_mut() {
    let mut buf = ELF32_DYNAMIC_ELF_HDR_BAD_VERSION.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
        Elf::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadVersion(0x05)));
}

#[test]
fn test_Elf_from_hdr_bad_endianness_mut() {
    let mut buf = ELF32_DYNAMIC_ELF_HDR_BAD_ENDIANNESS.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
        Elf::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadEndian(0x05)));
}

#[test]
fn test_Elf_from_hdr_bad_class_mut() {
    let mut buf = ELF32_DYNAMIC_ELF_HDR_BAD_CLASS.clone();
    let elf: Result<Elf<'_, LittleEndian, Elf32>, ElfError> =
        Elf::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadClass(0x05)));
}

#[test]
fn test_ElfMut_from_rel_hdr() {
    let mut buf = ELF32_REL_ELF_HDR.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf32>, ElfError> =
        ElfMut::try_from(&mut buf[0..]);

    assert!(elf.is_ok());
}

#[test]
fn test_ElfMut_from_dynamic_hdr() {
    let mut buf = ELF32_DYNAMIC_ELF_HDR.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf32>, ElfError> =
        ElfMut::try_from(&mut buf[0..]);

    assert!(elf.is_ok());
}

#[test]
fn test_ElfMut_from_hdr_33_bytes() {
    let mut buf = ELF32_DYNAMIC_ELF_HDR.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf32>, ElfError> =
        ElfMut::try_from(&mut buf[0 .. ELF32_DYNAMIC_ELF_HDR.len() - 1]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::TooShort));
}

#[test]
fn test_ElfMut_from_hdr_no_ehsize() {
    let mut buf = ELF32_DYNAMIC_ELF_HDR.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf32>, ElfError> =
        ElfMut::try_from(&mut buf[0 .. 39]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::TooShort));
}

#[test]
fn test_ElfMut_from_hdr_15_bytes() {
    let mut buf = ELF32_DYNAMIC_ELF_HDR.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf32>, ElfError> =
        ElfMut::try_from(&mut buf[0 .. 15]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::TooShort));
}

#[test]
fn test_ElfMut_from_hdr_5_bytes() {
    let mut buf = ELF32_DYNAMIC_ELF_HDR.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf32>, ElfError> =
        ElfMut::try_from(&mut buf[0 .. 5]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::TooShort));
}

#[test]
fn test_ElfMut_from_hdr_bad_magic0() {
    let mut buf = ELF32_DYNAMIC_ELF_HDR_BAD_MAGIC0.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf32>, ElfError> =
        ElfMut::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadMagic));
}

#[test]
fn test_ElfMut_from_hdr_bad_magic1() {
    let mut buf = ELF32_DYNAMIC_ELF_HDR_BAD_MAGIC1.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf32>, ElfError> =
        ElfMut::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadMagic));
}

#[test]
fn test_ElfMut_from_hdr_bad_magic2() {
    let mut buf = ELF32_DYNAMIC_ELF_HDR_BAD_MAGIC2.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf32>, ElfError> =
        ElfMut::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadMagic));
}

#[test]
fn test_ElfMut_from_hdr_bad_magic3() {
    let mut buf = ELF32_DYNAMIC_ELF_HDR_BAD_MAGIC3.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf32>, ElfError> =
        ElfMut::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadMagic));
}

#[test]
fn test_ElfMut_from_hdr_bad_version() {
    let mut buf = ELF32_DYNAMIC_ELF_HDR_BAD_VERSION.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf32>, ElfError> =
        ElfMut::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadVersion(0x05)));
}

#[test]
fn test_ElfMut_from_hdr_bad_endianness() {
    let mut buf = ELF32_DYNAMIC_ELF_HDR_BAD_ENDIANNESS.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf32>, ElfError> =
        ElfMut::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadEndian(0x05)));
}

#[test]
fn test_ElfMut_from_hdr_bad_class() {
    let mut buf = ELF32_DYNAMIC_ELF_HDR_BAD_CLASS.clone();
    let elf: Result<ElfMut<'_, LittleEndian, Elf32>, ElfError> =
        ElfMut::try_from(&mut buf[0..]);

    assert!(elf.is_err());
    assert_eq!(elf.err(), Some(ElfError::BadClass(0x05)));
}
