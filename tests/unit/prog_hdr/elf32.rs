use byteorder::LittleEndian;
use core::convert::TryFrom;
use core::convert::TryInto;
use elf_utils::Elf32;
use elf_utils::prog_hdr::ProgHdr;
use elf_utils::prog_hdr::ProgHdrData;
use elf_utils::prog_hdr::ProgHdrs;
use elf_utils::prog_hdr::Segment;

const ELF32_PROG_HDR_BYTES: usize = 320;

const ELF32_NUM_PROG_HDRS: usize = 10;

const ELF32_PROG_HDR: [u8; ELF32_PROG_HDR_BYTES] = [
    0x06, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
    0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
    0x40, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xbc, 0x46, 0x00, 0x00, 0xbc, 0x46, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0xc0, 0x46, 0x00, 0x00,
    0xc0, 0x56, 0x00, 0x00, 0xc0, 0x56, 0x00, 0x00,
    0x05, 0x4d, 0x01, 0x00, 0x05, 0x4d, 0x01, 0x00,
    0x05, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0xc8, 0x93, 0x01, 0x00,
    0xc8, 0xb3, 0x01, 0x00, 0xc8, 0xb3, 0x01, 0x00,
    0x48, 0x03, 0x00, 0x00, 0x48, 0x03, 0x00, 0x00,
    0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x10, 0x97, 0x01, 0x00,
    0x10, 0xc7, 0x01, 0x00, 0x10, 0xc7, 0x01, 0x00,
    0x64, 0x00, 0x00, 0x00, 0x68, 0x0b, 0x00, 0x00,
    0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x28, 0x96, 0x01, 0x00,
    0x28, 0xb6, 0x01, 0x00, 0x28, 0xb6, 0x01, 0x00,
    0x88, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x52, 0xe5, 0x74, 0x64, 0xc8, 0x93, 0x01, 0x00,
    0xc8, 0xb3, 0x01, 0x00, 0xc8, 0xb3, 0x01, 0x00,
    0x48, 0x03, 0x00, 0x00, 0x48, 0x03, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x50, 0xe5, 0x74, 0x64, 0x8c, 0x42, 0x00, 0x00,
    0x8c, 0x42, 0x00, 0x00, 0x8c, 0x42, 0x00, 0x00,
    0xbc, 0x00, 0x00, 0x00, 0xbc, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x51, 0xe5, 0x74, 0x64, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x74, 0x01, 0x00, 0x00,
    0x74, 0x01, 0x00, 0x00, 0x74, 0x01, 0x00, 0x00,
    0x18, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
];

const ELF32_PROG_HDR_CONTENTS_BARE: [ProgHdrData<Elf32, Segment<u32>,
                                                 Segment<u32>, Segment<u32>>;
                                     ELF32_NUM_PROG_HDRS] = [
    ProgHdrData::ProgHdr { virt_addr: 0x34, phys_addr: 0x34,
                           content: Segment { offset: 0x34, size: 0x140 } },
    ProgHdrData::Load { virt_addr: 0, phys_addr: 0,
                        mem_size: 0x46bc, align: 0x1000,
                        read: true, write: false, exec: false,
                        content: Segment { offset: 0, size: 0x46bc } },
    ProgHdrData::Load { virt_addr: 0x56c0, phys_addr: 0x56c0,
                        mem_size: 0x14d05, align: 0x1000,
                        read: true, write: false, exec: true,
                        content: Segment { offset: 0x46c0, size: 0x14d05 } },
    ProgHdrData::Load { virt_addr: 0x1b3c8, phys_addr: 0x1b3c8,
                        mem_size: 0x348, align: 4096,
                        read: true, write: true, exec: false,
                        content: Segment { offset: 0x193c8, size: 0x348 } },
    ProgHdrData::Load { virt_addr: 0x1c710, phys_addr: 0x1c710,
                        mem_size: 0xb68, align: 4096,
                        read: true, write: true, exec: false,
                        content: Segment { offset: 0x19710, size: 0x64 } },
    ProgHdrData::Dynamic { virt_addr: 0x1b628, phys_addr: 0x1b628,
                           content: Segment { offset: 0x19628, size: 0x88 } },
    ProgHdrData::Unknown { tag: 0x6474e552, flags: 4, offset: 0x193c8,
                           file_size: 0x348, mem_size: 0x348,
                           phys_addr: 0x1b3c8, virt_addr: 0x1b3c8, align: 1 },
    ProgHdrData::Unknown { tag: 0x6474e550, flags: 4, offset: 0x428c,
                           file_size: 0xbc, mem_size: 0xbc,
                           phys_addr: 0x428c, virt_addr: 0x428c, align: 4 },
    ProgHdrData::Unknown { tag: 0x6474e551, flags: 6, offset: 0,
                           file_size: 0, mem_size: 0,
                           phys_addr: 0, virt_addr: 0, align: 0 },
    ProgHdrData::Note { virt_addr: 0x174, phys_addr: 0x174,
                        content: Segment { offset: 0x174, size: 0x18 } },
];

#[test]
fn test_ProgHdrs_from_bytes_just_right() {
    let prog_hdr: Result<ProgHdrs<'_, LittleEndian, Elf32>, ()> =
        ProgHdrs::try_from(&ELF32_PROG_HDR[0..]);

    assert!(prog_hdr.is_ok());
}

#[test]
fn test_ProgHdrs_from_bytes_too_small() {
    let prog_hdr: Result<ProgHdrs<'_, LittleEndian, Elf32>, ()> =
        ProgHdrs::try_from(&ELF32_PROG_HDR[0 .. ELF32_PROG_HDR.len() - 1]);

    assert!(prog_hdr.is_err());
}

#[test]
fn test_ProgHdrs_from_bytes_num_hdrs() {
    let prog_hdr: ProgHdrs<'_, LittleEndian, Elf32> =
        ProgHdrs::try_from(&ELF32_PROG_HDR[0..])
        .expect("Expected success");

    assert_eq!(prog_hdr.num_hdrs(), ELF32_NUM_PROG_HDRS);
}

#[test]
fn test_ProgHdrs_from_bytes_iter_len() {
    let prog_hdr: ProgHdrs<'_, LittleEndian, Elf32> =
        ProgHdrs::try_from(&ELF32_PROG_HDR[0..])
        .expect("Expected success");
    let iter = prog_hdr.iter();

    assert_eq!(iter.len(), ELF32_NUM_PROG_HDRS);
}

#[test]
fn test_ProgHdrs_from_bytes_just_right_mut() {
    let mut buf = ELF32_PROG_HDR.clone();
    let prog_hdr: Result<ProgHdrs<'_, LittleEndian, Elf32>, ()> =
        ProgHdrs::try_from(&mut buf[0..]);

    assert!(prog_hdr.is_ok());
}

#[test]
fn test_ProgHdrs_from_bytes_too_small_mut() {
    let mut buf = ELF32_PROG_HDR.clone();
    let prog_hdr: Result<ProgHdrs<'_, LittleEndian, Elf32>, ()> =
        ProgHdrs::try_from(&mut buf[0 .. ELF32_PROG_HDR.len() - 1]);

    assert!(prog_hdr.is_err());
}

#[test]
fn test_ProgHdrs_from_bytes_num_hdrs_mut() {
    let mut buf = ELF32_PROG_HDR.clone();
    let prog_hdr: ProgHdrs<'_, LittleEndian, Elf32> =
        ProgHdrs::try_from(&mut buf[0..])
        .expect("Expected success");

    assert_eq!(prog_hdr.num_hdrs(), ELF32_NUM_PROG_HDRS);
}

#[test]
fn test_ProgHdrs_from_bytes_iter_len_mut() {
    let mut buf = ELF32_PROG_HDR.clone();
    let prog_hdr: ProgHdrs<'_, LittleEndian, Elf32> =
        ProgHdrs::try_from(&mut buf[0..])
        .expect("Expected success");
    let iter = prog_hdr.iter();

    assert_eq!(iter.len(), ELF32_NUM_PROG_HDRS);
}

#[test]
fn test_ProgHdrs_from_bytes_iter() {
    let prog_hdr: ProgHdrs<'_, LittleEndian, Elf32> =
        ProgHdrs::try_from(&ELF32_PROG_HDR[0..])
        .expect("Expected success");
    let mut iter = prog_hdr.iter();

    for expect in ELF32_PROG_HDR_CONTENTS_BARE.iter() {
        let ent = iter.next();

        assert!(ent.is_some());

        let data = ent.unwrap().try_into();

        assert!(data.is_ok());

        let actual = data.unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(iter.next().is_none());
}

#[test]
fn test_ProgHdrs_from_bytes_idx() {
    let prog_hdr: ProgHdrs<'_, LittleEndian, Elf32> =
        ProgHdrs::try_from(&ELF32_PROG_HDR[0..])
        .expect("Expected success");
    let mut iter = prog_hdr.iter();

    for i in 0 .. ELF32_PROG_HDR_CONTENTS_BARE.len() {
        let expect = &ELF32_PROG_HDR_CONTENTS_BARE[i];
        let ent = prog_hdr.idx(i);

        assert!(ent.is_some());

        let data = ent.unwrap().try_into();

        assert!(data.is_ok());

        let actual = data.unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(prog_hdr.idx(ELF32_PROG_HDR_CONTENTS_BARE.len()).is_none());
}

#[test]
fn test_ProgHdrs_create_just_right() {
    let mut buf = [0; ELF32_PROG_HDR_BYTES];
    let dynamic: Result<(ProgHdrs<'_, LittleEndian, Elf32>, &'_ mut [u8]), ()> =
        ProgHdrs::create_split(&mut buf[0..],
                               ELF32_PROG_HDR_CONTENTS_BARE.iter().map(|x| *x));

    assert!(dynamic.is_ok());

    let (dynamic, buf) = dynamic.expect("Expected success");

    assert_eq!(buf.len(), 0);
}

#[test]
fn test_ProgHdrs_create_too_big() {
    let mut buf = [0; ELF32_PROG_HDR_BYTES + 1];
    let dynamic: Result<(ProgHdrs<'_, LittleEndian, Elf32>, &'_ mut [u8]), ()> =
        ProgHdrs::create_split(&mut buf[0..],
                               ELF32_PROG_HDR_CONTENTS_BARE.iter().map(|x| *x));

    assert!(dynamic.is_ok());

    let (dynamic, buf) = dynamic.expect("Expected success");

    assert_eq!(buf.len(), 1);
}

#[test]
fn test_ProgHdrs_create_too_small() {
    let mut buf = [0; ELF32_PROG_HDR_BYTES - 1];
    let dynamic: Result<(ProgHdrs<'_, LittleEndian, Elf32>, &'_ mut [u8]), ()> =
        ProgHdrs::create_split(&mut buf[0..],
                               ELF32_PROG_HDR_CONTENTS_BARE.iter().map(|x| *x));

    assert!(dynamic.is_err());
}


#[test]
fn test_ProgHdrs_create_iter() {
    let mut buf = [0; ELF32_PROG_HDR_BYTES];
    let dynamic: Result<(ProgHdrs<'_, LittleEndian, Elf32>, &'_ mut [u8]), ()> =
        ProgHdrs::create_split(&mut buf[0..],
                               ELF32_PROG_HDR_CONTENTS_BARE.iter().map(|x| *x));

    assert!(dynamic.is_ok());

    let (dynamic, buf) = dynamic.expect("Expected success");

    assert_eq!(buf.len(), 0);

    let mut iter = dynamic.iter();

    for expect in ELF32_PROG_HDR_CONTENTS_BARE.iter() {
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
fn test_ProgHdrs_create_idx() {
    let mut buf = [0; ELF32_PROG_HDR_BYTES];
    let dynamic: Result<(ProgHdrs<'_, LittleEndian, Elf32>, &'_ mut [u8]), ()> =
        ProgHdrs::create_split(&mut buf[0..],
                               ELF32_PROG_HDR_CONTENTS_BARE.iter().map(|x| *x));

    assert!(dynamic.is_ok());

    let (dynamic, buf) = dynamic.expect("Expected success");

    assert_eq!(buf.len(), 0);

    for i in 0 .. ELF32_PROG_HDR_CONTENTS_BARE.len() {
        let expect = &ELF32_PROG_HDR_CONTENTS_BARE[i];
        let sym = dynamic.idx(i);

        assert!(sym.is_some());

        let data = sym.unwrap().try_into();

        assert!(data.is_ok());

        let actual = data.unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(dynamic.idx(ELF32_PROG_HDR_CONTENTS_BARE.len()).is_none());
}
