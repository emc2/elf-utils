use byteorder::LittleEndian;
use core::convert::TryFrom;
use core::convert::TryInto;
use elf_utils::Elf64;
use elf_utils::prog_hdr::ProgHdr;
use elf_utils::prog_hdr::ProgHdrData;
use elf_utils::prog_hdr::ProgHdrs;
use elf_utils::prog_hdr::Segment;

const ELF64_PROG_HDR_BYTES: usize = 560;

const ELF64_NUM_PROG_HDRS: usize = 10;

const ELF64_PROG_HDR: [u8; ELF64_PROG_HDR_BYTES] = [
    0x06, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x30, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x30, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x24, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x24, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    0x30, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x30, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x30, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x5c, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x5c, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
    0x38, 0xb0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x38, 0xd0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x38, 0xd0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x88, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x88, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
    0xc0, 0xb6, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xc0, 0xe6, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xc0, 0xe6, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xb0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xb0, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
    0xf8, 0xb4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf8, 0xd4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf8, 0xd4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x52, 0xe5, 0x74, 0x64, 0x04, 0x00, 0x00, 0x00,
    0x38, 0xb0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x38, 0xd0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x38, 0xd0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x88, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x88, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x50, 0xe5, 0x74, 0x64, 0x04, 0x00, 0x00, 0x00,
    0xdc, 0x49, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xdc, 0x49, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xdc, 0x49, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x24, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x24, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x51, 0xe5, 0x74, 0x64, 0x06, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x70, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x70, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x70, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
];

const ELF64_PROG_HDR_CONTENTS_BARE: [ProgHdrData<Elf64, Segment<u64>,
                                                 Segment<u64>, Segment<u64>>;
                                     ELF64_NUM_PROG_HDRS] = [
    ProgHdrData::ProgHdr { virt_addr: 0x40, phys_addr: 0x40,
                           content: Segment { offset: 0x40, size: 0x230 } },
    ProgHdrData::Load { virt_addr: 0, phys_addr: 0,
                        mem_size: 0x5424, align: 0x1000,
                        read: true, write: false, exec: false,
                        content: Segment { offset: 0, size: 0x5424 } },
    ProgHdrData::Load { virt_addr: 0x6430, phys_addr: 0x6430,
                        mem_size: 0x15c04, align: 0x1000,
                        read: true, write: false, exec: true,
                        content: Segment { offset: 0x5430, size: 0x15c04 } },
    ProgHdrData::Load { virt_addr: 0x1d038, phys_addr: 0x1d038,
                        mem_size: 0x688, align: 4096,
                        read: true, write: true, exec: false,
                        content: Segment { offset: 0x1b038, size: 0x688 } },
    ProgHdrData::Load { virt_addr: 0x1e6c0, phys_addr: 0x1e6c0,
                        mem_size: 0xeb0, align: 4096,
                        read: true, write: true, exec: false,
                        content: Segment { offset: 0x1b6c0, size: 0xb0 } },
    ProgHdrData::Dynamic { virt_addr: 0x1d4f8, phys_addr: 0x1d4f8,
                           content: Segment { offset: 0x1b4f8, size: 0x110 } },
    ProgHdrData::Unknown { tag: 0x6474e552, flags: 4, offset: 0x1b038,
                           file_size: 0x688, mem_size: 0x688,
                           phys_addr: 0x1d038, virt_addr: 0x1d038, align: 1 },
    ProgHdrData::Unknown { tag: 0x6474e550, flags: 4, offset: 0x49dc,
                           file_size: 0x224, mem_size: 0x224,
                           phys_addr: 0x49dc, virt_addr: 0x49dc, align: 4 },
    ProgHdrData::Unknown { tag: 0x6474e551, flags: 6, offset: 0,
                           file_size: 0, mem_size: 0,
                           phys_addr: 0, virt_addr: 0, align: 0 },
    ProgHdrData::Note { virt_addr: 0x270, phys_addr: 0x270,
                        content: Segment { offset: 0x270, size: 0x18 } },
];

#[test]
fn test_ProgHdrs_from_bytes_just_right() {
    let prog_hdr: Result<ProgHdrs<'_, LittleEndian, Elf64>, ()> =
        ProgHdrs::try_from(&ELF64_PROG_HDR[0..]);

    assert!(prog_hdr.is_ok());
}

#[test]
fn test_ProgHdrs_from_bytes_too_small() {
    let prog_hdr: Result<ProgHdrs<'_, LittleEndian, Elf64>, ()> =
        ProgHdrs::try_from(&ELF64_PROG_HDR[0 .. ELF64_PROG_HDR.len() - 1]);

    assert!(prog_hdr.is_err());
}

#[test]
fn test_ProgHdrs_from_bytes_num_hdrs() {
    let prog_hdr: ProgHdrs<'_, LittleEndian, Elf64> =
        ProgHdrs::try_from(&ELF64_PROG_HDR[0..])
        .expect("Expected success");

    assert_eq!(prog_hdr.num_hdrs(), ELF64_NUM_PROG_HDRS);
}

#[test]
fn test_ProgHdrs_from_bytes_iter_len() {
    let prog_hdr: ProgHdrs<'_, LittleEndian, Elf64> =
        ProgHdrs::try_from(&ELF64_PROG_HDR[0..])
        .expect("Expected success");
    let iter = prog_hdr.iter();

    assert_eq!(iter.len(), ELF64_NUM_PROG_HDRS);
}

#[test]
fn test_ProgHdrs_from_bytes_just_right_mut() {
    let mut buf = ELF64_PROG_HDR.clone();
    let prog_hdr: Result<ProgHdrs<'_, LittleEndian, Elf64>, ()> =
        ProgHdrs::try_from(&mut buf[0..]);

    assert!(prog_hdr.is_ok());
}

#[test]
fn test_ProgHdrs_from_bytes_too_small_mut() {
    let mut buf = ELF64_PROG_HDR.clone();
    let prog_hdr: Result<ProgHdrs<'_, LittleEndian, Elf64>, ()> =
        ProgHdrs::try_from(&mut buf[0 .. ELF64_PROG_HDR.len() - 1]);

    assert!(prog_hdr.is_err());
}

#[test]
fn test_ProgHdrs_from_bytes_num_hdrs_mut() {
    let mut buf = ELF64_PROG_HDR.clone();
    let prog_hdr: ProgHdrs<'_, LittleEndian, Elf64> =
        ProgHdrs::try_from(&mut buf[0..])
        .expect("Expected success");

    assert_eq!(prog_hdr.num_hdrs(), ELF64_NUM_PROG_HDRS);
}

#[test]
fn test_ProgHdrs_from_bytes_iter_len_mut() {
    let mut buf = ELF64_PROG_HDR.clone();
    let prog_hdr: ProgHdrs<'_, LittleEndian, Elf64> =
        ProgHdrs::try_from(&mut buf[0..])
        .expect("Expected success");
    let iter = prog_hdr.iter();

    assert_eq!(iter.len(), ELF64_NUM_PROG_HDRS);
}

#[test]
fn test_ProgHdrs_from_bytes_iter() {
    let prog_hdr: ProgHdrs<'_, LittleEndian, Elf64> =
        ProgHdrs::try_from(&ELF64_PROG_HDR[0..])
        .expect("Expected success");
    let mut iter = prog_hdr.iter();

    for expect in ELF64_PROG_HDR_CONTENTS_BARE.iter() {
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
    let prog_hdr: ProgHdrs<'_, LittleEndian, Elf64> =
        ProgHdrs::try_from(&ELF64_PROG_HDR[0..])
        .expect("Expected success");
    let mut iter = prog_hdr.iter();

    for i in 0 .. ELF64_PROG_HDR_CONTENTS_BARE.len() {
        let expect = &ELF64_PROG_HDR_CONTENTS_BARE[i];
        let ent = prog_hdr.idx(i);

        assert!(ent.is_some());

        let data = ent.unwrap().try_into();

        assert!(data.is_ok());

        let actual = data.unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(prog_hdr.idx(ELF64_PROG_HDR_CONTENTS_BARE.len()).is_none());
}

#[test]
fn test_ProgHdrs_create_just_right() {
    let mut buf = [0; ELF64_PROG_HDR_BYTES];
    let dynamic: Result<(ProgHdrs<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        ProgHdrs::create_split(&mut buf[0..],
                               ELF64_PROG_HDR_CONTENTS_BARE.iter().map(|x| *x));

    assert!(dynamic.is_ok());

    let (dynamic, buf) = dynamic.expect("Expected success");

    assert_eq!(buf.len(), 0);
}

#[test]
fn test_ProgHdrs_create_too_big() {
    let mut buf = [0; ELF64_PROG_HDR_BYTES + 1];
    let dynamic: Result<(ProgHdrs<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        ProgHdrs::create_split(&mut buf[0..],
                               ELF64_PROG_HDR_CONTENTS_BARE.iter().map(|x| *x));

    assert!(dynamic.is_ok());

    let (dynamic, buf) = dynamic.expect("Expected success");

    assert_eq!(buf.len(), 1);
}

#[test]
fn test_ProgHdrs_create_too_small() {
    let mut buf = [0; ELF64_PROG_HDR_BYTES - 1];
    let dynamic: Result<(ProgHdrs<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        ProgHdrs::create_split(&mut buf[0..],
                               ELF64_PROG_HDR_CONTENTS_BARE.iter().map(|x| *x));

    assert!(dynamic.is_err());
}


#[test]
fn test_ProgHdrs_create_iter() {
    let mut buf = [0; ELF64_PROG_HDR_BYTES];
    let dynamic: Result<(ProgHdrs<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        ProgHdrs::create_split(&mut buf[0..],
                               ELF64_PROG_HDR_CONTENTS_BARE.iter().map(|x| *x));

    assert!(dynamic.is_ok());

    let (dynamic, buf) = dynamic.expect("Expected success");

    assert_eq!(buf.len(), 0);

    let mut iter = dynamic.iter();

    for expect in ELF64_PROG_HDR_CONTENTS_BARE.iter() {
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
    let mut buf = [0; ELF64_PROG_HDR_BYTES];
    let dynamic: Result<(ProgHdrs<'_, LittleEndian, Elf64>, &'_ mut [u8]), ()> =
        ProgHdrs::create_split(&mut buf[0..],
                               ELF64_PROG_HDR_CONTENTS_BARE.iter().map(|x| *x));

    assert!(dynamic.is_ok());

    let (dynamic, buf) = dynamic.expect("Expected success");

    assert_eq!(buf.len(), 0);

    for i in 0 .. ELF64_PROG_HDR_CONTENTS_BARE.len() {
        let expect = &ELF64_PROG_HDR_CONTENTS_BARE[i];
        let sym = dynamic.idx(i);

        assert!(sym.is_some());

        let data = sym.unwrap().try_into();

        assert!(data.is_ok());

        let actual = data.unwrap();

        assert_eq!(expect, &actual)
    }

    assert!(dynamic.idx(ELF64_PROG_HDR_CONTENTS_BARE.len()).is_none());
}
