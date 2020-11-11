use core::convert::TryFrom;
use core::convert::TryInto;
use elf_utils::strtab::Strtab;
use elf_utils::strtab::StrtabError;

const ELF_SPEC_STRTAB: [u8; 25] = [
    0,
    'n' as u8, 'a' as u8, 'm' as u8, 'e' as u8, '.' as u8, 0,
    'V' as u8, 'a' as u8, 'r' as u8, 'i' as u8,
    'a' as u8, 'b' as u8, 'l' as u8, 'e' as u8, 0,
    'a' as u8, 'b' as u8, 'l' as u8, 'e' as u8, 0,
    0,
    'x' as u8, 'x' as u8, 0
];

const STRTAB_STRS: [&'static str; 5] = [
    "name.",
    "Variable",
    "able",
    "",
    "xx"
];


#[test]
fn test_Strtab_required_bytes() {
    let required = Strtab::required_bytes(STRTAB_STRS.iter().map(|x| *x));

    assert_eq!(required, 25);
}

#[test]
fn test_Strtab_from_u8() {
    let strtab: Result<Strtab<'_>, ()> =
        Strtab::try_from(&ELF_SPEC_STRTAB[0..]);

    assert!(strtab.is_ok())
}

#[test]
fn test_Strtab_from_u8_bad_start() {
    let strtab: Result<Strtab<'_>, ()> =
        Strtab::try_from(&ELF_SPEC_STRTAB[1..]);

    assert!(strtab.is_err())
}

#[test]
fn test_Strtab_from_u8_bad_end() {
    let strtab: Result<Strtab<'_>, ()> =
        Strtab::try_from(&ELF_SPEC_STRTAB[0 .. ELF_SPEC_STRTAB.len() - 1]);

    assert!(strtab.is_err())
}

#[test]
fn test_Strtab_from_u8_idx_0() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_SPEC_STRTAB[0..])
        .expect("Expected success");
    assert_eq!(strtab.idx(0), Ok(""));
}

#[test]
fn test_Strtab_from_u8_idx_name() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_SPEC_STRTAB[0..])
        .expect("Expected success");
    assert_eq!(strtab.idx(1), Ok("name."));
}

#[test]
fn test_Strtab_from_u8_idx_Variable() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_SPEC_STRTAB[0..])
        .expect("Expected success");
    assert_eq!(strtab.idx(7), Ok("Variable"));
}

#[test]
fn test_Strtab_from_u8_idx_able() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_SPEC_STRTAB[0..])
        .expect("Expected success");
    assert_eq!(strtab.idx(11), Ok("able"));
}

#[test]
fn test_Strtab_from_u8_idx_able_2() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_SPEC_STRTAB[0..])
        .expect("Expected success");
    assert_eq!(strtab.idx(16), Ok("able"));
}

#[test]
fn test_Strtab_from_u8_idx_xx() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_SPEC_STRTAB[0..])
        .expect("Expected success");
    assert_eq!(strtab.idx(22), Ok("xx"));
}

#[test]
fn test_Strtab_from_u8_idx_last() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_SPEC_STRTAB[0..])
        .expect("Expected success");
    assert_eq!(strtab.idx(24), Ok(""));
}

#[test]
fn test_Strtab_from_u8_idx_out_of_bounds() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_SPEC_STRTAB[0..])
        .expect("Expected success");
    assert_eq!(strtab.idx(25), Err(StrtabError::OutOfBounds));
}

#[test]
fn test_Strtab_from_u8_iter() {
    let strtab: Strtab<'_> =
        Strtab::try_from(&ELF_SPEC_STRTAB[0..])
        .expect("Expected success");
    let mut iter = strtab.iter();

    assert_eq!(iter.next(), Some((Ok(""), 0)));
    assert_eq!(iter.next(), Some((Ok("name."), 1)));
    assert_eq!(iter.next(), Some((Ok("Variable"), 7)));
    assert_eq!(iter.next(), Some((Ok("able"), 16)));
    assert_eq!(iter.next(), Some((Ok(""), 21)));
    assert_eq!(iter.next(), Some((Ok("xx"), 22)));
    assert_eq!(iter.next(), None);
}

#[test]
fn test_Strtab_create_just_right() {
    let mut buf = [0; 25];
    let strtab: Result<(Strtab<'_>, &'_ mut [u8]), ()> =
        Strtab::create_split(&mut buf[0..], STRTAB_STRS.iter().map(|x| *x));

    assert!(strtab.is_ok());

    let (strtab, buf) = strtab.expect("Expected success");

    assert_eq!(buf.len(), 0);
}

#[test]
fn test_Strtab_create_too_big() {
    let mut buf = [0; 26];
    let strtab: Result<(Strtab<'_>, &'_ mut [u8]), ()> =
        Strtab::create_split(&mut buf[0..], STRTAB_STRS.iter().map(|x| *x));

    assert!(strtab.is_ok());

    let (strtab, buf) = strtab.expect("Expected success");

    assert_eq!(buf.len(), 1);
}

#[test]
fn test_Strtab_create_too_small() {
    let mut buf = [0; 24];
    let strtab: Result<(Strtab<'_>, &'_ mut [u8]), ()> =
        Strtab::create_split(&mut buf[0..], STRTAB_STRS.iter().map(|x| *x));

    assert!(strtab.is_err());
}

#[test]
fn test_Strtab_create_iter() {
    let mut buf = [0; 25];
    let strtab: Result<(Strtab<'_>, &'_ mut [u8]), ()> =
        Strtab::create_split(&mut buf[0..], STRTAB_STRS.iter().map(|x| *x));

    assert!(strtab.is_ok());

    let (strtab, _) = strtab.expect("Expected success");
    let mut iter = strtab.iter();

    for (s, i) in strtab.iter() {
        match (s, strtab.idx(i)) {
            (Ok(actual), Ok(expect)) => assert_eq!(actual, expect),
            (Err(actual), Err(StrtabError::UTF8Decode(expect))) =>
                assert_eq!(actual, expect),
            (actual, expect) => panic!("Expected: {:?}\nActual: {:?}",
                                       expect, actual)
        }
    }
}
