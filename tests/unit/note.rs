use byteorder::ByteOrder;
use byteorder::LittleEndian;
use core::convert::TryFrom;
use elf_utils::note::required_bytes;
use elf_utils::note::NoteData;
use elf_utils::note::Notes;
use elf_utils::note::NotesError;
use elf_utils::note::NotesMut;

const ELF_NOTES_SIZE: usize = 72;

const ELF_NOTES: [u8; ELF_NOTES_SIZE] = [
    0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x46, 0x72, 0x65, 0x65,
    0x42, 0x53, 0x44, 0x00, 0x92, 0xd6, 0x13, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x46, 0x72, 0x65, 0x65,
    0x42, 0x53, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x46, 0x72, 0x65, 0x65,
    0x42, 0x53, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00
];

const ELF_NOTES_COUNT: usize = 3;

const ELF_NOTE_1_NAME_SIZE: usize = 8;
const ELF_NOTE_1_DESC_SIZE: usize = 4;

const ELF_NOTE_1_NAME: [u8; ELF_NOTE_1_NAME_SIZE] = [
    0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
];

const ELF_NOTE_1_DESC: [u8; ELF_NOTE_1_DESC_SIZE] = [
    0x92, 0xd6, 0x13, 0x00
];

const ELF_NOTE_2_NAME_SIZE: usize = 8;
const ELF_NOTE_2_DESC_SIZE: usize = 4;

const ELF_NOTE_2_NAME: [u8; ELF_NOTE_2_NAME_SIZE] = [
    0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
];

const ELF_NOTE_2_DESC: [u8; ELF_NOTE_2_DESC_SIZE] = [
    0x00, 0x00, 0x00, 0x00
];

const ELF_NOTE_3_NAME_SIZE: usize = 8;
const ELF_NOTE_3_DESC_SIZE: usize = 4;

const ELF_NOTE_3_NAME: [u8; ELF_NOTE_3_NAME_SIZE] = [
    0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
];

const ELF_NOTE_3_DESC: [u8; ELF_NOTE_3_DESC_SIZE] = [
    0x00, 0x00, 0x00, 0x00
];

const ELF_NOTES_CONTENTS: [NoteData<'static>; ELF_NOTES_COUNT] = [
    NoteData { kind: 1, name: &ELF_NOTE_1_NAME, desc: &ELF_NOTE_1_DESC },
    NoteData { kind: 4, name: &ELF_NOTE_2_NAME, desc: &ELF_NOTE_2_DESC },
    NoteData { kind: 2, name: &ELF_NOTE_3_NAME, desc: &ELF_NOTE_3_DESC },
];

#[test]
fn test_Note_from_slice_ok() {
    let notes: Result<Notes<'_, LittleEndian>, NotesError> =
        Notes::try_from(&ELF_NOTES[0..]);

    assert!(notes.is_ok());
}

#[test]
fn test_Note_from_slice_too_small() {
    let notes: Result<Notes<'_, LittleEndian>, NotesError> =
        Notes::try_from(&ELF_NOTES[0 .. ELF_NOTES.len() - 1]);

    assert!(notes.is_err());
}

#[test]
fn test_Note_from_slice_iter() {
    let notes: Notes<'_, LittleEndian> =
        Notes::try_from(&ELF_NOTES[0..]).expect("Expected success");
    let mut iter = notes.iter();

    for expected in ELF_NOTES_CONTENTS.iter() {
        let note = iter.next();

        assert!(note.is_some());

        let actual = note.unwrap();

        assert_eq!(expected, &actual)
    }

    assert!(iter.next().is_none());
}

#[test]
fn test_Note_create_just_right() {
    let mut buf = [0; ELF_NOTES.len()];
    let notes: Result<(Notes<'_, LittleEndian>, &'_ mut [u8]), ()> =
        Notes::create_split(&mut buf[0..], ELF_NOTES_CONTENTS.iter());

    assert!(notes.is_ok());

    let (notes, buf) = notes.expect("Expected success");

    assert_eq!(buf.len(), 0);
}

#[test]
fn test_Note_create_too_big() {
    let mut buf = [0; ELF_NOTES.len() + 1];
    let notes: Result<(Notes<'_, LittleEndian>, &'_ mut [u8]), ()> =
        Notes::create_split(&mut buf[0..], ELF_NOTES_CONTENTS.iter());

    assert!(notes.is_ok());

    let (notes, buf) = notes.expect("Expected success");

    assert_eq!(buf.len(), 1);
}

#[test]
fn test_Note_create_too_small() {
    let mut buf = [0; ELF_NOTES.len() - 1];
    let notes: Result<(Notes<'_, LittleEndian>, &'_ mut [u8]), ()> =
        Notes::create_split(&mut buf[0..], ELF_NOTES_CONTENTS.iter());

    assert!(notes.is_err());
}

#[test]
fn test_Note_create_iter() {
    let mut buf = [0; ELF_NOTES.len()];
    let notes: Notes<'_, LittleEndian> =
        Notes::create(&mut buf[0..], ELF_NOTES_CONTENTS.iter())
        .expect("Expected success");
    let mut iter = notes.iter();

    for expected in ELF_NOTES_CONTENTS.iter() {
        let note = iter.next();

        assert!(note.is_some());

        let actual = note.unwrap();

        assert_eq!(expected, &actual)
    }

    assert!(iter.next().is_none());
}

#[test]
fn test_required_bytes() {
    assert_eq!(required_bytes(ELF_NOTES_CONTENTS.iter()),
               ELF_NOTES.len())
}

#[test]
fn test_NoteMut_from_slice_ok() {
    let mut buf = ELF_NOTES.clone();
    let notes: Result<Notes<'_, LittleEndian>, NotesError> =
        Notes::try_from(&mut buf[0..]);

    assert!(notes.is_ok());
}

#[test]
fn test_NoteMut_from_slice_too_small() {
    let mut buf = ELF_NOTES.clone();
    let notes: Result<Notes<'_, LittleEndian>, NotesError> =
        Notes::try_from(&mut buf[0 .. ELF_NOTES.len() - 1]);

    assert!(notes.is_err());
}

#[test]
fn test_NoteMut_from_slice_iter() {
    let mut buf = ELF_NOTES.clone();
    let notes: Notes<'_, LittleEndian> =
        Notes::try_from(&mut buf[0..]).expect("Expected success");
    let mut iter = notes.iter();

    for expected in ELF_NOTES_CONTENTS.iter() {
        let note = iter.next();

        assert!(note.is_some());

        let actual = note.unwrap();

        assert_eq!(expected, &actual)
    }

    assert!(iter.next().is_none());
}

#[test]
fn test_NoteMut_create_just_right() {
    let mut buf = [0; ELF_NOTES.len()];
    let notes: Result<(NotesMut<'_, LittleEndian>, &'_ mut [u8]), ()> =
        NotesMut::create_split(&mut buf[0..], ELF_NOTES_CONTENTS.iter());

    assert!(notes.is_ok());

    let (notes, buf) = notes.expect("Expected success");

    assert_eq!(buf.len(), 0);
}

#[test]
fn test_NoteMut_create_too_big() {
    let mut buf = [0; ELF_NOTES.len() + 1];
    let notes: Result<(NotesMut<'_, LittleEndian>, &'_ mut [u8]), ()> =
        NotesMut::create_split(&mut buf[0..], ELF_NOTES_CONTENTS.iter());

    assert!(notes.is_ok());

    let (notes, buf) = notes.expect("Expected success");

    assert_eq!(buf.len(), 1);
}

#[test]
fn test_NoteMut_create_too_small() {
    let mut buf = [0; ELF_NOTES.len() - 1];
    let notes: Result<(NotesMut<'_, LittleEndian>, &'_ mut [u8]), ()> =
        NotesMut::create_split(&mut buf[0..], ELF_NOTES_CONTENTS.iter());

    assert!(notes.is_err());
}

#[test]
fn test_NoteMut_create_iter() {
    let mut buf = [0; ELF_NOTES.len()];
    let notes: NotesMut<'_, LittleEndian> =
        NotesMut::create(&mut buf[0..], ELF_NOTES_CONTENTS.iter())
        .expect("Expected success");
    let mut iter = notes.iter();

    for expected in ELF_NOTES_CONTENTS.iter() {
        let note = iter.next();

        assert!(note.is_some());

        let actual = note.unwrap();

        assert_eq!(expected, &actual)
    }

    assert!(iter.next().is_none());
}
