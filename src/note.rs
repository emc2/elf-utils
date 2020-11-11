//! ELF note section functionality.
//!
//! This module provides a [Notes] type which acts as a wrapper
//! around ELF note section data.
//!
//! # Examples
//!
//! A `Notes` can be created from any slice containing binary data
//! that contains some number of properly-formatted ELF notes.
//!
//! ```
//! extern crate elf_utils;
//!
//! use byteorder::LittleEndian;
//! use core::convert::TryFrom;
//! use elf_utils::note::Notes;
//!
//! const ELF_NOTES: [u8; 72] = [
//!     0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
//!     0x01, 0x00, 0x00, 0x00, 0x46, 0x72, 0x65, 0x65,
//!     0x42, 0x53, 0x44, 0x00, 0x92, 0xd6, 0x13, 0x00,
//!     0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
//!     0x04, 0x00, 0x00, 0x00, 0x46, 0x72, 0x65, 0x65,
//!     0x42, 0x53, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x46, 0x72, 0x65, 0x65,
//!     0x42, 0x53, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00
//! ];
//!
//! let notes: Result<Notes<'_, LittleEndian>, ()> =
//!     Notes::try_from(&ELF_NOTES[0..]);
//!
//! assert!(notes.is_ok());
//! ```
//!
//! It is also possible to iterate over the notes:
//!
//! ```
//! extern crate elf_utils;
//!
//! use byteorder::LittleEndian;
//! use core::convert::TryFrom;
//! use elf_utils::note::Notes;
//! use elf_utils::note::NoteData;
//!
//! const ELF_NOTES: [u8; 72] = [
//!     0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
//!     0x01, 0x00, 0x00, 0x00, 0x46, 0x72, 0x65, 0x65,
//!     0x42, 0x53, 0x44, 0x00, 0x92, 0xd6, 0x13, 0x00,
//!     0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
//!     0x04, 0x00, 0x00, 0x00, 0x46, 0x72, 0x65, 0x65,
//!     0x42, 0x53, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
//!     0x02, 0x00, 0x00, 0x00, 0x46, 0x72, 0x65, 0x65,
//!     0x42, 0x53, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00
//! ];
//!
//! let notes: Notes<'_, LittleEndian> =
//!     Notes::try_from(&ELF_NOTES[0..]).unwrap();
//! let mut iter = notes.iter();
//!
//! const ELF_NOTE_1_NAME: [u8; 8] = [
//!     0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
//! ];
//! const ELF_NOTE_1_DESC: [u8; 4] = [
//!     0x92, 0xd6, 0x13, 0x00
//! ];
//! const ELF_NOTE_2_NAME: [u8; 8] = [
//!     0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
//! ];
//! const ELF_NOTE_2_DESC: [u8; 4] = [
//!     0x00, 0x00, 0x00, 0x00
//! ];
//! const ELF_NOTE_3_NAME: [u8; 8] = [
//!     0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
//! ];
//! const ELF_NOTE_3_DESC: [u8; 4] = [
//!     0x00, 0x00, 0x00, 0x00
//! ];
//!
//! assert_eq!(iter.next(), Some(NoteData { kind: 1, name: &ELF_NOTE_1_NAME,
//!                                         desc: &ELF_NOTE_1_DESC }));
//! assert_eq!(iter.next(), Some(NoteData { kind: 4, name: &ELF_NOTE_2_NAME,
//!                                         desc: &ELF_NOTE_2_DESC }));
//! assert_eq!(iter.next(), Some(NoteData { kind: 2, name: &ELF_NOTE_3_NAME,
//!                                         desc: &ELF_NOTE_3_DESC }));
//! assert_eq!(iter.next(), None);
//! ```
//!
//! A `Notes` can be created in mutable memory from any iterator over
//! string values using [create](Notes::create):
//!
//! ```
//! extern crate elf_utils;
//!
//! use byteorder::LittleEndian;
//! use core::convert::TryFrom;
//! use elf_utils::note::Notes;
//! use elf_utils::note::NoteData;
//!
//!
//! const ELF_NOTE_1_NAME: [u8; 8] = [
//!     0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
//! ];
//! const ELF_NOTE_1_DESC: [u8; 4] = [
//!     0x92, 0xd6, 0x13, 0x00
//! ];
//! const ELF_NOTE_2_NAME: [u8; 8] = [
//!     0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
//! ];
//! const ELF_NOTE_2_DESC: [u8; 4] = [
//!     0x00, 0x00, 0x00, 0x00
//! ];
//! const ELF_NOTE_3_NAME: [u8; 8] = [
//!     0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
//! ];
//! const ELF_NOTE_3_DESC: [u8; 4] = [
//!     0x00, 0x00, 0x00, 0x00
//! ];
//! const ELF_NOTES_CONTENTS: [NoteData<'static>; 3] = [
//!     NoteData { kind: 1, name: &ELF_NOTE_1_NAME, desc: &ELF_NOTE_1_DESC },
//!     NoteData { kind: 4, name: &ELF_NOTE_2_NAME, desc: &ELF_NOTE_2_DESC },
//!     NoteData { kind: 2, name: &ELF_NOTE_3_NAME, desc: &ELF_NOTE_3_DESC },
//! ];
//!
//! let mut buf = [0; 72];
//! let notes: Result<Notes<'_, LittleEndian>, ()> =
//!     Notes::create(&mut buf[0..], ELF_NOTES_CONTENTS.iter().map(|x| *x));
//!
//! assert!(notes.is_ok());
//! ```
//!
//! The size of the buffer needed to hold the `Notes` can be obtained
//! with [required_bytes].
//!
//! ```
//! extern crate elf_utils;
//!
//! use byteorder::LittleEndian;
//! use core::convert::TryFrom;
//! use elf_utils::note::required_bytes;
//! use elf_utils::note::Notes;
//! use elf_utils::note::NoteData;
//!
//! const ELF_NOTE_1_NAME: [u8; 8] = [
//!     0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
//! ];
//! const ELF_NOTE_1_DESC: [u8; 4] = [
//!     0x92, 0xd6, 0x13, 0x00
//! ];
//! const ELF_NOTE_2_NAME: [u8; 8] = [
//!     0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
//! ];
//! const ELF_NOTE_2_DESC: [u8; 4] = [
//!     0x00, 0x00, 0x00, 0x00
//! ];
//! const ELF_NOTE_3_NAME: [u8; 8] = [
//!     0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
//! ];
//! const ELF_NOTE_3_DESC: [u8; 4] = [
//!     0x00, 0x00, 0x00, 0x00
//! ];
//! const ELF_NOTES_CONTENTS: [NoteData<'static>; 3] = [
//!     NoteData { kind: 1, name: &ELF_NOTE_1_NAME, desc: &ELF_NOTE_1_DESC },
//!     NoteData { kind: 4, name: &ELF_NOTE_2_NAME, desc: &ELF_NOTE_2_DESC },
//!     NoteData { kind: 2, name: &ELF_NOTE_3_NAME, desc: &ELF_NOTE_3_DESC },
//! ];
//!
//! assert_eq!(required_bytes(ELF_NOTES_CONTENTS.iter().map(|x| *x)), 72)
//! ```
//!
//! The [create_split](Notes::create_split) variant returns a
//! reference to the remaining space.  This is useful for creating a
//! `Notes` as part of a larger set of contiguous objects:
//!
//! ```
//! extern crate elf_utils;
//!
//! use byteorder::LittleEndian;
//! use core::convert::TryFrom;
//! use elf_utils::note::NoteData;
//! use elf_utils::note::Notes;
//!
//! const ELF_NOTE_1_NAME: [u8; 8] = [
//!     0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
//! ];
//! const ELF_NOTE_1_DESC: [u8; 4] = [
//!     0x92, 0xd6, 0x13, 0x00
//! ];
//! const ELF_NOTE_2_NAME: [u8; 8] = [
//!     0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
//! ];
//! const ELF_NOTE_2_DESC: [u8; 4] = [
//!     0x00, 0x00, 0x00, 0x00
//! ];
//! const ELF_NOTE_3_NAME: [u8; 8] = [
//!     0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
//! ];
//! const ELF_NOTE_3_DESC: [u8; 4] = [
//!     0x00, 0x00, 0x00, 0x00
//! ];
//! const ELF_NOTES_CONTENTS: [NoteData<'static>; 3] = [
//!     NoteData { kind: 1, name: &ELF_NOTE_1_NAME, desc: &ELF_NOTE_1_DESC },
//!     NoteData { kind: 4, name: &ELF_NOTE_2_NAME, desc: &ELF_NOTE_2_DESC },
//!     NoteData { kind: 2, name: &ELF_NOTE_3_NAME, desc: &ELF_NOTE_3_DESC },
//! ];
//!
//! let mut buf = [0; 80];
//! let res: Result<(Notes<'_, LittleEndian>, &'_ mut [u8]), ()> =
//!     Notes::create_split(&mut buf[0..],
//!                         ELF_NOTES_CONTENTS.iter().map(|x| *x));
//! let (notes, buf) = res.unwrap();
//!
//! assert_eq!(buf.len(), 8);
//! ```

use byteorder::ByteOrder;
use core::convert::TryFrom;
use core::iter::FusedIterator;
use core::iter::Iterator;
use core::marker::PhantomData;

const ELF_NOTE_WORD_SIZE: usize = 4;

const ELF_NOTE_NAME_SIZE_START: usize = 0;
const ELF_NOTE_NAME_SIZE_SIZE: usize = ELF_NOTE_WORD_SIZE;
const ELF_NOTE_NAME_SIZE_END: usize = ELF_NOTE_NAME_SIZE_START +
                                      ELF_NOTE_NAME_SIZE_SIZE;

const ELF_NOTE_DESC_SIZE_START: usize = ELF_NOTE_NAME_SIZE_END;
const ELF_NOTE_DESC_SIZE_SIZE: usize = ELF_NOTE_WORD_SIZE;
const ELF_NOTE_DESC_SIZE_END: usize = ELF_NOTE_DESC_SIZE_START +
                                      ELF_NOTE_DESC_SIZE_SIZE;

const ELF_NOTE_TYPE_START: usize = ELF_NOTE_DESC_SIZE_END;
const ELF_NOTE_TYPE_SIZE: usize = ELF_NOTE_WORD_SIZE;
const ELF_NOTE_TYPE_END: usize = ELF_NOTE_TYPE_START + ELF_NOTE_TYPE_SIZE;

const ELF_NOTE_NAME_START: usize = ELF_NOTE_TYPE_END;
const ELF_NOTE_NAME_SIZE: usize = ELF_NOTE_WORD_SIZE;
const ELF_NOTE_NAME_END: usize = ELF_NOTE_NAME_START + ELF_NOTE_NAME_SIZE;

const ELF_NOTE_DESC_START: usize = ELF_NOTE_NAME_END;
const ELF_NOTE_DESC_SIZE: usize = ELF_NOTE_WORD_SIZE;
const ELF_NOTE_DESC_END: usize = ELF_NOTE_DESC_START + ELF_NOTE_DESC_SIZE;

/// In-place read-only ELF notes section.
///
/// ELF note sections contain one or more simple data objects
/// consisting of a name and descriptor.  They allow platforms to
/// attach simple metadata to an ELF file.
///
/// A `Notes` is essentially a 'handle' for the raw ELF data, whose
/// format may differ from the host format.  It can be iterated over
/// with [iter](Notes::iter).
///
/// A `Notes` can be created from raw ELF note data using the
/// [TryFrom](core::convert::TryFrom) instance.  This will verify that
/// the internal size values are correct before creating a `Notes`.
///
/// New `Notes` can be created from an iterator over [NoteData] with
/// [create](Notes::create) or [create_split](Notes::create_split).
///
/// # Examples
///
/// ```
/// extern crate elf_utils;
///
/// use byteorder::LittleEndian;
/// use core::convert::TryFrom;
/// use elf_utils::note::Notes;
///
/// const ELF_NOTES: [u8; 72] = [
///     0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
///     0x01, 0x00, 0x00, 0x00, 0x46, 0x72, 0x65, 0x65,
///     0x42, 0x53, 0x44, 0x00, 0x92, 0xd6, 0x13, 0x00,
///     0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
///     0x04, 0x00, 0x00, 0x00, 0x46, 0x72, 0x65, 0x65,
///     0x42, 0x53, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x46, 0x72, 0x65, 0x65,
///     0x42, 0x53, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00
/// ];
///
/// let notes: Result<Notes<'_, LittleEndian>, ()> =
///     Notes::try_from(&ELF_NOTES[0..]);
///
/// assert!(notes.is_ok());
/// ```
#[derive(Copy, Clone)]
pub struct Notes<'a, B: ByteOrder> {
    byteorder: PhantomData<B>,
    data: &'a [u8]
}

pub struct NotesMut<'a, B: ByteOrder> {
    byteorder: PhantomData<B>,
    data: &'a mut [u8]
}

/// Iterator over the contents of an ELF note section.
///
/// This is an iterator which produces [NoteData] for each note object
/// in a [Notes] section.
///
/// # Examples
///
/// ```
/// extern crate elf_utils;
///
/// use byteorder::LittleEndian;
/// use core::convert::TryFrom;
/// use elf_utils::note::Notes;
/// use elf_utils::note::NoteData;
///
/// const ELF_NOTES: [u8; 72] = [
///     0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
///     0x01, 0x00, 0x00, 0x00, 0x46, 0x72, 0x65, 0x65,
///     0x42, 0x53, 0x44, 0x00, 0x92, 0xd6, 0x13, 0x00,
///     0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
///     0x04, 0x00, 0x00, 0x00, 0x46, 0x72, 0x65, 0x65,
///     0x42, 0x53, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
///     0x02, 0x00, 0x00, 0x00, 0x46, 0x72, 0x65, 0x65,
///     0x42, 0x53, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00
/// ];
///
/// let notes: Notes<'_, LittleEndian> =
///     Notes::try_from(&ELF_NOTES[0..]).unwrap();
///
/// const ELF_NOTE_1_NAME: [u8; 8] = [
///     0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
/// ];
/// const ELF_NOTE_1_DESC: [u8; 4] = [
///     0x92, 0xd6, 0x13, 0x00
/// ];
/// const ELF_NOTE_2_NAME: [u8; 8] = [
///     0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
/// ];
/// const ELF_NOTE_2_DESC: [u8; 4] = [
///     0x00, 0x00, 0x00, 0x00
/// ];
/// const ELF_NOTE_3_NAME: [u8; 8] = [
///     0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
/// ];
/// const ELF_NOTE_3_DESC: [u8; 4] = [
///     0x00, 0x00, 0x00, 0x00
/// ];
///
/// let mut iter = notes.iter();
///
/// assert_eq!(iter.next(), Some(NoteData { kind: 1, name: &ELF_NOTE_1_NAME,
///                                         desc: &ELF_NOTE_1_DESC }));
/// assert_eq!(iter.next(), Some(NoteData { kind: 4, name: &ELF_NOTE_2_NAME,
///                                         desc: &ELF_NOTE_2_DESC }));
/// assert_eq!(iter.next(), Some(NoteData { kind: 2, name: &ELF_NOTE_3_NAME,
///                                         desc: &ELF_NOTE_3_DESC }));
/// assert_eq!(iter.next(), None);
/// ```
#[derive(Copy, Clone)]
pub struct NotesIter<'a, B: ByteOrder> {
    byteorder: PhantomData<B>,
    data: &'a [u8],
    idx: usize
}

/// Projected ELF note data.
///
/// This is a representation of the data in a single ELF note in a
/// form that can be manipulated native code.  `NoteData` can also be
/// used to create a note section with the [create](Notes::create) and
/// [create_split](Notes::create_split) functions.
#[derive(Copy, Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub struct NoteData<'a> {
    /// Type field, interpreted as a 4-byte integer in the ELF's
    /// byte-order.
    pub kind: u32,
    /// Name data.
    pub name: &'a [u8],
    /// Descriptor data.
    pub desc: &'a [u8]
}

/// Calculate the size of a single ELF note.
#[inline]
fn get_size<'a, B>(data: &'a [u8], byteorder: PhantomData<B>) -> Option<usize>
    where B: ByteOrder {
    if data.len() >= ELF_NOTE_WORD_SIZE * 2 {
        let namesize = B::read_u32(&data[ELF_NOTE_NAME_SIZE_START ..
                                         ELF_NOTE_NAME_SIZE_END]) as usize;
        let descsize = B::read_u32(&data[ELF_NOTE_DESC_SIZE_START ..
                                         ELF_NOTE_DESC_SIZE_END]) as usize;
        let size = (ELF_NOTE_WORD_SIZE * 3) + namesize + descsize;

        if data.len() >= size {
            Some(size)
        } else {
            None
        }
    } else {
        None
    }
}

/// Check the internal formatting of an ELF note section.
#[inline]
fn check<'a, B>(data: &'a [u8], byteorder: PhantomData<B>) -> bool
    where B: ByteOrder {
    let mut idx = 0;

    while idx < data.len() {
        let buf = &data[idx..];

        match get_size(buf, byteorder) {
            Some(size) => idx += size,
            None => return false
        }
    }

    true
}

#[inline]
fn project<'a, B>(data: &'a [u8], byteorder: PhantomData<B>) -> NoteData<'a>
    where B: ByteOrder {
    let name_size = B::read_u32(&data[ELF_NOTE_NAME_SIZE_START ..
                                      ELF_NOTE_NAME_SIZE_END]) as usize;
    let desc_size = B::read_u32(&data[ELF_NOTE_DESC_SIZE_START ..
                                      ELF_NOTE_DESC_SIZE_END]) as usize;
    let kind = B::read_u32(&data[ELF_NOTE_TYPE_START .. ELF_NOTE_TYPE_END]);
    let name_start = ELF_NOTE_TYPE_END;
    let name_end = name_start + name_size;
    let name = &data[name_start .. name_end];
    let desc_start = name_end;
    let desc_end = desc_start + desc_size;
    let desc = &data[desc_start .. desc_end];

    NoteData { kind: kind, name: name, desc: desc }
}

fn create_split_raw<'a, B, I>(buf: &'a mut [u8], notes: I,
                              byteorder: PhantomData<B>) ->
    Result<(&'a mut [u8], &'a mut [u8]), ()>
    where I: Iterator<Item = NoteData<'a>>,
          B: ByteOrder {
    let mut idx = 0;

    for NoteData { kind, name, desc } in notes {
        let namesize = name.len();
        let descsize = desc.len();
        let size = namesize + descsize + (ELF_NOTE_WORD_SIZE * 3);

        if buf.len() >= size + idx {
            let name_start = ELF_NOTE_TYPE_END;
            let name_end = name_start + namesize;
            let desc_start = name_end;
            let desc_end = desc_start + descsize;

            B::write_u32(&mut buf[idx + ELF_NOTE_NAME_SIZE_START ..
                                  idx + ELF_NOTE_NAME_SIZE_END],
                         namesize as u32);
            B::write_u32(&mut buf[idx + ELF_NOTE_DESC_SIZE_START ..
                                  idx + ELF_NOTE_DESC_SIZE_END],
                         descsize as u32);
            B::write_u32(&mut buf[idx + ELF_NOTE_TYPE_START ..
                                  idx + ELF_NOTE_TYPE_END],
                         kind);
            (&mut buf[idx + name_start .. idx + name_end])
                .clone_from_slice(&name[0..]);
            (&mut buf[idx + desc_start .. idx + desc_end])
                .clone_from_slice(&desc[0..]);

            idx += size
        } else {
            return Err(())
        }
    }

    Ok(buf.split_at_mut(idx))
}


/// Calculate the number of bytes required to represent all of the
/// note objects in `notes`.
#[inline]
pub fn required_bytes<'a, I>(notes: I) -> usize
    where I: Iterator<Item = NoteData<'a>> {
    let mut size = 0;

    for NoteData { name, desc, .. } in notes {
        let namesize = name.len();
        let descsize = desc.len();

        size += (ELF_NOTE_WORD_SIZE * 3) + namesize + descsize;
    }

    size
}

impl<'a, B> Notes<'a, B>
    where B: ByteOrder {
    /// Attempt to create a `Notes` in `buf` containing the note objects
    /// in `notes`.
    ///
    /// This will write the note data into the buffer in the ELF
    /// format.  Returns both the `Notes` and the remaining space if
    /// successful.
    ///
    /// # Errors
    ///
    /// The only error that can occur is if the notes don't fit into
    /// the provided memory.
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate elf_utils;
    ///
    /// use byteorder::LittleEndian;
    /// use core::convert::TryFrom;
    /// use elf_utils::note::NoteData;
    /// use elf_utils::note::Notes;
    ///
    /// const NOTE_1_NAME: [u8; 8] = [
    ///     0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
    /// ];
    /// const NOTE_1_DESC: [u8; 4] = [
    ///     0x92, 0xd6, 0x13, 0x00
    /// ];
    /// const NOTE_2_NAME: [u8; 8] = [
    ///     0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
    /// ];
    /// const NOTE_2_DESC: [u8; 4] = [
    ///     0x00, 0x00, 0x00, 0x00
    /// ];
    /// const NOTE_3_NAME: [u8; 8] = [
    ///     0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
    /// ];
    /// const NOTE_3_DESC: [u8; 4] = [
    ///     0x00, 0x00, 0x00, 0x00
    /// ];
    /// const NOTES_CONTENTS: [NoteData<'static>; 3] = [
    ///     NoteData { kind: 1, name: &NOTE_1_NAME, desc: &NOTE_1_DESC },
    ///     NoteData { kind: 4, name: &NOTE_2_NAME, desc: &NOTE_2_DESC },
    ///     NoteData { kind: 2, name: &NOTE_3_NAME, desc: &NOTE_3_DESC },
    /// ];
    ///
    /// let mut buf = [0; 80];
    /// let res: Result<(Notes<'_, LittleEndian>, &'_ mut [u8]), ()> =
    ///     Notes::create_split(&mut buf[0..],
    ///                         NOTES_CONTENTS.iter().map(|x| *x));
    /// let (notes, buf) = res.unwrap();
    ///
    /// assert_eq!(buf.len(), 8);
    ///
    /// let mut iter = notes.iter();
    ///
    /// assert_eq!(iter.next(), Some(NoteData { kind: 1, name: &NOTE_1_NAME,
    ///                                         desc: &NOTE_1_DESC }));
    /// assert_eq!(iter.next(), Some(NoteData { kind: 4, name: &NOTE_2_NAME,
    ///                                         desc: &NOTE_2_DESC }));
    /// assert_eq!(iter.next(), Some(NoteData { kind: 2, name: &NOTE_3_NAME,
    ///                                         desc: &NOTE_3_DESC }));
    /// assert_eq!(iter.next(), None);
    /// ```
    #[inline]
    pub fn create_split<I>(buf: &'a mut [u8], notes: I) ->
        Result<(Notes<'a, B>, &'a mut [u8]), ()>
        where I: Iterator<Item = NoteData<'a>>,
              B: ByteOrder {
        let byteorder: PhantomData<B> = PhantomData;

        match create_split_raw(buf, notes, byteorder) {
            Ok((note, rest)) => Ok((Notes { byteorder: byteorder,
                                            data: note }, rest)),
            Err(err) => Err(err)
        }
    }

    /// Attempt to create a `Notes` in `buf` containing the note objects
    /// in `notes` (see [create_split](Notes::create_split)).
    ///
    /// This will write the note data into the buffer in the ELF
    /// format.
    ///
    /// # Errors
    ///
    /// The only error that can occur is if the notes don't fit into
    /// the provided memory.
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate elf_utils;
    ///
    /// use byteorder::LittleEndian;
    /// use core::convert::TryFrom;
    /// use elf_utils::note::NoteData;
    /// use elf_utils::note::Notes;
    ///
    /// const NOTE_1_NAME: [u8; 8] = [
    ///     0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
    /// ];
    /// const NOTE_1_DESC: [u8; 4] = [
    ///     0x92, 0xd6, 0x13, 0x00
    /// ];
    /// const NOTE_2_NAME: [u8; 8] = [
    ///     0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
    /// ];
    /// const NOTE_2_DESC: [u8; 4] = [
    ///     0x00, 0x00, 0x00, 0x00
    /// ];
    /// const NOTE_3_NAME: [u8; 8] = [
    ///     0x46, 0x72, 0x65, 0x65, 0x42, 0x53, 0x44, 0x00
    /// ];
    /// const NOTE_3_DESC: [u8; 4] = [
    ///     0x00, 0x00, 0x00, 0x00
    /// ];
    /// const NOTES_CONTENTS: [NoteData<'static>; 3] = [
    ///     NoteData { kind: 1, name: &NOTE_1_NAME, desc: &NOTE_1_DESC },
    ///     NoteData { kind: 4, name: &NOTE_2_NAME, desc: &NOTE_2_DESC },
    ///     NoteData { kind: 2, name: &NOTE_3_NAME, desc: &NOTE_3_DESC },
    /// ];
    ///
    /// let mut buf = [0; 80];
    /// let notes: Notes<'_, LittleEndian> =
    ///     Notes::create(&mut buf[0..], NOTES_CONTENTS.iter().map(|x| *x))
    ///     .unwrap();
    /// let mut iter = notes.iter();
    ///
    /// assert_eq!(iter.next(), Some(NoteData { kind: 1, name: &NOTE_1_NAME,
    ///                                         desc: &NOTE_1_DESC }));
    /// assert_eq!(iter.next(), Some(NoteData { kind: 4, name: &NOTE_2_NAME,
    ///                                         desc: &NOTE_2_DESC }));
    /// assert_eq!(iter.next(), Some(NoteData { kind: 2, name: &NOTE_3_NAME,
    ///                                         desc: &NOTE_3_DESC }));
    /// assert_eq!(iter.next(), None);
    /// ```
    #[inline]
    pub fn create<I>(buf: &'a mut [u8], notes: I) -> Result<Notes<'a, B>, ()>
        where I: Iterator<Item = NoteData<'a>>,
              B: ByteOrder {
        let byteorder: PhantomData<B> = PhantomData;

        match Self::create_split(buf, notes) {
            Ok((notes, rest)) => Ok(notes),
            Err(err) => Err(err)
        }
    }

    /// Get an iterator over this `Notes`.
    #[inline]
    pub fn iter(&self) -> NotesIter<'a, B> {
        NotesIter { byteorder: PhantomData, data: self.data, idx: 0 }
    }
}

impl<'a, B> NotesMut<'a, B>
    where B: ByteOrder {
    /// Attempt to create a `NotesMut` in `buf` containing the note objects
    /// in `notes`.  Returns both the `Notes` and the remaining space
    /// if successful.
    ///
    /// # Errors
    ///
    /// The only error that can occur is if the notes don't fit into
    /// the provided memory.
    #[inline]
    pub fn create_split<I>(buf: &'a mut [u8], notes: I) ->
        Result<(NotesMut<'a, B>, &'a mut [u8]), ()>
        where I: Iterator<Item = NoteData<'a>>,
              B: ByteOrder {
        let byteorder: PhantomData<B> = PhantomData;

        match create_split_raw(buf, notes, byteorder) {
            Ok((note, rest)) => Ok((NotesMut { byteorder: byteorder,
                                                  data: note }, rest)),
            Err(err) => Err(err)
        }
    }

    /// Attempt to create a `NotesMut` in `buf` containing the note objects
    /// in `notes` (see `create_split`).
    #[inline]
    pub fn create<I>(buf: &'a mut [u8], notes: I) ->
        Result<NotesMut<'a, B>, ()>
        where I: Iterator<Item = NoteData<'a>>,
              B: ByteOrder {
        let byteorder: PhantomData<B> = PhantomData;

        match Self::create_split(buf, notes) {
            Ok((notes, rest)) => Ok(notes),
            Err(err) => Err(err)
        }
    }

    /// Get an iterator over this `Notes`.
    #[inline]
    pub fn iter(&'a self) -> NotesIter<'a, B> {
        NotesIter { byteorder: PhantomData, data: self.data, idx: 0 }
    }
}

impl<'a, B> TryFrom<&'a [u8]> for Notes<'a, B>
    where B: ByteOrder {
    type Error = ();

    #[inline]
    fn try_from(data: &'a [u8]) -> Result<Notes<'a, B>, Self::Error> {
        let byteorder: PhantomData<B> = PhantomData;

        if check(data, byteorder) {
            Ok(Notes { byteorder: byteorder, data: data })
        } else {
            Err(())
        }
    }
}

impl<'a, B> TryFrom<&'a mut [u8]> for Notes<'a, B>
    where B: ByteOrder {
    type Error = ();

    #[inline]
    fn try_from(data: &'a mut [u8]) -> Result<Notes<'a, B>, Self::Error> {
        let byteorder: PhantomData<B> = PhantomData;

        if check(data, byteorder) {
            Ok(Notes { byteorder: byteorder, data: data })
        } else {
            Err(())
        }
    }
}

impl<'a, B> TryFrom<&'a mut [u8]> for NotesMut<'a, B>
    where B: ByteOrder {
    type Error = ();

    #[inline]
    fn try_from(data: &'a mut [u8]) -> Result<NotesMut<'a, B>, Self::Error> {
        let byteorder: PhantomData<B> = PhantomData;

        if check(data, byteorder) {
            Ok(NotesMut { byteorder: byteorder, data: data })
        } else {
            Err(())
        }
    }
}

impl<'a, B> Iterator for NotesIter<'a, B>
    where B: ByteOrder {
    type Item = NoteData<'a>;

    fn next(&mut self) -> Option<NoteData<'a>> {
        let len = self.data.len();
        let start = self.idx;

        match get_size(&self.data[start..], self.byteorder) {
            Some(size) => {
                let buf = &self.data[start .. start + size];

                self.idx += size;

                Some(project(buf, self.byteorder))
            },
            None => None
        }
    }
}

impl<'a, B> FusedIterator for NotesIter<'a, B> where B: ByteOrder {}
