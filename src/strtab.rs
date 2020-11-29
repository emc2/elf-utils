//! ELF string table functionality.
//!
//! This module provides the [Strtab] type which acts as a wrapper
//! around ELF string table data.
//!
//! # Examples
//!
//! A `Strtab` can be created from any slice containing binary data
//! that begins and ends with a zero byte (in accordance with the ELF
//! standard) using the [TryFrom](core::convert::TryFrom) instances:
//!
//! ```
//! extern crate elf_utils;
//!
//! use core::convert::TryFrom;
//! use elf_utils::strtab::Strtab;
//!
//! const STRTAB_DATA: [u8; 25] = [
//!     0,
//!     'n' as u8, 'a' as u8, 'm' as u8, 'e' as u8, '.' as u8, 0,
//!     'V' as u8, 'a' as u8, 'r' as u8, 'i' as u8,
//!     'a' as u8, 'b' as u8, 'l' as u8, 'e' as u8, 0,
//!     'a' as u8, 'b' as u8, 'l' as u8, 'e' as u8, 0,
//!     0,
//!     'x' as u8, 'x' as u8, 0
//! ];
//!
//! let strtab: Result<Strtab<'_>, ()> =
//!     Strtab::try_from(&STRTAB_DATA[0..]);
//!
//! assert!(strtab.is_ok())
//! ```
//!
//! String table indexes can then be converted to `&str`s via the
//! [idx](Strtab::idx) function:
//!
//! ```
//! extern crate elf_utils;
//!
//! use core::convert::TryFrom;
//! use elf_utils::strtab::Strtab;
//!
//! const STRTAB_DATA: [u8; 6] = [
//!     0, 'n' as u8, 'a' as u8, 'm' as u8, 'e' as u8, 0,
//! ];
//!
//! let strtab: Strtab<'_> = Strtab::try_from(&STRTAB_DATA[0..]).unwrap();
//!
//! assert_eq!(strtab.idx(0), Ok(""));
//! assert_eq!(strtab.idx(1), Ok("name"));
//! ```
//!
//! It is also possible to iterate over the strings in a table,
//! obtaining each string's index as well as its value:
//!
//! ```
//! extern crate elf_utils;
//!
//! use core::convert::TryFrom;
//! use elf_utils::strtab::Strtab;
//!
//! const STRTAB_DATA: [u8; 25] = [
//!     0,
//!     'n' as u8, 'a' as u8, 'm' as u8, 'e' as u8, '.' as u8, 0,
//!     'V' as u8, 'a' as u8, 'r' as u8, 'i' as u8,
//!     'a' as u8, 'b' as u8, 'l' as u8, 'e' as u8, 0,
//!     'a' as u8, 'b' as u8, 'l' as u8, 'e' as u8, 0,
//!     0,
//!     'x' as u8, 'x' as u8, 0
//! ];
//!
//! let strtab: Strtab<'_> = Strtab::try_from(&STRTAB_DATA[0..]).unwrap();
//! let mut iter = strtab.iter();
//!
//! assert_eq!(iter.next(), Some((Ok(""), 0)));
//! assert_eq!(iter.next(), Some((Ok("name."), 1)));
//! assert_eq!(iter.next(), Some((Ok("Variable"), 7)));
//! assert_eq!(iter.next(), Some((Ok("able"), 16)));
//! assert_eq!(iter.next(), Some((Ok(""), 21)));
//! assert_eq!(iter.next(), Some((Ok("xx"), 22)));
//! assert_eq!(iter.next(), None);
//! ```
//!
//! A `Strtab` can be created in mutable memory from any iterator over
//! string values using [create](Strtab::create):
//!
//! ```
//! extern crate elf_utils;
//!
//! use core::convert::TryFrom;
//! use elf_utils::strtab::Strtab;
//!
//! const STRTAB_STRS: [&'static str; 5] = [
//!     "name.",
//!     "Variable",
//!     "able",
//!     "",
//!     "xx"
//! ];
//!
//! let mut buf = [0; 25];
//! let strtab: Result<Strtab<'_>, ()> =
//!     Strtab::create(&mut buf[0..], STRTAB_STRS.iter().map(|x| *x));
//!
//! assert!(strtab.is_ok());
//! ```
//!
//! The size of the buffer needed to hold the `Strtab` can be obtained
//! with [required_bytes](Strtab::required_bytes):
//!
//! ```
//! extern crate elf_utils;
//!
//! use core::convert::TryFrom;
//! use elf_utils::strtab::Strtab;
//!
//! const STRTAB_STRS: [&'static str; 5] = [
//!     "name.",
//!     "Variable",
//!     "able",
//!     "",
//!     "xx"
//! ];
//!
//! let required = Strtab::required_bytes(STRTAB_STRS.iter().map(|x| *x));
//!
//! assert_eq!(required, 25);
//! ```
//!
//! The [create_split](Strtab::create_split) variant returns a
//! reference to the remaining space.  This is useful for creating a
//! `Strtab` as part of a larger set of contiguous objects:
//!
//! ```
//! extern crate elf_utils;
//!
//! use core::convert::TryFrom;
//! use elf_utils::strtab::Strtab;
//!
//! const STRTAB_STRS: [&'static str; 5] = [
//!     "name.",
//!     "Variable",
//!     "able",
//!     "",
//!     "xx"
//! ];
//!
//! let mut buf = [0; 30];
//! let (strtab, buf) =
//!     Strtab::create_split(&mut buf[0..],
//!                          STRTAB_STRS.iter().map(|x| *x)).unwrap();
//!
//! assert_eq!(buf.len(), 5);
//! ```
use core::convert::TryFrom;
use core::convert::TryInto;
use core::iter::FusedIterator;
use core::iter::Iterator;
use core::str::from_utf8;

/// Trait for things that can be converted from one type to another
/// with the use of a [Strtab].
///
/// This is typically used with objects such as symbols, section
/// headers, etc. that contain a string index as a name.  It can also
/// be used to convert iterators and other objects to produce data
/// that contains string references.
pub trait WithStrtab<'a> {
    /// Result of conversion.
    type Result;
    /// Errors that can occur (typically derived from a `StrtabError`).
    type Error;

    /// Consume the caller to convert it using `strtab`.
    fn with_strtab(self, strtab: Strtab<'a>) ->
        Result<Self::Result, Self::Error>;
}

/// In-place read-only ELF string table.
///
/// An ELF string table is a contiguous collection of null-terminated
/// strings.  Other ELF structures reference strings in the table by
/// providing an offset into the table, which is converted into a
/// string by taking the null-terminated string starting at the
/// offset.
///
/// A `Strtab` is essentially a 'handle' for raw ELF data.  It can be
/// used to convert a string table index into a string using the
/// [idx](Strtab::idx) function, or iterated over with
/// [iter](Strtab::iter).
///
/// A `Strtab` can be created from raw string table data (including
/// the first and last zero bytes) using the
/// [TryFrom](core::convert::TryFrom) instance.
///
/// New `Strtab`s can be created from an iterator over strings with
/// [create](Strtab::create) or [create_split](Strtab::create_split).
///
/// # Examples
///
/// The following example is adapted from the ELF specification:
/// ```
/// extern crate elf_utils;
///
/// use core::convert::TryFrom;
/// use elf_utils::strtab::Strtab;
/// use elf_utils::strtab::StrtabError;
///
/// const STRTAB_DATA: [u8; 25] = [
///     0,
///     'n' as u8, 'a' as u8, 'm' as u8, 'e' as u8, '.' as u8, 0,
///     'V' as u8, 'a' as u8, 'r' as u8, 'i' as u8,
///     'a' as u8, 'b' as u8, 'l' as u8, 'e' as u8, 0,
///     'a' as u8, 'b' as u8, 'l' as u8, 'e' as u8, 0,
///     0,
///     'x' as u8, 'x' as u8, 0
/// ];
///
/// let strtab: Strtab<'_> = Strtab::try_from(&STRTAB_DATA[0..]).unwrap();
/// let mut iter = strtab.iter();
///
/// assert_eq!(strtab.idx(0), Ok(""));
/// assert_eq!(strtab.idx(1), Ok("name."));
/// assert_eq!(strtab.idx(7), Ok("Variable"));
/// assert_eq!(strtab.idx(11), Ok("able"));
/// assert_eq!(strtab.idx(16), Ok("able"));
/// assert_eq!(strtab.idx(22), Ok("xx"));
/// assert_eq!(strtab.idx(24), Ok(""));
/// assert_eq!(strtab.idx(25), Err(StrtabError::OutOfBounds));
/// ```

#[derive(Copy, Clone)]
pub struct Strtab<'a> {
    data: &'a [u8]
}

/// Iterator for [Strtab]s.
///
/// This iterator produces both the index of a string as well as its
/// value, allowing a reverse string map to be constructed.  Note that
/// this will only iterate over the complete null-terminated strings
/// in the table; a `Strtab` implicitly contains any suffix of one of
/// these strings as well, though these will not be iterated over.
///
/// # Examples
///
/// ```
/// extern crate elf_utils;
///
/// use core::convert::TryFrom;
/// use elf_utils::strtab::Strtab;
///
/// const STRTAB_DATA: [u8; 25] = [
///     0,
///     'n' as u8, 'a' as u8, 'm' as u8, 'e' as u8, '.' as u8, 0,
///     'V' as u8, 'a' as u8, 'r' as u8, 'i' as u8,
///     'a' as u8, 'b' as u8, 'l' as u8, 'e' as u8, 0,
///     'a' as u8, 'b' as u8, 'l' as u8, 'e' as u8, 0,
///     0,
///     'x' as u8, 'x' as u8, 0
/// ];
///
/// let strtab: Strtab<'_> = Strtab::try_from(&STRTAB_DATA[0..]).unwrap();
/// let mut iter = strtab.iter();
///
/// assert_eq!(iter.next(), Some((Ok(""), 0)));
/// assert_eq!(iter.next(), Some((Ok("name."), 1)));
/// assert_eq!(iter.next(), Some((Ok("Variable"), 7)));
/// assert_eq!(iter.next(), Some((Ok("able"), 16)));
/// assert_eq!(iter.next(), Some((Ok(""), 21)));
/// assert_eq!(iter.next(), Some((Ok("xx"), 22)));
/// assert_eq!(iter.next(), None);
/// ```
#[derive(Clone)]
pub struct StrtabIter<'a> {
    /// Raw string table data.
    data: &'a [u8],
    /// Current byte index.
    idx: usize
}

/// Errors that can occur looking up a string in a `Strtab`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StrtabError<'a> {
    /// Index out of bounds.
    OutOfBounds,
    /// Error occurred while UTF-8 decoding.
    UTF8Decode(&'a [u8])
}

impl<'a> Strtab<'a> {
    /// Calculate the number of bytes required to represent all of the
    /// strings in `strs`.
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate elf_utils;
    ///
    /// use core::convert::TryFrom;
    /// use elf_utils::strtab::Strtab;
    ///
    /// const STRTAB_STRS: [&'static str; 5] = [
    ///     "name.",
    ///     "Variable",
    ///     "able",
    ///     "",
    ///     "xx"
    /// ];
    ///
    /// let required = Strtab::required_bytes(STRTAB_STRS.iter().map(|x| *x));
    ///
    /// assert_eq!(required, 25);
    /// ```
    #[inline]
    pub fn required_bytes<S, I>(strs: I) -> usize
        where S: Into<&'a str>,
              I: Iterator<Item = S> {
        let mut len = 1;

        for str in strs {
            len += str.into().as_bytes().len() + 1;
        }

        len
    }

    /// Get an iterator over this `Strtab`.
    ///
    /// The iterator provides both the value of each string as well as
    /// its index.
    #[inline]
    pub fn iter(&self) -> StrtabIter<'a> {
        StrtabIter { data: self.data, idx: (0 as u8).into() }
    }

    /// Attempt to create a `Strtab` in `buf` containing the strings
    /// in `strs`.
    ///
    /// This will write the string table into the buffer in the ELF
    /// format.  Returns both the `Strtab` and the remaining space if
    /// successful.
    ///
    /// # Errors
    ///
    /// The only error that can occur is if the string table doesn't
    /// fit into the provided memory.
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate elf_utils;
    ///
    /// use core::convert::TryFrom;
    /// use elf_utils::strtab::Strtab;
    ///
    /// const STRTAB_STRS: [&'static str; 5] = [
    ///     "name.",
    ///     "Variable",
    ///     "able",
    ///     "",
    ///     "xx"
    /// ];
    ///
    /// let mut buf = [0; 30];
    /// let (strtab, buf) =
    ///     Strtab::create_split(&mut buf[0..],
    ///                          STRTAB_STRS.iter().map(|x| *x)).unwrap();
    ///
    /// assert_eq!(buf.len(), 5);
    ///
    /// let mut iter = strtab.iter();
    ///
    /// assert_eq!(iter.next(), Some((Ok(""), 0)));
    /// assert_eq!(iter.next(), Some((Ok("name."), 1)));
    /// assert_eq!(iter.next(), Some((Ok("Variable"), 7)));
    /// assert_eq!(iter.next(), Some((Ok("able"), 16)));
    /// assert_eq!(iter.next(), Some((Ok(""), 21)));
    /// assert_eq!(iter.next(), Some((Ok("xx"), 22)));
    /// assert_eq!(iter.next(), None);
    /// ```
    pub fn create_split<'b, S, I>(buf: &'a mut [u8], strs: I) ->
        Result<(Strtab<'a>, &'a mut [u8]), ()>
        where S: Into<&'b str>,
              I: Iterator<Item = S> {
        let len = buf.len();
        let mut idx = 0;

        for str in strs {
            let bytes = str.into().as_bytes();
            let strlen = bytes.len();

            if idx + strlen + 1 < len {
                buf[idx] = 0;
                idx += 1;
                buf[idx .. idx + strlen].clone_from_slice(bytes);
                idx += strlen;
            } else {
                return Err(())
            }
        }

        if idx < len {
            let (data, out) = buf.split_at_mut(idx + 1);

            data[idx] = 0;

            Ok((Strtab { data: data }, out))
        } else {
            Err(())
        }
    }

    /// Attempt to create a `Strtab` in `buf` containing the strings
    /// in `strs` (see [create_split](Strtab::create_split)).
    ///
    /// This will write the string table into the buffer in the ELF
    /// format.
    ///
    /// # Errors
    ///
    /// The only error that can occur is if the string table doesn't
    /// fit into the provided memory.
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate elf_utils;
    ///
    /// use core::convert::TryFrom;
    /// use elf_utils::strtab::Strtab;
    ///
    /// const STRTAB_STRS: [&'static str; 5] = [
    ///     "name.",
    ///     "Variable",
    ///     "able",
    ///     "",
    ///     "xx"
    /// ];
    ///
    /// let mut buf = [0; 25];
    /// let strtab: Strtab<'_> =
    ///     Strtab::create(&mut buf[0..],
    ///                    STRTAB_STRS.iter().map(|x| *x)).unwrap();
    ///
    /// let mut iter = strtab.iter();
    ///
    /// assert_eq!(iter.next(), Some((Ok(""), 0)));
    /// assert_eq!(iter.next(), Some((Ok("name."), 1)));
    /// assert_eq!(iter.next(), Some((Ok("Variable"), 7)));
    /// assert_eq!(iter.next(), Some((Ok("able"), 16)));
    /// assert_eq!(iter.next(), Some((Ok(""), 21)));
    /// assert_eq!(iter.next(), Some((Ok("xx"), 22)));
    /// assert_eq!(iter.next(), None);
    /// ```
    #[inline]
    pub fn create<'b, S, I>(buf: &'a mut [u8], strs: I) ->
        Result<Strtab<'a>, ()>
        where S: Into<&'b str>,
              I: Iterator<Item = S> {
        match Self::create_split(buf, strs) {
            Ok((out, _)) => Ok(out),
            Err(err) => Err(err)
        }
    }

    /// Get the length of the underlying data in this `Strtab`.
    ///
    /// This value includes the first and last null characters.
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Get the string at index `idx` in this `Strtab`.
    ///
    /// This is capable of indexing any suffix of a string in the
    /// `Strtab` in addition to the full strings.
    ///
    /// # Errors
    ///
    /// Errors can occur if `idx` is out of bounds, or if a UTF8
    /// decode error occurs.
    pub fn idx<Idx>(&self, idx: Idx) -> Result<&'a str, StrtabError<'a>>
        where Idx: TryInto<usize> {
        match idx.try_into() {
            Ok(idx) => {
                let len = self.data.len();

                if idx < len {
                    let mut end = idx;

                    for i in idx .. len {
                        if self.data[end] == 0 {
                            break;
                        }

                        end += 1;
                    }

                    let outbuf = &self.data[idx .. end];

                    match from_utf8(outbuf) {
                        Ok(out) => Ok(out),
                        Err(_) => Err(StrtabError::UTF8Decode(outbuf))
                    }
                } else {
                    Err(StrtabError::OutOfBounds)
                }
            },
            Err(_) => Err(StrtabError::OutOfBounds)
        }
    }
}

impl<'a> Iterator for StrtabIter<'a> {
    type Item = (Result<&'a str, &'a [u8]>, usize);

    fn next(&mut self) -> Option<(Result<&'a str, &'a [u8]>, usize)> {
        let len = self.data.len();
        let start = self.idx;
        let idx = match start.try_into() {
            Ok(idx) => idx,
            Err(_) => panic!("Integer conversion should not fail")
        };

        if len != idx {
            let mut end = match self.idx.try_into() {
                Ok(end) => end,
                Err(_) => panic!("Integer conversion should not fail")
            };

            for i in idx .. len {
                if self.data[end] == 0 {
                    break;
                }

                end += 1;
            }

            let strbuf = &self.data[idx .. end];

            self.idx = match (end + 1).try_into() {
                Ok(idx) => idx,
                Err(_) => panic!("Integer conversion should not fail")
            };

            match from_utf8(strbuf) {
                Ok(out) => Some((Ok(out), start)),
                Err(_) => Some((Err(strbuf), start))
            }
        } else {
            None
        }
    }
}

impl<'a> FusedIterator for StrtabIter<'a> {}

impl<'a> TryFrom<&'a [u8]> for Strtab<'a> {
    type Error = ();

    /// Check that the first and last bytes are 0, as per the ELF
    /// standard.
    fn try_from(data: &'a [u8]) -> Result<Strtab<'a>, ()> {
        if data[0] == 0 && data[data.len() - 1] == 0 {
            Ok(Strtab { data: data })
        } else {
            Err(())
        }
    }
}
