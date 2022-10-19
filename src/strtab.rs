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
//! use elf_utils::strtab::StrtabError;
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
//! let strtab: Result<Strtab<'_>, StrtabError> =
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
use core::convert::Infallible;
use core::convert::TryFrom;
use core::convert::TryInto;
use core::fmt::Display;
use core::fmt::Formatter;
use core::iter::FusedIterator;
use core::iter::Iterator;
use core::str::from_utf8;
use crate::elf::ElfClass;

#[cfg(feature = "builder")]
use alloc::vec::Vec;
#[cfg(feature = "builder")]
use core::ops::Index;

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
    /// Errors that can occur (typically derived from a `StrtabIdxError`).
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
/// use elf_utils::strtab::StrtabIdxError;
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
/// assert_eq!(strtab.idx(25), Err(StrtabIdxError::OutOfBounds(25)));
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

#[cfg(feature = "builder")]
/// A builder object for [Strtab]s.
#[derive(Clone)]
pub struct StrtabBuilder<'a> {
    strs: Vec<&'a str>
}

#[cfg(feature = "builder")]
/// A map from [StrtabBuilderIdx]es to [Strtab] offsets.
#[derive(Clone)]
pub struct StrtabBuilderIdxMap<Class: ElfClass> {
    map: Vec<Class::Word>
}

#[cfg(feature = "builder")]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StrtabBuilderIdx(usize);

/// Errors that can occur looking up a string in a [Strtab].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StrtabIdxError<'a, Idx> {
    /// Index out of bounds.
    OutOfBounds(Idx),
    /// Error occurred while UTF-8 decoding.
    UTF8Decode(&'a [u8])
}

/// Errors that can occur creating a [Strtab] from raw data.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StrtabError {
    /// First character is not a null character.
    BadFirst,
    /// Last character is not a null character.
    BadLast
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
    pub fn idx<Idx>(&self, idx: Idx) -> Result<&'a str, StrtabIdxError<'a, Idx>>
        where Idx: Clone + TryInto<usize> {
        match idx.clone().try_into() {
            Ok(i) => {
                let len = self.data.len();

                if i < len {
                    let mut end = i;

                    for _ in i .. len {
                        if self.data[end] == 0 {
                            break;
                        }

                        end += 1;
                    }

                    let outbuf = &self.data[i .. end];

                    match from_utf8(outbuf) {
                        Ok(out) => Ok(out),
                        Err(_) => Err(StrtabIdxError::UTF8Decode(outbuf))
                    }
                } else {
                    Err(StrtabIdxError::OutOfBounds(idx))
                }
            },
            Err(_) => Err(StrtabIdxError::OutOfBounds(idx))
        }
    }
}

#[cfg(feature = "builder")]
impl<Class: ElfClass> Index<StrtabBuilderIdx> for StrtabBuilderIdxMap<Class> {
    type Output = Class::Word;

    fn index(&self, index: StrtabBuilderIdx) -> &Class::Word {
        &self.map[index.0]
    }
}

#[cfg(feature = "builder")]
impl<'a> StrtabBuilder<'a> {
    /// Create a new `StrtabBuilder`.
    pub fn new() -> StrtabBuilder<'a> {
        StrtabBuilder { strs: Vec::new() }
    }

    /// Create a new `StrtabBuilder` with a size hint.
    pub fn with_capacity(size: usize) -> StrtabBuilder<'a> {
        StrtabBuilder { strs: Vec::with_capacity(size) }
    }

    /// Add a `&'a str` to this `NotesBuilder`.
    pub fn add(&mut self, str: &'a str) -> StrtabBuilderIdx {
        let idx = self.strs.len();

        self.strs.push(str);

        StrtabBuilderIdx(idx)
    }

    /// Get the size of the memory that will be generated by this
    /// `StrtabBuilder`.
    pub fn size(&self) -> usize {
        let mut out = 1;

        for str in &self.strs {
            out += 1 + str.len();
        }

        out
    }

    pub(crate) fn build_split_with_map<'b, Class>(&self, buf: &'a mut [u8]) ->
        Result<(Strtab<'a>, StrtabBuilderIdxMap<Class>, &'a mut [u8]), ()>
        where Class: ElfClass {
        let len = buf.len();
        let mut idx = 0;
        let mut map: Vec<Class::Word> = Vec::new();

        for str in &self.strs {
            let bytes = str.as_bytes();
            let strlen = bytes.len();

            if idx + strlen + 1 < len {
                buf[idx] = 0;
                idx += 1;

                match idx.try_into() {
                    Ok(idx) => {
                        map.push(idx);
                    },
                    Err(_) => {
                        return Err(());
                    }
                }

                buf[idx .. idx + strlen].clone_from_slice(bytes);
                idx += strlen;
            } else {
                return Err(())
            }
        }

        if idx < len {
            let (data, out) = buf.split_at_mut(idx + 1);

            data[idx] = 0;

            Ok((Strtab { data: data }, StrtabBuilderIdxMap { map: map }, out))
        } else {
            Err(())
        }
    }

    #[inline]
    pub(crate) fn build_with_map<'b, Class>(&self, buf: &'a mut [u8]) ->
        Result<(Strtab<'a>, StrtabBuilderIdxMap<Class>), ()>
        where Class: ElfClass {
        match self.build_split_with_map(buf) {
            Ok((out, map, _)) => Ok((out, map)),
            Err(err) => Err(err)
        }
    }

    #[inline]
    pub fn build_split<'b, Class>(&self, buf: &'a mut [u8]) ->
        Result<(Strtab<'a>, &'a mut [u8]), ()>
        where Class: ElfClass {
        match self.build_split_with_map::<Class>(buf) {
            Ok((out, _, next)) => Ok((out, next)),
            Err(err) => Err(err)
        }
    }

    #[inline]
    pub fn build<'b, Class>(&self, buf: &'a mut [u8]) -> Result<Strtab<'a>, ()>
        where Class: ElfClass  {
        match self.build_split_with_map::<Class>(buf) {
            Ok((out, _, _)) => Ok(out),
            Err(err) => Err(err)
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

            for _ in idx .. len {
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

#[cfg(feature = "builder")]
impl<'a> TryFrom<StrtabBuilderIdx> for usize {
    type Error = Infallible;

    fn try_from(data: StrtabBuilderIdx) -> Result<usize, Self::Error> {
        Ok(data.0)
    }
}

impl<'a> TryFrom<&'a [u8]> for Strtab<'a> {
    type Error = StrtabError;

    /// Check that the first and last bytes are 0, as per the ELF
    /// standard.
    fn try_from(data: &'a [u8]) -> Result<Strtab<'a>, Self::Error> {
        if data[0] != 0 {
            Err(StrtabError::BadFirst)
        } else if data[data.len() - 1] != 0 {
            Err(StrtabError::BadLast)
        } else {
            Ok(Strtab { data: data })
        }
    }
}

impl Display for StrtabError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            StrtabError::BadFirst => write!(f, "first character not null"),
            StrtabError::BadLast => write!(f, "last character not null"),
        }
    }
}

impl<'a, Idx> Display for StrtabIdxError<'a, Idx>
    where Idx: Display {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            StrtabIdxError::OutOfBounds(idx) =>
                write!(f, "index {} out of bounds", idx),
            StrtabIdxError::UTF8Decode(_) =>
                write!(f, "UTF-8 decode error"),
        }
    }
}
