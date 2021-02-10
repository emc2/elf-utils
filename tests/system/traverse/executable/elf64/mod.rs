use crate::data::executable::x86_64::EXPECTED;
use crate::data::executable::x86_64::HEADER_DATA;
use crate::data::executable::x86_64::PATH;
use crate::data::executable::x86_64::PROG_HDR_CONTENTS;
use crate::data::executable::x86_64::SECTION_HDR_CONTENTS_BARE;
use crate::data::executable::x86_64::SECTION_HDR_CONTENTS_STRS;
use crate::system::traverse::traverse_elf_file;
use std::fs::read;

#[test]
fn traverse_test() {
    let data = read(PATH).expect("expected success");
    let data = data.as_slice();

    println!("Read {} bytes\n", data.len());

    traverse_elf_file(data, &HEADER_DATA, Some(&PROG_HDR_CONTENTS),
                      &SECTION_HDR_CONTENTS_BARE, &SECTION_HDR_CONTENTS_STRS,
                      &EXPECTED);

    //assert!(false);
}
