// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{diag, errors::new::Diagnostics, parser::syntax::make_loc};
use move_ir_types::location::*;

#[derive(Default)]
struct Context {
    filename: &'static str,
    start_offset: usize,
    diags: Diagnostics,
}

impl Context {
    fn new(filename: &'static str, start_offset: usize) -> Self {
        Self {
            filename,
            start_offset,
            diags: Diagnostics::new(),
        }
    }

    fn error(&mut self, start: usize, end: usize, err_text: String) {
        let loc = make_loc(
            self.filename,
            self.start_offset + 2 + start, // add 2 for the beginning of the string
            self.start_offset + 2 + end,
        );
        self.diags
            .add(diag!(Syntax::InvalidByteString, (loc, err_text)))
    }

    fn has_diags(&self) -> bool {
        !self.diags.is_empty()
    }

    fn get_diags(self) -> Diagnostics {
        self.diags
    }
}

pub fn decode(loc: Loc, text: &str) -> Result<Vec<u8>, Diagnostics> {
    let filename = loc.file();
    let start_offset = loc.span().start().0 as usize;
    let mut context = Context::new(filename, start_offset);
    let mut buffer = vec![];
    let chars: Vec<_> = text.chars().collect();
    decode_(&mut context, &mut buffer, chars);
    if !context.has_diags() {
        Ok(buffer)
    } else {
        Err(context.get_diags())
    }
}

fn decode_(context: &mut Context, buffer: &mut Vec<u8>, chars: Vec<char>) {
    let len = chars.len();
    let mut i = 0;
    macro_rules! next_char {
        () => {{
            let c = chars[i];
            i += 1;
            c
        }};
    }
    macro_rules! next_char_opt {
        () => {{
            if i < len {
                Some(next_char!())
            } else {
                None
            }
        }};
    }
    while i < len {
        let cur = i;
        let c = next_char!();
        if c != '\\' {
            push(buffer, c);
            continue;
        }

        match next_char!() {
            'n' => push(buffer, '\n'),
            'r' => push(buffer, '\r'),
            't' => push(buffer, '\t'),
            '\\' => push(buffer, '\\'),
            '0' => push(buffer, '\0'),
            '"' => push(buffer, '"'),
            'x' => {
                let d0_opt = next_char_opt!();
                let d1_opt = next_char_opt!();
                let hex = match (d0_opt, d1_opt) {
                    (Some(d0), Some(d1)) => {
                        let mut hex = String::new();
                        hex.push(d0);
                        hex.push(d1);
                        hex
                    }

                    // Unexpected end of text
                    (d0_opt @ Some(_), None) | (d0_opt @ None, None) => {
                        let h = match d0_opt {
                            Some(d0) => format!("{}", d0),
                            None => "".to_string(),
                        };
                        let err_text = format!(
                            "Invalid escape: '\\x{}'. Hex literals are represented by two \
                             symbols: [\\x00-\\xFF].",
                            h
                        );
                        context.error(cur, len, err_text);
                        return;
                    }

                    // There was a second digit but no first?
                    (None, Some(_)) => unreachable!(),
                };
                match hex::decode(hex) {
                    Ok(hex_buffer) => buffer.extend(hex_buffer),
                    Err(hex::FromHexError::InvalidHexCharacter { c, index }) => {
                        let err_text = format!("Invalid hexadecimal character: '{}'", c);
                        context.error(cur + 2 + index, cur + 2 + index, err_text);
                    }
                    Err(_) => unreachable!("ICE unexpected error parsing hex byte string value"),
                }
            }
            c => {
                context.error(cur, cur + 2, format!("Invalid escape sequence: '\\{}'", c));
            }
        }
    }
}

fn push(buffer: &mut Vec<u8>, ch: char) {
    assert!(ch.is_ascii(), "ICE ascii-only support is gated at parsing");
    buffer.extend(vec![ch as u8]);
}
