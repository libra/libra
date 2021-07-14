// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Result};
use codespan::Files;
use codespan_reporting::{
    diagnostic::{Diagnostic, Label},
    term::{
        emit,
        termcolor::{ColorChoice, StandardStream},
        Config,
    },
};
use ir_to_bytecode_syntax::syntax::{self, ParseError};
use move_core_types::account_address::AccountAddress;
use move_ir_types::{ast, location::*};

/// Determine if a character is an allowed eye-visible (printable) character.
///
/// The only allowed printable characters are the printable ascii characters (SPACE through ~) and
/// tabs. All other characters are invalid and we return false.
pub fn is_permitted_printable_char(c: char) -> bool {
    let x = c as u32;
    let is_above_space = x >= 0x20; // Don't allow meta characters
    let is_below_tilde = x <= 0x7E; // Don't allow DEL meta character
    let is_tab = x == 0x09; // Allow tabs
    (is_above_space && is_below_tilde) || is_tab
}

/// Determine if a character is a permitted newline character.
///
/// The only permitted newline character is \n. All others are invalid.
pub fn is_permitted_newline_char(c: char) -> bool {
    let x = c as u32;
    x == 0x0A
}

/// Determine if a character is permitted character.
///
/// A permitted character is either a permitted printable character, or a permitted
/// newline. Any other characters are disallowed from appearing in the file.
pub fn is_permitted_char(c: char) -> bool {
    is_permitted_printable_char(c) || is_permitted_newline_char(c)
}

fn verify_string(string: &str) -> Result<()> {
    string
        .chars()
        .find(|c| !is_permitted_char(*c))
        .map_or(Ok(()), |chr| {
            bail!(
                "Parser Error: invalid character {} found when reading file.\
                 Only ascii printable, tabs (\\t), and \\n line ending characters are permitted.",
                chr
            )
        })
}

fn strip_comments(source: &str) -> String {
    const SLASH: char = '/';
    const SPACE: char = ' ';

    let mut in_comment = false;
    let mut acc = String::with_capacity(source.len());
    let mut char_iter = source.chars().peekable();

    while let Some(chr) = char_iter.next() {
        let at_newline = is_permitted_newline_char(chr);
        let at_or_after_slash_slash =
            in_comment || (chr == SLASH && char_iter.peek().map(|c| *c == SLASH).unwrap_or(false));
        in_comment = !at_newline && at_or_after_slash_slash;
        acc.push(if in_comment { SPACE } else { chr });
    }

    acc
}

// We restrict strings to only ascii visual characters (0x20 <= c <= 0x7E) or a permitted newline
// character--\n--or a tab--\t.
fn strip_comments_and_verify(string: &str) -> Result<String> {
    verify_string(string)?;
    Ok(strip_comments(string))
}

/// Given the raw input of a file, creates a `ScriptOrModule` enum
/// Fails with `Err(_)` if the text cannot be parsed`
pub fn parse_script_or_module(file_name: &'static str, s: &str) -> Result<ast::ScriptOrModule> {
    let stripped_string = &strip_comments_and_verify(s)?;
    syntax::parse_script_or_module_string(file_name, stripped_string)
        .or_else(|e| handle_error(e, s))
}

/// Given the raw input of a file, creates a `Script` struct
/// Fails with `Err(_)` if the text cannot be parsed
pub fn parse_script(file_name: &str, script_str: &str) -> Result<ast::Script> {
    let stripped_string = &strip_comments_and_verify(script_str)?;
    syntax::parse_script_string(file_name, stripped_string)
        .or_else(|e| handle_error(e, stripped_string))
}

/// Given the raw input of a file, creates a single `ModuleDefinition` struct
/// Fails with `Err(_)` if the text cannot be parsed
pub fn parse_module(file_name: &str, modules_str: &str) -> Result<ast::ModuleDefinition> {
    let stripped_string = &strip_comments_and_verify(modules_str)?;
    syntax::parse_module_string(file_name, stripped_string)
        .or_else(|e| handle_error(e, stripped_string))
}

/// Given the raw input of a file, creates a single `Cmd_` struct
/// Fails with `Err(_)` if the text cannot be parsed
pub fn parse_cmd_(
    file_name: &str,
    cmd_str: &str,
    _sender_address: AccountAddress,
) -> Result<ast::Cmd_> {
    let stripped_string = &strip_comments_and_verify(cmd_str)?;
    syntax::parse_cmd_string(file_name, stripped_string)
        .or_else(|e| handle_error(e, stripped_string))
}

fn handle_error<T>(e: syntax::ParseError<Loc, anyhow::Error>, code_str: &str) -> Result<T> {
    let msg = match &e {
        ParseError::InvalidToken { location } => {
            let mut files = Files::new();
            let id = files.add(location.file(), code_str.to_string());
            let lbl = Label::new(id, location.span(), "Invalid Token");
            let error = Diagnostic::new_error("Parser Error", lbl);
            let writer = &mut StandardStream::stderr(ColorChoice::Auto);
            emit(writer, &Config::default(), &files, &error).unwrap();
            "Invalid Token".to_string()
        }
        ParseError::User { error } => {
            println!("{}", error);
            format!("{}", error)
        }
    };
    bail!("ParserError: {}", msg)
}

#[cfg(test)]
mod tests {
    #[test]
    fn verify_character_allowlist() {
        let mut good_chars = (0x20..=0x7E).collect::<Vec<u8>>();
        good_chars.push(0x0A);
        good_chars.push(0x09);

        let mut bad_chars = (0x0..0x09).collect::<Vec<_>>();
        bad_chars.append(&mut (0x0B..=0x1F).collect::<Vec<_>>());
        bad_chars.push(0x7F);

        // Test to make sure that all the characters that are in the allowlist pass.
        {
            let s = std::str::from_utf8(&good_chars)
                .expect("Failed to construct string containing an invalid character. This shouldn't happen.");
            assert!(super::verify_string(s).is_ok());
        }

        // Test to make sure that we fail for all characters not in the allowlist.
        for bad_char in bad_chars {
            good_chars.push(bad_char);
            let s = std::str::from_utf8(&good_chars)
                .expect("Failed to construct string containing an invalid character. This shouldn't happen.");
            assert!(super::verify_string(s).is_err());
            good_chars.pop();
        }
    }

    #[test]
    fn test_strip_comments() {
        let mut good_chars = (0x20..=0x7E).map(|x: u8| x as char).collect::<String>();
        good_chars.push(0x09 as char);
        good_chars.push(0x0A as char);
        good_chars.insert(0, 0x2F as char);
        good_chars.insert(0, 0x2F as char);

        {
            let x = super::strip_comments(&good_chars);
            assert!(x.chars().all(|x| x == ' ' || x == '\t' || x == '\n'));
        }

        // Remove the \n at the end of the line
        good_chars.pop();

        let bad_chars: Vec<u8> = vec![
            0x0B, // VT
            0x0C, // FF
            0x0D, // CR
            0x0D, 0x0A, // CRLF
            0xC2, 0x85, // NEL
            0xE2, 0x80, 0xA8, // LS
            0xE2, 0x80, 0xA9, // PS
            0x1E, // RS
            0x15, // NL
            0x76, // NEWLINE
        ];

        let bad_chars = std::str::from_utf8(&bad_chars).expect(
            "Failed to construct string containing an invalid character. This shouldn't happen.",
        );
        for bad_char in bad_chars.chars() {
            good_chars.push(bad_char);
            good_chars.push('\n');
            good_chars.push('a');
            let x = super::strip_comments(&good_chars);
            assert!(x
                .chars()
                .all(|c| c == ' ' || c == '\t' || c == '\n' || c == 'a'));
            good_chars.pop();
            good_chars.pop();
            good_chars.pop();
        }
    }
}
