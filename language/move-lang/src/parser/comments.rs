// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{diag, errors::new::Diagnostics};
use codespan::{ByteIndex, Span};
use move_ir_types::location::*;
use std::{collections::BTreeMap, iter::Peekable, str::Chars};

/// Types to represent comments.
pub type CommentMap = BTreeMap<&'static str, MatchedFileCommentMap>;
pub type MatchedFileCommentMap = BTreeMap<ByteIndex, String>;
pub type FileCommentMap = BTreeMap<Span, String>;

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

fn verify_string(fname: &'static str, string: &str) -> Result<(), Diagnostics> {
    match string
        .chars()
        .enumerate()
        .find(|(_, c)| !is_permitted_char(*c))
    {
        None => Ok(()),
        Some((idx, chr)) => {
            let span = Span::new(ByteIndex(idx as u32), ByteIndex(idx as u32));
            let loc = Loc::new(fname, span);
            let msg = format!(
                "Invalid character '{}' found when reading file. Only ASCII printable characters, \
                 tabs (\\t), and line endings (\\n) are permitted.",
                chr
            );
            Err(Diagnostics::from(vec![diag!(
                Syntax::InvalidCharacter,
                (loc, msg)
            )]))
        }
    }
}

/// Strips line and block comments from input source, and collects documentation comments,
/// putting them into a map indexed by the span of the comment region. Comments in the original
/// source will be replaced by spaces, such that positions of source items stay unchanged.
/// Block comments can be nested.
///
/// Documentation comments are comments which start with
/// `///` or `/**`, but not `////` or `/***`. The actually comment delimiters
/// (`/// .. <newline>` and `/** .. */`) will be not included in extracted comment string. The
/// span in the returned map, however, covers the whole region of the comment, including the
/// delimiters.
fn strip_comments(
    fname: &'static str,
    input: &str,
) -> Result<(String, FileCommentMap), Diagnostics> {
    const SLASH: char = '/';
    const SPACE: char = ' ';
    const STAR: char = '*';
    const QUOTE: char = '"';
    const BACKSLASH: char = '\\';

    enum State {
        Source,
        String,
        LineComment,
        BlockComment,
    }

    let mut source = String::with_capacity(input.len());
    let mut comment_map = FileCommentMap::new();

    let mut state = State::Source;
    let mut pos = 0;
    let mut comment_start_pos = 0;
    let mut comment = String::new();
    let mut block_nest = 0;

    let next_is =
        |peekable: &mut Peekable<Chars>, chr| peekable.peek().map(|c| *c == chr).unwrap_or(false);

    let mut commit_comment = |state, start_pos, end_pos, content: String| match state {
        State::BlockComment if !content.starts_with('*') || content.starts_with("**") => {}
        State::LineComment if !content.starts_with('/') || content.starts_with("//") => {}
        _ => {
            comment_map.insert(Span::new(start_pos, end_pos), content[1..].to_string());
        }
    };

    let mut char_iter = input.chars().peekable();
    while let Some(chr) = char_iter.next() {
        match state {
            // Strings
            State::Source if chr == QUOTE => {
                source.push(chr);
                pos += 1;
                state = State::String;
            }
            State::String => {
                source.push(chr);
                pos += 1;
                if chr == BACKSLASH {
                    // Skip over the escaped character (e.g., a quote or another backslash)
                    if let Some(next) = char_iter.next() {
                        source.push(next);
                        pos += 1;
                    }
                } else if chr == QUOTE {
                    state = State::Source;
                }
            }
            // Line comments
            State::Source if chr == SLASH && next_is(&mut char_iter, SLASH) => {
                // Starting line comment. We do not capture the `//` in the comment.
                char_iter.next();
                source.push(SPACE);
                source.push(SPACE);
                comment_start_pos = pos;
                pos += 2;
                state = State::LineComment;
            }
            State::LineComment if is_permitted_newline_char(chr) => {
                // Ending line comment. The newline will be added to the source.
                commit_comment(state, comment_start_pos, pos, std::mem::take(&mut comment));
                source.push(chr);
                pos += 1;
                state = State::Source;
            }
            State::LineComment => {
                // Continuing line comment.
                source.push(SPACE);
                comment.push(chr);
                pos += 1;
            }

            // Block comments.
            State::Source if chr == SLASH && next_is(&mut char_iter, STAR) => {
                // Starting block comment. We do not capture the `/*` in the comment.
                char_iter.next();
                source.push(SPACE);
                source.push(SPACE);
                comment_start_pos = pos;
                pos += 2;
                state = State::BlockComment;
            }
            State::BlockComment if chr == SLASH && next_is(&mut char_iter, STAR) => {
                // Starting nested block comment.
                char_iter.next();
                source.push(SPACE);
                comment.push(chr);
                pos += 1;
                block_nest += 1;
            }
            State::BlockComment
                if block_nest > 0 && chr == STAR && next_is(&mut char_iter, SLASH) =>
            {
                // Ending nested block comment.
                char_iter.next();
                source.push(SPACE);
                comment.push(chr);
                pos -= 1;
                block_nest -= 1;
            }
            State::BlockComment
                if block_nest == 0 && chr == STAR && next_is(&mut char_iter, SLASH) =>
            {
                // Ending block comment. The `*/` will not be captured and also not part of the
                // source.
                char_iter.next();
                source.push(SPACE);
                source.push(SPACE);
                pos += 2;
                commit_comment(state, comment_start_pos, pos, std::mem::take(&mut comment));
                state = State::Source;
            }
            State::BlockComment => {
                // Continuing block comment.
                source.push(SPACE);
                comment.push(chr);
                pos += 1;
            }
            State::Source => {
                // Continuing regular source.
                source.push(chr);
                pos += 1;
            }
        }
    }
    match state {
        State::LineComment => {
            // We allow the last line to have no line terminator
            commit_comment(state, comment_start_pos, pos, std::mem::take(&mut comment));
        }
        State::BlockComment => {
            if pos > 0 {
                // try to point to last real character
                pos -= 1;
            }
            let loc = Loc::new(fname, Span::new(pos, pos));
            let start_loc = Loc::new(fname, Span::new(comment_start_pos, comment_start_pos + 2));
            let diag = diag!(
                Syntax::InvalidDocComment,
                (loc, "Unclosed block comment"),
                (start_loc, "Unclosed block comment starts here"),
            );
            return Err(Diagnostics::from(vec![diag]));
        }
        State::Source | State::String => {}
    }

    Ok((source, comment_map))
}

// We restrict strings to only ascii visual characters (0x20 <= c <= 0x7E) or a permitted newline
// character--\n--or a tab--\t.
pub(crate) fn strip_comments_and_verify(
    fname: &'static str,
    string: &str,
) -> Result<(String, FileCommentMap), Diagnostics> {
    verify_string(fname, string)?;
    strip_comments(fname, string)
}
