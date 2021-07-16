// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use codespan::{ByteIndex, Span};
use move_ir_types::location::*;

use crate::{
    diag,
    errors::new::{Diagnostic, Diagnostics},
    parser::{ast::*, lexer::*},
    shared::*,
};
use std::collections::BTreeMap;

// In the informal grammar comments in this file, Comma<T> is shorthand for:
//      (<T> ",")* <T>?
// Note that this allows an optional trailing comma.

//**************************************************************************************************
// Error Handling
//**************************************************************************************************

fn current_token_error_string(tokens: &Lexer) -> String {
    if tokens.peek() == Tok::EOF {
        "end-of-file".to_string()
    } else {
        format!("'{}'", tokens.content())
    }
}

fn unexpected_token_error(tokens: &Lexer, expected: &str) -> Diagnostic {
    unexpected_token_error_(tokens, tokens.start_loc(), expected)
}

fn unexpected_token_error_(
    tokens: &Lexer,
    expected_start_loc: usize,
    expected: &str,
) -> Diagnostic {
    let unexpected_loc = current_token_loc(tokens);
    let unexpected = current_token_error_string(tokens);
    let expected_loc = if expected_start_loc < tokens.start_loc() {
        make_loc(
            tokens.file_name(),
            expected_start_loc,
            tokens.previous_end_loc(),
        )
    } else {
        unexpected_loc
    };
    diag!(
        Syntax::UnexpectedToken,
        (unexpected_loc, format!("Unexpected {}", unexpected)),
        (expected_loc, format!("Expected {}", expected)),
    )
}

//**************************************************************************************************
// Miscellaneous Utilities
//**************************************************************************************************

pub fn make_loc(file: &'static str, start: usize, end: usize) -> Loc {
    Loc::new(
        file,
        Span::new(ByteIndex(start as u32), ByteIndex(end as u32)),
    )
}

fn current_token_loc(tokens: &Lexer) -> Loc {
    let start_loc = tokens.start_loc();
    make_loc(
        tokens.file_name(),
        start_loc,
        start_loc + tokens.content().len(),
    )
}

fn spanned<T>(file: &'static str, start: usize, end: usize, value: T) -> Spanned<T> {
    Spanned {
        loc: make_loc(file, start, end),
        value,
    }
}

// Check for the specified token and consume it if it matches.
// Returns true if the token matches.
fn match_token(tokens: &mut Lexer, tok: Tok) -> Result<bool, Diagnostic> {
    if tokens.peek() == tok {
        tokens.advance()?;
        Ok(true)
    } else {
        Ok(false)
    }
}

// Check for the specified token and return an error if it does not match.
fn consume_token(tokens: &mut Lexer, tok: Tok) -> Result<(), Diagnostic> {
    consume_token_(tokens, tok, tokens.start_loc(), "")
}

fn consume_token_(
    tokens: &mut Lexer,
    tok: Tok,
    expected_start_loc: usize,
    expected_case: &str,
) -> Result<(), Diagnostic> {
    if tokens.peek() == tok {
        tokens.advance()?;
        Ok(())
    } else {
        let expected = format!("'{}'{}", tok, expected_case);
        Err(unexpected_token_error_(
            tokens,
            expected_start_loc,
            &expected,
        ))
    }
}

// let unexp_loc = current_token_loc(tokens);
// let unexp_msg = format!("Unexpected {}", current_token_error_string(tokens));

// let end_loc = tokens.previous_end_loc();
// let addr_loc = make_loc(tokens.file_name(), start_loc, end_loc);
// let exp_msg = format!("Expected '::' {}", case);
// Err(vec![(unexp_loc, unexp_msg), (addr_loc, exp_msg)])

// Check for the identifier token with specified value and return an error if it does not match.
fn consume_identifier(tokens: &mut Lexer, value: &str) -> Result<(), Diagnostic> {
    if tokens.peek() == Tok::IdentifierValue && tokens.content() == value {
        tokens.advance()
    } else {
        let expected = format!("'{}'", value);
        Err(unexpected_token_error(tokens, &expected))
    }
}

// If the next token is the specified kind, consume it and return
// its source location.
fn consume_optional_token_with_loc(
    tokens: &mut Lexer,
    tok: Tok,
) -> Result<Option<Loc>, Diagnostic> {
    if tokens.peek() == tok {
        let start_loc = tokens.start_loc();
        tokens.advance()?;
        let end_loc = tokens.previous_end_loc();
        Ok(Some(make_loc(tokens.file_name(), start_loc, end_loc)))
    } else {
        Ok(None)
    }
}

// While parsing a list and expecting a ">" token to mark the end, replace
// a ">>" token with the expected ">". This handles the situation where there
// are nested type parameters that result in two adjacent ">" tokens, e.g.,
// "A<B<C>>".
fn adjust_token(tokens: &mut Lexer, end_token: Tok) {
    if tokens.peek() == Tok::GreaterGreater && end_token == Tok::Greater {
        tokens.replace_token(Tok::Greater, 1);
    }
}

// Parse a comma-separated list of items, including the specified starting and
// ending tokens.
fn parse_comma_list<F, R>(
    tokens: &mut Lexer,
    start_token: Tok,
    end_token: Tok,
    parse_list_item: F,
    item_description: &str,
) -> Result<Vec<R>, Diagnostic>
where
    F: Fn(&mut Lexer) -> Result<R, Diagnostic>,
{
    let start_loc = tokens.start_loc();
    consume_token(tokens, start_token)?;
    parse_comma_list_after_start(
        tokens,
        start_loc,
        start_token,
        end_token,
        parse_list_item,
        item_description,
    )
}

// Parse a comma-separated list of items, including the specified ending token, but
// assuming that the starting token has already been consumed.
fn parse_comma_list_after_start<F, R>(
    tokens: &mut Lexer,
    start_loc: usize,
    start_token: Tok,
    end_token: Tok,
    parse_list_item: F,
    item_description: &str,
) -> Result<Vec<R>, Diagnostic>
where
    F: Fn(&mut Lexer) -> Result<R, Diagnostic>,
{
    adjust_token(tokens, end_token);
    if match_token(tokens, end_token)? {
        return Ok(vec![]);
    }
    let mut v = vec![];
    loop {
        if tokens.peek() == Tok::Comma {
            let current_loc = tokens.start_loc();
            let loc = make_loc(tokens.file_name(), current_loc, current_loc);
            return Err(diag!(
                Syntax::UnexpectedToken,
                (loc, format!("Expected {}", item_description))
            ));
        }
        v.push(parse_list_item(tokens)?);
        adjust_token(tokens, end_token);
        if match_token(tokens, end_token)? {
            break Ok(v);
        }
        if !match_token(tokens, Tok::Comma)? {
            let current_loc = tokens.start_loc();
            let loc = make_loc(tokens.file_name(), current_loc, current_loc);
            let loc2 = make_loc(tokens.file_name(), start_loc, start_loc);
            return Err(diag!(
                Syntax::UnexpectedToken,
                (loc, format!("Expected '{}'", end_token)),
                (loc2, format!("To match this '{}'", start_token)),
            ));
        }
        adjust_token(tokens, end_token);
        if match_token(tokens, end_token)? {
            break Ok(v);
        }
    }
}

// Parse a list of items, without specified start and end tokens, and the separator determined by
// the passed function `parse_list_continue`.
fn parse_list<C, F, R>(
    tokens: &mut Lexer,
    mut parse_list_continue: C,
    parse_list_item: F,
) -> Result<Vec<R>, Diagnostic>
where
    C: FnMut(&mut Lexer) -> Result<bool, Diagnostic>,
    F: Fn(&mut Lexer) -> Result<R, Diagnostic>,
{
    let mut v = vec![];
    loop {
        v.push(parse_list_item(tokens)?);
        if !parse_list_continue(tokens)? {
            break Ok(v);
        }
    }
}

//**************************************************************************************************
// Identifiers, Addresses, and Names
//**************************************************************************************************

// Parse an identifier:
//      Identifier = <IdentifierValue>
fn parse_identifier(tokens: &mut Lexer) -> Result<Name, Diagnostic> {
    if tokens.peek() != Tok::IdentifierValue {
        return Err(unexpected_token_error(tokens, "an identifier"));
    }
    let start_loc = tokens.start_loc();
    let id = tokens.content().to_string();
    tokens.advance()?;
    let end_loc = tokens.previous_end_loc();
    Ok(spanned(tokens.file_name(), start_loc, end_loc, id))
}

// Parse a numerical address value
//     AddressBytes = <Number>
fn parse_address_bytes(tokens: &mut Lexer) -> Result<Spanned<AddressBytes>, Diagnostic> {
    let loc = current_token_loc(tokens);
    let addr_res = AddressBytes::parse_str(tokens.content());
    consume_token(tokens, Tok::NumValue)?;
    match addr_res {
        Ok(addr_) => Ok(sp(loc, addr_)),
        Err(msg) => Err(diag!(Syntax::InvalidAddress, (loc, msg))),
    }
}

// Parse the beginning of an access, either an address or an identifier:
//      LeadingNameAccess = <AddressBytes> | <Identifier>
fn parse_leading_name_access(tokens: &mut Lexer) -> Result<LeadingNameAccess, Diagnostic> {
    parse_leading_name_access_(tokens, || "an address or an identifier")
}

// Parse the beginning of an access, either an address or an identifier with a specific description
fn parse_leading_name_access_<'a, F: FnOnce() -> &'a str>(
    tokens: &mut Lexer,
    item_description: F,
) -> Result<LeadingNameAccess, Diagnostic> {
    match tokens.peek() {
        Tok::IdentifierValue => {
            let loc = current_token_loc(tokens);
            let n = parse_identifier(tokens)?;
            Ok(sp(loc, LeadingNameAccess_::Name(n)))
        }
        Tok::NumValue => {
            let sp!(loc, addr) = parse_address_bytes(tokens)?;
            Ok(sp(loc, LeadingNameAccess_::AnonymousAddress(addr)))
        }
        _ => Err(unexpected_token_error(tokens, item_description())),
    }
}

// Parse a variable name:
//      Var = <Identifier>
fn parse_var(tokens: &mut Lexer) -> Result<Var, Diagnostic> {
    Ok(Var(parse_identifier(tokens)?))
}

// Parse a field name:
//      Field = <Identifier>
fn parse_field(tokens: &mut Lexer) -> Result<Field, Diagnostic> {
    Ok(Field(parse_identifier(tokens)?))
}

// Parse a module name:
//      ModuleName = <Identifier>
fn parse_module_name(tokens: &mut Lexer) -> Result<ModuleName, Diagnostic> {
    Ok(ModuleName(parse_identifier(tokens)?))
}

// Parse a module identifier:
//      ModuleIdent = <LeadingNameAccess> "::" <ModuleName>
fn parse_module_ident(tokens: &mut Lexer) -> Result<ModuleIdent, Diagnostic> {
    let start_loc = tokens.start_loc();
    let address = parse_leading_name_access(tokens)?;

    consume_token_(
        tokens,
        Tok::ColonColon,
        start_loc,
        " after an address in a module identifier",
    )?;
    let module = parse_module_name(tokens)?;
    let end_loc = tokens.previous_end_loc();
    let loc = make_loc(tokens.file_name(), start_loc, end_loc);
    Ok(sp(loc, ModuleIdent_ { address, module }))
}

// Parse a module access (a variable, struct type, or function):
//      NameAccessChain = <LeadingNameAccess> ( "::" <Identifier> ( "::" <Identifier> )? )?
fn parse_name_access_chain<'a, F: FnOnce() -> &'a str>(
    tokens: &mut Lexer,
    item_description: F,
) -> Result<NameAccessChain, Diagnostic> {
    let start_loc = tokens.start_loc();
    let access = parse_name_access_chain_(tokens, item_description)?;
    let end_loc = tokens.previous_end_loc();
    Ok(spanned(tokens.file_name(), start_loc, end_loc, access))
}

// Parse a module access with a specific description
fn parse_name_access_chain_<'a, F: FnOnce() -> &'a str>(
    tokens: &mut Lexer,
    item_description: F,
) -> Result<NameAccessChain_, Diagnostic> {
    let start_loc = tokens.start_loc();
    let ln = parse_leading_name_access_(tokens, item_description)?;
    let ln = match ln {
        // A name by itself is a valid access chain
        sp!(_, LeadingNameAccess_::Name(n1)) if tokens.peek() != Tok::ColonColon => {
            return Ok(NameAccessChain_::One(n1))
        }
        ln => ln,
    };

    consume_token_(
        tokens,
        Tok::ColonColon,
        start_loc,
        " after an address in a module access chain",
    )?;
    let n2 = parse_identifier(tokens)?;
    if tokens.peek() != Tok::ColonColon {
        return Ok(NameAccessChain_::Two(ln, n2));
    }
    let ln_n2_loc = make_loc(tokens.file_name(), start_loc, tokens.previous_end_loc());
    consume_token(tokens, Tok::ColonColon)?;
    let n3 = parse_identifier(tokens)?;
    Ok(NameAccessChain_::Three(sp(ln_n2_loc, (ln, n2)), n3))
}

//**************************************************************************************************
// Modifiers
//**************************************************************************************************

struct Modifiers {
    visibility: Option<Visibility>,
    native: Option<Loc>,
}

impl Modifiers {
    fn empty() -> Self {
        Self {
            visibility: None,
            native: None,
        }
    }
}

// Parse module member modifiers: visiblility and native.
// The modifiers are also used for script-functions
//      ModuleMemberModifiers = <ModuleMemberModifier>*
//      ModuleMemberModifier = <Visibility> | "native"
// ModuleMemberModifiers checks for uniqueness, meaning each individual ModuleMemberModifier can
// appear only once
fn parse_module_member_modifiers(tokens: &mut Lexer) -> Result<Modifiers, Diagnostic> {
    let mut mods = Modifiers::empty();
    loop {
        match tokens.peek() {
            Tok::Public => {
                let vis = parse_visibility(tokens)?;
                if let Some(prev_vis) = mods.visibility {
                    let msg = "Duplicate visibility modifier".to_string();
                    let prev_msg = "Visibility modifier previously given here".to_string();
                    return Err(diag!(
                        Declarations::DuplicateItem,
                        (vis.loc().unwrap(), msg),
                        (prev_vis.loc().unwrap(), prev_msg),
                    ));
                }
                mods.visibility = Some(vis)
            }
            Tok::Native => {
                let loc = current_token_loc(tokens);
                tokens.advance()?;
                if let Some(prev_loc) = mods.native {
                    let msg = "Duplicate 'native' modifier".to_string();
                    let prev_msg = "'native' modifier previously given here".to_string();
                    return Err(diag!(
                        Declarations::DuplicateItem,
                        (loc, msg),
                        (prev_loc, prev_msg)
                    ));
                }
                mods.native = Some(loc)
            }
            _ => break,
        }
    }
    Ok(mods)
}

// Parse a function visibility modifier:
//      Visibility = "public" ( "(" "script" | "friend" ")" )?
fn parse_visibility(tokens: &mut Lexer) -> Result<Visibility, Diagnostic> {
    let start_loc = tokens.start_loc();
    consume_token(tokens, Tok::Public)?;
    let sub_public_vis = if match_token(tokens, Tok::LParen)? {
        let sub_token = tokens.peek();
        tokens.advance()?;
        if sub_token != Tok::RParen {
            consume_token(tokens, Tok::RParen)?;
        }
        Some(sub_token)
    } else {
        None
    };
    let end_loc = tokens.previous_end_loc();
    // this loc will cover the span of 'public' or 'public(...)' in entirety
    let loc = make_loc(tokens.file_name(), start_loc, end_loc);
    Ok(match sub_public_vis {
        None => Visibility::Public(loc),
        Some(Tok::Script) => Visibility::Script(loc),
        Some(Tok::Friend) => Visibility::Friend(loc),
        _ => {
            let msg = format!(
                "Invalid visibility modifier. Consider removing it or using one of '{}', '{}', or \
                 '{}'",
                Visibility::PUBLIC,
                Visibility::SCRIPT,
                Visibility::FRIEND
            );
            return Err(diag!(Syntax::UnexpectedToken, (loc, msg)));
        }
    })
}
// Parse an attribute value. Either a value literal or a module access
//      AttributeValue =
//          <Value>
//          | <NameAccessChain>
fn parse_attribute_value(tokens: &mut Lexer) -> Result<AttributeValue, Diagnostic> {
    if let Some(v) = maybe_parse_value(tokens)? {
        return Ok(sp(v.loc, AttributeValue_::Value(v)));
    }

    let ma = parse_name_access_chain(tokens, || "attribute name value")?;
    Ok(sp(ma.loc, AttributeValue_::ModuleAccess(ma)))
}

// Parse a single attribute
//      Attribute =
//          <Identifier>
//          | <Identifier> "=" <AttributeValue>
//          | <Identifier> "(" Comma<Attribute> ")"
fn parse_attribute(tokens: &mut Lexer) -> Result<Attribute, Diagnostic> {
    let start_loc = tokens.start_loc();
    let n = parse_identifier(tokens)?;
    let attr_ = match tokens.peek() {
        Tok::Equal => {
            tokens.advance()?;
            Attribute_::Assigned(n, Box::new(parse_attribute_value(tokens)?))
        }
        Tok::LParen => {
            let args_ = parse_comma_list(
                tokens,
                Tok::LParen,
                Tok::RParen,
                parse_attribute,
                "attribute",
            )?;
            let end_loc = tokens.previous_end_loc();
            Attribute_::Parameterized(n, spanned(tokens.file_name(), start_loc, end_loc, args_))
        }
        _ => Attribute_::Name(n),
    };
    let end_loc = tokens.previous_end_loc();
    Ok(spanned(tokens.file_name(), start_loc, end_loc, attr_))
}

// Parse attributes. Used to annotate a variety of AST nodes
//      Attributes = ("#" "[" Comma<Attribute> "]")*
fn parse_attributes(tokens: &mut Lexer) -> Result<Vec<Attributes>, Diagnostic> {
    let mut attributes_vec = vec![];
    while let Tok::NumSign = tokens.peek() {
        let start_loc = tokens.start_loc();
        tokens.advance()?;
        let attributes_ = parse_comma_list(
            tokens,
            Tok::LBracket,
            Tok::RBracket,
            parse_attribute,
            "attribute",
        )?;
        let end_loc = tokens.previous_end_loc();
        attributes_vec.push(spanned(tokens.file_name(), start_loc, end_loc, attributes_))
    }
    Ok(attributes_vec)
}

//**************************************************************************************************
// Fields and Bindings
//**************************************************************************************************

// Parse a field name optionally followed by a colon and an expression argument:
//      ExpField = <Field> <":" <Exp>>?
fn parse_exp_field(tokens: &mut Lexer) -> Result<(Field, Exp), Diagnostic> {
    let f = parse_field(tokens)?;
    let arg = if match_token(tokens, Tok::Colon)? {
        parse_exp(tokens)?
    } else {
        sp(
            f.loc(),
            Exp_::Name(sp(f.loc(), NameAccessChain_::One(f.0.clone())), None),
        )
    };
    Ok((f, arg))
}

// Parse a field name optionally followed by a colon and a binding:
//      BindField = <Field> <":" <Bind>>?
//
// If the binding is not specified, the default is to use a variable
// with the same name as the field.
fn parse_bind_field(tokens: &mut Lexer) -> Result<(Field, Bind), Diagnostic> {
    let f = parse_field(tokens)?;
    let arg = if match_token(tokens, Tok::Colon)? {
        parse_bind(tokens)?
    } else {
        let v = Var(f.0.clone());
        sp(v.loc(), Bind_::Var(v))
    };
    Ok((f, arg))
}

// Parse a binding:
//      Bind =
//          <Var>
//          | <NameAccessChain> <OptionalTypeArgs> "{" Comma<BindField> "}"
fn parse_bind(tokens: &mut Lexer) -> Result<Bind, Diagnostic> {
    let start_loc = tokens.start_loc();
    if tokens.peek() == Tok::IdentifierValue {
        let next_tok = tokens.lookahead()?;
        if next_tok != Tok::LBrace && next_tok != Tok::Less && next_tok != Tok::ColonColon {
            let v = Bind_::Var(parse_var(tokens)?);
            let end_loc = tokens.previous_end_loc();
            return Ok(spanned(tokens.file_name(), start_loc, end_loc, v));
        }
    }
    // The item description specified here should include the special case above for
    // variable names, because if the current tokens cannot be parsed as a struct name
    // it is possible that the user intention was to use a variable name.
    let ty = parse_name_access_chain(tokens, || "a variable or struct name")?;
    let ty_args = parse_optional_type_args(tokens)?;
    let args = parse_comma_list(
        tokens,
        Tok::LBrace,
        Tok::RBrace,
        parse_bind_field,
        "a field binding",
    )?;
    let end_loc = tokens.previous_end_loc();
    let unpack = Bind_::Unpack(Box::new(ty), ty_args, args);
    Ok(spanned(tokens.file_name(), start_loc, end_loc, unpack))
}

// Parse a list of bindings, which can be zero, one, or more bindings:
//      BindList =
//          <Bind>
//          | "(" Comma<Bind> ")"
//
// The list is enclosed in parenthesis, except that the parenthesis are
// optional if there is a single Bind.
fn parse_bind_list(tokens: &mut Lexer) -> Result<BindList, Diagnostic> {
    let start_loc = tokens.start_loc();
    let b = if tokens.peek() != Tok::LParen {
        vec![parse_bind(tokens)?]
    } else {
        parse_comma_list(
            tokens,
            Tok::LParen,
            Tok::RParen,
            parse_bind,
            "a variable or structure binding",
        )?
    };
    let end_loc = tokens.previous_end_loc();
    Ok(spanned(tokens.file_name(), start_loc, end_loc, b))
}

// Parse a list of bindings for lambda.
//      LambdaBindList =
//          "|" Comma<Bind> "|"
fn parse_lambda_bind_list(tokens: &mut Lexer) -> Result<BindList, Diagnostic> {
    let start_loc = tokens.start_loc();
    let b = parse_comma_list(
        tokens,
        Tok::Pipe,
        Tok::Pipe,
        parse_bind,
        "a variable or structure binding",
    )?;
    let end_loc = tokens.previous_end_loc();
    Ok(spanned(tokens.file_name(), start_loc, end_loc, b))
}

//**************************************************************************************************
// Values
//**************************************************************************************************

// Parse a byte string:
//      ByteString = <ByteStringValue>
fn parse_byte_string(tokens: &mut Lexer) -> Result<Value_, Diagnostic> {
    if tokens.peek() != Tok::ByteStringValue {
        return Err(unexpected_token_error(tokens, "a byte string value"));
    }
    let s = tokens.content();
    let text = s[2..s.len() - 1].to_owned();
    let value_ = if s.starts_with("x\"") {
        Value_::HexString(text)
    } else {
        assert!(s.starts_with("b\""));
        Value_::ByteString(text)
    };
    tokens.advance()?;
    Ok(value_)
}

// Parse a value:
//      Value =
//          "@" <LeadingAccessName>
//          | "true"
//          | "false"
//          | <Number>
//          | <NumberTyped>
//          | <ByteString>
fn maybe_parse_value(tokens: &mut Lexer) -> Result<Option<Value>, Diagnostic> {
    let start_loc = tokens.start_loc();
    let val = match tokens.peek() {
        Tok::AtSign => {
            tokens.advance()?;
            let addr = parse_leading_name_access(tokens)?;
            Value_::Address(addr)
        }
        Tok::True => {
            tokens.advance()?;
            Value_::Bool(true)
        }
        Tok::False => {
            tokens.advance()?;
            Value_::Bool(false)
        }
        Tok::NumValue => {
            //  If the number is followed by "::", parse it as the beginning of an address access
            if let Ok(Tok::ColonColon) = tokens.lookahead() {
                return Ok(None);
            }
            let num = tokens.content().to_owned();
            tokens.advance()?;
            Value_::Num(num)
        }
        Tok::NumTypedValue => {
            let num = tokens.content().to_owned();
            tokens.advance()?;
            Value_::Num(num)
        }

        Tok::ByteStringValue => parse_byte_string(tokens)?,
        _ => return Ok(None),
    };
    let end_loc = tokens.previous_end_loc();
    Ok(Some(spanned(tokens.file_name(), start_loc, end_loc, val)))
}

fn parse_value(tokens: &mut Lexer) -> Result<Value, Diagnostic> {
    Ok(maybe_parse_value(tokens)?.expect("parse_value called with invalid token"))
}

//**************************************************************************************************
// Sequences
//**************************************************************************************************

// Parse a sequence item:
//      SequenceItem =
//          <Exp>
//          | "let" <BindList> (":" <Type>)? ("=" <Exp>)?
fn parse_sequence_item(tokens: &mut Lexer) -> Result<SequenceItem, Diagnostic> {
    let start_loc = tokens.start_loc();
    let item = if match_token(tokens, Tok::Let)? {
        let b = parse_bind_list(tokens)?;
        let ty_opt = if match_token(tokens, Tok::Colon)? {
            Some(parse_type(tokens)?)
        } else {
            None
        };
        if match_token(tokens, Tok::Equal)? {
            let e = parse_exp(tokens)?;
            SequenceItem_::Bind(b, ty_opt, Box::new(e))
        } else {
            SequenceItem_::Declare(b, ty_opt)
        }
    } else {
        let e = parse_exp(tokens)?;
        SequenceItem_::Seq(Box::new(e))
    };
    let end_loc = tokens.previous_end_loc();
    Ok(spanned(tokens.file_name(), start_loc, end_loc, item))
}

// Parse a sequence:
//      Sequence = <UseDecl>* (<SequenceItem> ";")* <Exp>? "}"
//
// Note that this does not include the opening brace of a block but it
// does consume the closing right brace.
fn parse_sequence(tokens: &mut Lexer) -> Result<Sequence, Diagnostic> {
    let mut uses = vec![];
    while tokens.peek() == Tok::Use {
        uses.push(parse_use_decl(vec![], tokens)?);
    }

    let mut seq: Vec<SequenceItem> = vec![];
    let mut last_semicolon_loc = None;
    let mut eopt = None;
    while tokens.peek() != Tok::RBrace {
        let item = parse_sequence_item(tokens)?;
        if tokens.peek() == Tok::RBrace {
            // If the sequence ends with an expression that is not
            // followed by a semicolon, split out that expression
            // from the rest of the SequenceItems.
            match item.value {
                SequenceItem_::Seq(e) => {
                    eopt = Some(Spanned {
                        loc: item.loc,
                        value: e.value,
                    });
                }
                _ => return Err(unexpected_token_error(tokens, "';'")),
            }
            break;
        }
        seq.push(item);
        last_semicolon_loc = Some(current_token_loc(&tokens));
        consume_token(tokens, Tok::Semicolon)?;
    }
    tokens.advance()?; // consume the RBrace
    Ok((uses, seq, last_semicolon_loc, Box::new(eopt)))
}

//**************************************************************************************************
// Expressions
//**************************************************************************************************

// Parse an expression term:
//      Term =
//          "break"
//          | "continue"
//          | <NameExp>
//          | <Value>
//          | "(" Comma<Exp> ")"
//          | "(" <Exp> ":" <Type> ")"
//          | "(" <Exp> "as" <Type> ")"
//          | "{" <Sequence>
fn parse_term(tokens: &mut Lexer) -> Result<Exp, Diagnostic> {
    let start_loc = tokens.start_loc();
    let term = match tokens.peek() {
        Tok::Break => {
            tokens.advance()?;
            Exp_::Break
        }

        Tok::Continue => {
            tokens.advance()?;
            Exp_::Continue
        }

        Tok::IdentifierValue => parse_name_exp(tokens)?,

        Tok::NumValue => {
            // Check if this is a ModuleIdent (in a ModuleAccess).
            if tokens.lookahead()? == Tok::ColonColon {
                parse_name_exp(tokens)?
            } else {
                Exp_::Value(parse_value(tokens)?)
            }
        }

        Tok::AtSign | Tok::True | Tok::False | Tok::NumTypedValue | Tok::ByteStringValue => {
            Exp_::Value(parse_value(tokens)?)
        }

        // "(" Comma<Exp> ")"
        // "(" <Exp> ":" <Type> ")"
        // "(" <Exp> "as" <Type> ")"
        Tok::LParen => {
            let list_loc = tokens.start_loc();
            tokens.advance()?; // consume the LParen
            if match_token(tokens, Tok::RParen)? {
                Exp_::Unit
            } else {
                // If there is a single expression inside the parens,
                // then it may be followed by a colon and a type annotation.
                let e = parse_exp(tokens)?;
                if match_token(tokens, Tok::Colon)? {
                    let ty = parse_type(tokens)?;
                    consume_token(tokens, Tok::RParen)?;
                    Exp_::Annotate(Box::new(e), ty)
                } else if match_token(tokens, Tok::As)? {
                    let ty = parse_type(tokens)?;
                    consume_token(tokens, Tok::RParen)?;
                    Exp_::Cast(Box::new(e), ty)
                } else {
                    if tokens.peek() != Tok::RParen {
                        consume_token(tokens, Tok::Comma)?;
                    }
                    let mut es = parse_comma_list_after_start(
                        tokens,
                        list_loc,
                        Tok::LParen,
                        Tok::RParen,
                        parse_exp,
                        "an expression",
                    )?;
                    if es.is_empty() {
                        e.value
                    } else {
                        es.insert(0, e);
                        Exp_::ExpList(es)
                    }
                }
            }
        }

        // "{" <Sequence>
        Tok::LBrace => {
            tokens.advance()?; // consume the LBrace
            Exp_::Block(parse_sequence(tokens)?)
        }

        Tok::Spec => {
            let spec_block = parse_spec_block(vec![], tokens)?;
            Exp_::Spec(spec_block)
        }

        _ => {
            return Err(unexpected_token_error(tokens, "an expression term"));
        }
    };
    let end_loc = tokens.previous_end_loc();
    Ok(spanned(tokens.file_name(), start_loc, end_loc, term))
}

// Parse a pack, call, or other reference to a name:
//      NameExp =
//          <NameAccessChain> <OptionalTypeArgs> "{" Comma<ExpField> "}"
//          | <NameAccessChain> <OptionalTypeArgs> "(" Comma<Exp> ")"
//          | <NameAccessChain> <OptionalTypeArgs>
fn parse_name_exp(tokens: &mut Lexer) -> Result<Exp_, Diagnostic> {
    let n = parse_name_access_chain(tokens, || {
        panic!("parse_name_exp with something other than a ModuleAccess")
    })?;

    // There's an ambiguity if the name is followed by a "<". If there is no whitespace
    // after the name, treat it as the start of a list of type arguments. Otherwise
    // assume that the "<" is a boolean operator.
    let mut tys = None;
    let start_loc = tokens.start_loc();
    if tokens.peek() == Tok::Less && start_loc == n.loc.span().end().to_usize() {
        let loc = make_loc(tokens.file_name(), start_loc, start_loc);
        tys = parse_optional_type_args(tokens).map_err(|mut diag| {
            let msg = "Perhaps you need a blank space before this '<' operator?";
            diag.add_secondary_label((loc, msg.to_owned()));
            diag
        })?;
    }

    match tokens.peek() {
        // Pack: "{" Comma<ExpField> "}"
        Tok::LBrace => {
            let fs = parse_comma_list(
                tokens,
                Tok::LBrace,
                Tok::RBrace,
                parse_exp_field,
                "a field expression",
            )?;
            Ok(Exp_::Pack(n, tys, fs))
        }

        // Call: "(" Comma<Exp> ")"
        Tok::LParen => {
            let rhs = parse_call_args(tokens)?;
            Ok(Exp_::Call(n, tys, rhs))
        }

        // Other name reference...
        _ => Ok(Exp_::Name(n, tys)),
    }
}

// Parse the arguments to a call: "(" Comma<Exp> ")"
fn parse_call_args(tokens: &mut Lexer) -> Result<Spanned<Vec<Exp>>, Diagnostic> {
    let start_loc = tokens.start_loc();
    let args = parse_comma_list(
        tokens,
        Tok::LParen,
        Tok::RParen,
        parse_exp,
        "a call argument expression",
    )?;
    let end_loc = tokens.previous_end_loc();
    Ok(spanned(tokens.file_name(), start_loc, end_loc, args))
}

// Return true if the current token is one that might occur after an Exp.
// This is needed, for example, to check for the optional Exp argument to
// a return (where "return" is itself an Exp).
fn at_end_of_exp(tokens: &mut Lexer) -> bool {
    matches!(
        tokens.peek(),
        // These are the tokens that can occur after an Exp. If the grammar
        // changes, we need to make sure that these are kept up to date and that
        // none of these tokens can occur at the beginning of an Exp.
        Tok::Else | Tok::RBrace | Tok::RParen | Tok::Comma | Tok::Colon | Tok::Semicolon
    )
}

// Parse an expression:
//      Exp =
//            <LambdaBindList> <Exp>        spec only
//          | <Quantifier>                  spec only
//          | "if" "(" <Exp> ")" <Exp> ("else" <Exp>)?
//          | "while" "(" <Exp> ")" <Exp>
//          | "loop" <Exp>
//          | "return" <Exp>?
//          | "abort" <Exp>
//          | <BinOpExp>
//          | <UnaryExp> "=" <Exp>
fn parse_exp(tokens: &mut Lexer) -> Result<Exp, Diagnostic> {
    let start_loc = tokens.start_loc();
    let exp = match tokens.peek() {
        Tok::Pipe => {
            let bindings = parse_lambda_bind_list(tokens)?;
            let body = Box::new(parse_exp(tokens)?);
            Exp_::Lambda(bindings, body)
        }
        Tok::IdentifierValue if is_quant(tokens) => parse_quant(tokens)?,
        Tok::If => {
            tokens.advance()?;
            consume_token(tokens, Tok::LParen)?;
            let eb = Box::new(parse_exp(tokens)?);
            consume_token(tokens, Tok::RParen)?;
            let et = Box::new(parse_exp(tokens)?);
            let ef = if match_token(tokens, Tok::Else)? {
                Some(Box::new(parse_exp(tokens)?))
            } else {
                None
            };
            Exp_::IfElse(eb, et, ef)
        }
        Tok::While => {
            tokens.advance()?;
            consume_token(tokens, Tok::LParen)?;
            let eb = Box::new(parse_exp(tokens)?);
            consume_token(tokens, Tok::RParen)?;
            let eloop = Box::new(parse_exp(tokens)?);
            Exp_::While(eb, eloop)
        }
        Tok::Loop => {
            tokens.advance()?;
            let eloop = Box::new(parse_exp(tokens)?);
            Exp_::Loop(eloop)
        }
        Tok::Return => {
            tokens.advance()?;
            let e = if at_end_of_exp(tokens) {
                None
            } else {
                Some(Box::new(parse_exp(tokens)?))
            };
            Exp_::Return(e)
        }
        Tok::Abort => {
            tokens.advance()?;
            let e = Box::new(parse_exp(tokens)?);
            Exp_::Abort(e)
        }
        _ => {
            // This could be either an assignment or a binary operator
            // expression.
            let lhs = parse_unary_exp(tokens)?;
            if tokens.peek() != Tok::Equal {
                return parse_binop_exp(tokens, lhs, /* min_prec */ 1);
            }
            tokens.advance()?; // consume the "="
            let rhs = Box::new(parse_exp(tokens)?);
            Exp_::Assign(Box::new(lhs), rhs)
        }
    };
    let end_loc = tokens.previous_end_loc();
    Ok(spanned(tokens.file_name(), start_loc, end_loc, exp))
}

// Get the precedence of a binary operator. The minimum precedence value
// is 1, and larger values have higher precedence. For tokens that are not
// binary operators, this returns a value of zero so that they will be
// below the minimum value and will mark the end of the binary expression
// for the code in parse_binop_exp.
fn get_precedence(token: Tok) -> u32 {
    match token {
        // Reserved minimum precedence value is 1
        Tok::EqualEqualGreater => 2,
        Tok::LessEqualEqualGreater => 2,
        Tok::PipePipe => 3,
        Tok::AmpAmp => 4,
        Tok::EqualEqual => 5,
        Tok::ExclaimEqual => 5,
        Tok::Less => 5,
        Tok::Greater => 5,
        Tok::LessEqual => 5,
        Tok::GreaterEqual => 5,
        Tok::PeriodPeriod => 6,
        Tok::Pipe => 7,
        Tok::Caret => 8,
        Tok::Amp => 9,
        Tok::LessLess => 10,
        Tok::GreaterGreater => 10,
        Tok::Plus => 11,
        Tok::Minus => 11,
        Tok::Star => 12,
        Tok::Slash => 12,
        Tok::Percent => 12,
        _ => 0, // anything else is not a binary operator
    }
}

// Parse a binary operator expression:
//      BinOpExp =
//          <BinOpExp> <BinOp> <BinOpExp>
//          | <UnaryExp>
//      BinOp = (listed from lowest to highest precedence)
//          "==>"                                       spec only
//          | "||"
//          | "&&"
//          | "==" | "!=" | "<" | ">" | "<=" | ">="
//          | ".."                                      spec only
//          | "|"
//          | "^"
//          | "&"
//          | "<<" | ">>"
//          | "+" | "-"
//          | "*" | "/" | "%"
//
// This function takes the LHS of the expression as an argument, and it
// continues parsing binary expressions as long as they have at least the
// specified "min_prec" minimum precedence.
fn parse_binop_exp(tokens: &mut Lexer, lhs: Exp, min_prec: u32) -> Result<Exp, Diagnostic> {
    let mut result = lhs;
    let mut next_tok_prec = get_precedence(tokens.peek());

    while next_tok_prec >= min_prec {
        // Parse the operator.
        let op_start_loc = tokens.start_loc();
        let op_token = tokens.peek();
        tokens.advance()?;
        let op_end_loc = tokens.previous_end_loc();

        let mut rhs = parse_unary_exp(tokens)?;

        // If the next token is another binary operator with a higher
        // precedence, then recursively parse that expression as the RHS.
        let this_prec = next_tok_prec;
        next_tok_prec = get_precedence(tokens.peek());
        if this_prec < next_tok_prec {
            rhs = parse_binop_exp(tokens, rhs, this_prec + 1)?;
            next_tok_prec = get_precedence(tokens.peek());
        }

        let op = match op_token {
            Tok::EqualEqual => BinOp_::Eq,
            Tok::ExclaimEqual => BinOp_::Neq,
            Tok::Less => BinOp_::Lt,
            Tok::Greater => BinOp_::Gt,
            Tok::LessEqual => BinOp_::Le,
            Tok::GreaterEqual => BinOp_::Ge,
            Tok::PipePipe => BinOp_::Or,
            Tok::AmpAmp => BinOp_::And,
            Tok::Caret => BinOp_::Xor,
            Tok::Pipe => BinOp_::BitOr,
            Tok::Amp => BinOp_::BitAnd,
            Tok::LessLess => BinOp_::Shl,
            Tok::GreaterGreater => BinOp_::Shr,
            Tok::Plus => BinOp_::Add,
            Tok::Minus => BinOp_::Sub,
            Tok::Star => BinOp_::Mul,
            Tok::Slash => BinOp_::Div,
            Tok::Percent => BinOp_::Mod,
            Tok::PeriodPeriod => BinOp_::Range,
            Tok::EqualEqualGreater => BinOp_::Implies,
            Tok::LessEqualEqualGreater => BinOp_::Iff,
            _ => panic!("Unexpected token that is not a binary operator"),
        };
        let sp_op = spanned(tokens.file_name(), op_start_loc, op_end_loc, op);

        let start_loc = result.loc.span().start().to_usize();
        let end_loc = tokens.previous_end_loc();
        let e = Exp_::BinopExp(Box::new(result), sp_op, Box::new(rhs));
        result = spanned(tokens.file_name(), start_loc, end_loc, e);
    }

    Ok(result)
}

// Parse a unary expression:
//      UnaryExp =
//          "!" <UnaryExp>
//          | "&mut" <UnaryExp>
//          | "&" <UnaryExp>
//          | "*" <UnaryExp>
//          | "move" <Var>
//          | "copy" <Var>
//          | <DotOrIndexChain>
fn parse_unary_exp(tokens: &mut Lexer) -> Result<Exp, Diagnostic> {
    let start_loc = tokens.start_loc();
    let exp = match tokens.peek() {
        Tok::Exclaim => {
            tokens.advance()?;
            let op_end_loc = tokens.previous_end_loc();
            let op = spanned(tokens.file_name(), start_loc, op_end_loc, UnaryOp_::Not);
            let e = parse_unary_exp(tokens)?;
            Exp_::UnaryExp(op, Box::new(e))
        }
        Tok::AmpMut => {
            tokens.advance()?;
            let e = parse_unary_exp(tokens)?;
            Exp_::Borrow(true, Box::new(e))
        }
        Tok::Amp => {
            tokens.advance()?;
            let e = parse_unary_exp(tokens)?;
            Exp_::Borrow(false, Box::new(e))
        }
        Tok::Star => {
            tokens.advance()?;
            let e = parse_unary_exp(tokens)?;
            Exp_::Dereference(Box::new(e))
        }
        Tok::Move => {
            tokens.advance()?;
            Exp_::Move(parse_var(tokens)?)
        }
        Tok::Copy => {
            tokens.advance()?;
            Exp_::Copy(parse_var(tokens)?)
        }
        _ => {
            return parse_dot_or_index_chain(tokens);
        }
    };
    let end_loc = tokens.previous_end_loc();
    Ok(spanned(tokens.file_name(), start_loc, end_loc, exp))
}

// Parse an expression term optionally followed by a chain of dot or index accesses:
//      DotOrIndexChain =
//          <DotOrIndexChain> "." <Identifier>
//          | <DotOrIndexChain> "[" <Exp> "]"                      spec only
//          | <Term>
fn parse_dot_or_index_chain(tokens: &mut Lexer) -> Result<Exp, Diagnostic> {
    let start_loc = tokens.start_loc();
    let mut lhs = parse_term(tokens)?;
    loop {
        let exp = match tokens.peek() {
            Tok::Period => {
                tokens.advance()?;
                let n = parse_identifier(tokens)?;
                Exp_::Dot(Box::new(lhs), n)
            }
            Tok::LBracket => {
                tokens.advance()?;
                let index = parse_exp(tokens)?;
                let exp = Exp_::Index(Box::new(lhs), Box::new(index));
                consume_token(tokens, Tok::RBracket)?;
                exp
            }
            _ => break,
        };
        let end_loc = tokens.previous_end_loc();
        lhs = spanned(tokens.file_name(), start_loc, end_loc, exp);
    }
    Ok(lhs)
}

// Lookahead to determine whether this is a quantifier. This matches
//
//      ( "exists" | "forall" | "choose" | "min" )
//          <Identifier> ( ":" | <Identifier> ) ...
//
// as a sequence to identify a quantifier. While the <Identifier> after
// the exists/forall would by syntactically sufficient (Move does not
// have affixed identifiers in expressions), we add another token
// of lookahead to keep the result more precise in the presence of
// syntax errors.
fn is_quant(tokens: &mut Lexer) -> bool {
    if !matches!(tokens.content(), "exists" | "forall" | "choose") {
        return false;
    }
    match tokens.lookahead2() {
        Err(_) => false,
        Ok((tok1, tok2)) => {
            tok1 == Tok::IdentifierValue && matches!(tok2, Tok::Colon | Tok::IdentifierValue)
        }
    }
}

// Parses a quantifier expressions, assuming is_quant(tokens) is true.
//
//   <Quantifier> =
//       ( "forall" | "exists" ) <QuantifierBindings> ({ (<Exp>)* })* ("where" <Exp>)? ":" Exp
//     | ( "choose" [ "min" ] ) <QuantifierBind> "where" <Exp>
//   <QuantifierBindings> = <QuantifierBind> ("," <QuantifierBind>)*
//   <QuantifierBind> = <Identifier> ":" <Type> | <Identifier> "in" <Exp>
//
fn parse_quant(tokens: &mut Lexer) -> Result<Exp_, Diagnostic> {
    let start_loc = tokens.start_loc();
    let kind = match tokens.content() {
        "exists" => {
            tokens.advance()?;
            QuantKind_::Exists
        }
        "forall" => {
            tokens.advance()?;
            QuantKind_::Forall
        }
        "choose" => {
            tokens.advance()?;
            match tokens.peek() {
                Tok::IdentifierValue if tokens.content() == "min" => {
                    tokens.advance()?;
                    QuantKind_::ChooseMin
                }
                _ => QuantKind_::Choose,
            }
        }
        _ => unreachable!(),
    };
    let spanned_kind = spanned(
        tokens.file_name(),
        start_loc,
        tokens.previous_end_loc(),
        kind,
    );

    if matches!(kind, QuantKind_::Choose | QuantKind_::ChooseMin) {
        let binding = parse_quant_binding(tokens)?;
        consume_identifier(tokens, "where")?;
        let body = parse_exp(tokens)?;
        return Ok(Exp_::Quant(
            spanned_kind,
            Spanned {
                loc: binding.loc,
                value: vec![binding],
            },
            vec![],
            None,
            Box::new(body),
        ));
    }

    let bindings_start_loc = tokens.start_loc();
    let binds_with_range_list = parse_list(
        tokens,
        |tokens| {
            if tokens.peek() == Tok::Comma {
                tokens.advance()?;
                Ok(true)
            } else {
                Ok(false)
            }
        },
        parse_quant_binding,
    )?;
    let binds_with_range_list = spanned(
        tokens.file_name(),
        bindings_start_loc,
        tokens.previous_end_loc(),
        binds_with_range_list,
    );

    let triggers = if tokens.peek() == Tok::LBrace {
        parse_list(
            tokens,
            |tokens| {
                if tokens.peek() == Tok::LBrace {
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
            |tokens| {
                parse_comma_list(
                    tokens,
                    Tok::LBrace,
                    Tok::RBrace,
                    parse_exp,
                    "a trigger expresssion",
                )
            },
        )?
    } else {
        Vec::new()
    };

    let condition = match tokens.peek() {
        Tok::IdentifierValue if tokens.content() == "where" => {
            tokens.advance()?;
            Some(Box::new(parse_exp(tokens)?))
        }
        _ => None,
    };
    consume_token(tokens, Tok::Colon)?;
    let body = parse_exp(tokens)?;

    Ok(Exp_::Quant(
        spanned_kind,
        binds_with_range_list,
        triggers,
        condition,
        Box::new(body),
    ))
}

// Parses one quantifier binding.
fn parse_quant_binding(tokens: &mut Lexer) -> Result<Spanned<(Bind, Exp)>, Diagnostic> {
    let start_loc = tokens.start_loc();
    let ident = parse_identifier(tokens)?;
    let bind = spanned(
        tokens.file_name(),
        start_loc,
        tokens.previous_end_loc(),
        Bind_::Var(Var(ident)),
    );
    let range = if tokens.peek() == Tok::Colon {
        // This is a quantifier over the full domain of a type.
        // Built `domain<ty>()` expression.
        tokens.advance()?;
        let ty = parse_type(tokens)?;
        make_builtin_call(ty.loc, "$spec_domain", Some(vec![ty]), vec![])
    } else {
        // This is a quantifier over a value, like a vector or a range.
        consume_identifier(tokens, "in")?;
        parse_exp(tokens)?
    };
    let end_loc = tokens.previous_end_loc();
    Ok(spanned(
        tokens.file_name(),
        start_loc,
        end_loc,
        (bind, range),
    ))
}

fn make_builtin_call(loc: Loc, name: &str, type_args: Option<Vec<Type>>, args: Vec<Exp>) -> Exp {
    let maccess = sp(loc, NameAccessChain_::One(sp(loc, name.to_string())));
    sp(loc, Exp_::Call(maccess, type_args, sp(loc, args)))
}

//**************************************************************************************************
// Types
//**************************************************************************************************

// Parse a Type:
//      Type =
//          <NameAccessChain> ("<" Comma<Type> ">")?
//          | "&" <Type>
//          | "&mut" <Type>
//          | "|" Comma<Type> "|" Type   (spec only)
//          | "(" Comma<Type> ")"
fn parse_type(tokens: &mut Lexer) -> Result<Type, Diagnostic> {
    let start_loc = tokens.start_loc();
    let t = match tokens.peek() {
        Tok::LParen => {
            let mut ts = parse_comma_list(tokens, Tok::LParen, Tok::RParen, parse_type, "a type")?;
            match ts.len() {
                0 => Type_::Unit,
                1 => ts.pop().unwrap().value,
                _ => Type_::Multiple(ts),
            }
        }
        Tok::Amp => {
            tokens.advance()?;
            let t = parse_type(tokens)?;
            Type_::Ref(false, Box::new(t))
        }
        Tok::AmpMut => {
            tokens.advance()?;
            let t = parse_type(tokens)?;
            Type_::Ref(true, Box::new(t))
        }
        Tok::Pipe => {
            let args = parse_comma_list(tokens, Tok::Pipe, Tok::Pipe, parse_type, "a type")?;
            let result = parse_type(tokens)?;
            return Ok(spanned(
                tokens.file_name(),
                start_loc,
                tokens.previous_end_loc(),
                Type_::Fun(args, Box::new(result)),
            ));
        }
        _ => {
            let tn = parse_name_access_chain(tokens, || "a type name")?;
            let tys = if tokens.peek() == Tok::Less {
                parse_comma_list(tokens, Tok::Less, Tok::Greater, parse_type, "a type")?
            } else {
                vec![]
            };
            Type_::Apply(Box::new(tn), tys)
        }
    };
    let end_loc = tokens.previous_end_loc();
    Ok(spanned(tokens.file_name(), start_loc, end_loc, t))
}

// Parse an optional list of type arguments.
//    OptionalTypeArgs = "<" Comma<Type> ">" | <empty>
fn parse_optional_type_args(tokens: &mut Lexer) -> Result<Option<Vec<Type>>, Diagnostic> {
    if tokens.peek() == Tok::Less {
        Ok(Some(parse_comma_list(
            tokens,
            Tok::Less,
            Tok::Greater,
            parse_type,
            "a type",
        )?))
    } else {
        Ok(None)
    }
}

fn token_to_ability(token: Tok, content: &str) -> Option<Ability_> {
    match (token, content) {
        (Tok::Copy, _) => Some(Ability_::Copy),
        (Tok::IdentifierValue, Ability_::DROP) => Some(Ability_::Drop),
        (Tok::IdentifierValue, Ability_::STORE) => Some(Ability_::Store),
        (Tok::IdentifierValue, Ability_::KEY) => Some(Ability_::Key),
        _ => None,
    }
}

// Parse a type ability
//      Ability =
//          <Copy>
//          | "drop"
//          | "store"
//          | "key"
fn parse_ability(tokens: &mut Lexer) -> Result<Ability, Diagnostic> {
    let loc = current_token_loc(tokens);
    match token_to_ability(tokens.peek(), tokens.content()) {
        Some(ability) => {
            tokens.advance()?;
            Ok(sp(loc, ability))
        }
        None => {
            let msg = format!(
                "Unexpected {}. Expected a type ability, one of: 'copy', 'drop', 'store', or 'key'",
                current_token_error_string(tokens)
            );
            Err(diag!(Syntax::UnexpectedToken, (loc, msg),))
        }
    }
}

// Parse a type parameter:
//      TypeParameter =
//          <Identifier> <Constraint>?
//      Constraint =
//          ":" <Ability> (+ <Ability>)*
fn parse_type_parameter(tokens: &mut Lexer) -> Result<(Name, Vec<Ability>), Diagnostic> {
    let n = parse_identifier(tokens)?;

    let ability_constraints = if match_token(tokens, Tok::Colon)? {
        parse_list(
            tokens,
            |tokens| match tokens.peek() {
                Tok::Plus => {
                    tokens.advance()?;
                    Ok(true)
                }
                Tok::Greater | Tok::Comma => Ok(false),
                _ => Err(unexpected_token_error(
                    tokens,
                    &format!(
                        "one of: '{}', '{}', or '{}'",
                        Tok::Plus,
                        Tok::Greater,
                        Tok::Comma
                    ),
                )),
            },
            parse_ability,
        )?
    } else {
        vec![]
    };
    Ok((n, ability_constraints))
}

// Parse type parameter with optional phantom declaration:
//   TypeParameterWithPhantomDecl = "phantom"? <TypeParameter>
fn parse_type_parameter_with_phantom_decl(
    tokens: &mut Lexer,
) -> Result<StructTypeParameter, Diagnostic> {
    let is_phantom = if tokens.peek() == Tok::IdentifierValue && tokens.content() == "phantom" {
        tokens.advance()?;
        true
    } else {
        false
    };
    let (name, constraints) = parse_type_parameter(tokens)?;
    Ok(StructTypeParameter {
        is_phantom,
        name,
        constraints,
    })
}

// Parse optional type parameter list.
//    OptionalTypeParameters = "<" Comma<TypeParameter> ">" | <empty>
fn parse_optional_type_parameters(
    tokens: &mut Lexer,
) -> Result<Vec<(Name, Vec<Ability>)>, Diagnostic> {
    if tokens.peek() == Tok::Less {
        parse_comma_list(
            tokens,
            Tok::Less,
            Tok::Greater,
            parse_type_parameter,
            "a type parameter",
        )
    } else {
        Ok(vec![])
    }
}

// Parse optional struct type parameters:
//    StructTypeParameter = "<" Comma<TypeParameterWithPhantomDecl> ">" | <empty>
fn parse_struct_type_parameters(
    tokens: &mut Lexer,
) -> Result<Vec<StructTypeParameter>, Diagnostic> {
    if tokens.peek() == Tok::Less {
        parse_comma_list(
            tokens,
            Tok::Less,
            Tok::Greater,
            parse_type_parameter_with_phantom_decl,
            "a type parameter",
        )
    } else {
        Ok(vec![])
    }
}

//**************************************************************************************************
// Functions
//**************************************************************************************************

// Parse a function declaration:
//      FunctionDecl =
//          "fun"
//          <FunctionDefName> "(" Comma<Parameter> ")"
//          (":" <Type>)?
//          ("acquires" <NameAccessChain> ("," <NameAccessChain>)*)?
//          ("{" <Sequence> "}" | ";")
//
fn parse_function_decl(
    attributes: Vec<Attributes>,
    start_loc: usize,
    modifiers: Modifiers,
    tokens: &mut Lexer,
) -> Result<Function, Diagnostic> {
    let Modifiers { visibility, native } = modifiers;

    // "fun" <FunctionDefName>
    consume_token(tokens, Tok::Fun)?;
    let name = FunctionName(parse_identifier(tokens)?);
    let type_parameters = parse_optional_type_parameters(tokens)?;

    // "(" Comma<Parameter> ")"
    let parameters = parse_comma_list(
        tokens,
        Tok::LParen,
        Tok::RParen,
        parse_parameter,
        "a function parameter",
    )?;

    // (":" <Type>)?
    let return_type = if match_token(tokens, Tok::Colon)? {
        parse_type(tokens)?
    } else {
        sp(name.loc(), Type_::Unit)
    };

    // ("acquires" (<NameAccessChain> ",")* <NameAccessChain> ","?
    let mut acquires = vec![];
    if match_token(tokens, Tok::Acquires)? {
        let follows_acquire = |tok| matches!(tok, Tok::Semicolon | Tok::LBrace);
        loop {
            acquires.push(parse_name_access_chain(tokens, || {
                "a resource struct name"
            })?);
            if follows_acquire(tokens.peek()) {
                break;
            }
            consume_token(tokens, Tok::Comma)?;
            if follows_acquire(tokens.peek()) {
                break;
            }
        }
    }

    let body = match native {
        Some(loc) => {
            consume_token(tokens, Tok::Semicolon)?;
            sp(loc, FunctionBody_::Native)
        }
        _ => {
            let start_loc = tokens.start_loc();
            consume_token(tokens, Tok::LBrace)?;
            let seq = parse_sequence(tokens)?;
            let end_loc = tokens.previous_end_loc();
            sp(
                make_loc(tokens.file_name(), start_loc, end_loc),
                FunctionBody_::Defined(seq),
            )
        }
    };

    let signature = FunctionSignature {
        type_parameters,
        parameters,
        return_type,
    };

    let loc = make_loc(tokens.file_name(), start_loc, tokens.previous_end_loc());
    Ok(Function {
        attributes,
        loc,
        visibility: visibility.unwrap_or(Visibility::Internal),
        signature,
        acquires,
        name,
        body,
    })
}

// Parse a function parameter:
//      Parameter = <Var> ":" <Type>
fn parse_parameter(tokens: &mut Lexer) -> Result<(Var, Type), Diagnostic> {
    let v = parse_var(tokens)?;
    consume_token(tokens, Tok::Colon)?;
    let t = parse_type(tokens)?;
    Ok((v, t))
}

//**************************************************************************************************
// Structs
//**************************************************************************************************

// Parse a struct definition:
//      StructDecl =
//          "struct" <StructDefName> ("has" <Ability> (, <Ability>)+)?
//          ("{" Comma<FieldAnnot> "}" | ";")
//      StructDefName =
//          <Identifier> <OptionalTypeParameters>
fn parse_struct_decl(
    attributes: Vec<Attributes>,
    start_loc: usize,
    modifiers: Modifiers,
    tokens: &mut Lexer,
) -> Result<StructDefinition, Diagnostic> {
    let Modifiers { visibility, native } = modifiers;
    if let Some(vis) = visibility {
        let msg = format!(
            "Invalid struct declaration. Structs cannot have visibility modifiers as they are \
             always '{}'",
            Visibility::PUBLIC
        );
        return Err(diag!(Syntax::InvalidModifier, (vis.loc().unwrap(), msg)));
    }

    consume_token(tokens, Tok::Struct)?;

    // <StructDefName>
    let name = StructName(parse_identifier(tokens)?);
    let type_parameters = parse_struct_type_parameters(tokens)?;

    let abilities = if tokens.peek() == Tok::IdentifierValue && tokens.content() == "has" {
        tokens.advance()?;
        parse_list(
            tokens,
            |tokens| match tokens.peek() {
                Tok::Comma => {
                    tokens.advance()?;
                    Ok(true)
                }
                Tok::LBrace | Tok::Semicolon => Ok(false),
                _ => Err(unexpected_token_error(
                    tokens,
                    &format!(
                        "one of: '{}', '{}', or '{}'",
                        Tok::Comma,
                        Tok::LBrace,
                        Tok::Semicolon
                    ),
                )),
            },
            parse_ability,
        )?
    } else {
        vec![]
    };

    let fields = match native {
        Some(loc) => {
            consume_token(tokens, Tok::Semicolon)?;
            StructFields::Native(loc)
        }
        _ => {
            let list = parse_comma_list(
                tokens,
                Tok::LBrace,
                Tok::RBrace,
                parse_field_annot,
                "a field",
            )?;
            StructFields::Defined(list)
        }
    };

    let loc = make_loc(tokens.file_name(), start_loc, tokens.previous_end_loc());
    Ok(StructDefinition {
        attributes,
        loc,
        abilities,
        name,
        type_parameters,
        fields,
    })
}

// Parse a field annotated with a type:
//      FieldAnnot = <DocComments> <Field> ":" <Type>
fn parse_field_annot(tokens: &mut Lexer) -> Result<(Field, Type), Diagnostic> {
    tokens.match_doc_comments();
    let f = parse_field(tokens)?;
    consume_token(tokens, Tok::Colon)?;
    let st = parse_type(tokens)?;
    Ok((f, st))
}

//**************************************************************************************************
// Constants
//**************************************************************************************************

// Parse a constant:
//      ConstantDecl = "const" <Identifier> ":" <Type> "=" <Exp> ";"
fn parse_constant_decl(
    attributes: Vec<Attributes>,
    start_loc: usize,
    modifiers: Modifiers,
    tokens: &mut Lexer,
) -> Result<Constant, Diagnostic> {
    let Modifiers { visibility, native } = modifiers;
    if let Some(vis) = visibility {
        let msg = "Invalid constant declaration. Constants cannot have visibility modifiers as \
                   they are always internal";
        return Err(diag!(Syntax::InvalidModifier, (vis.loc().unwrap(), msg)));
    }
    if let Some(loc) = native {
        let msg = "Invalid constant declaration. 'native' constants are not supported";
        return Err(diag!(Syntax::InvalidModifier, (loc, msg)));
    }
    consume_token(tokens, Tok::Const)?;
    let name = ConstantName(parse_identifier(tokens)?);
    consume_token(tokens, Tok::Colon)?;
    let signature = parse_type(tokens)?;
    consume_token(tokens, Tok::Equal)?;
    let value = parse_exp(tokens)?;
    consume_token(tokens, Tok::Semicolon)?;
    let loc = make_loc(tokens.file_name(), start_loc, tokens.previous_end_loc());
    Ok(Constant {
        attributes,
        loc,
        signature,
        name,
        value,
    })
}

//**************************************************************************************************
// AddressBlock
//**************************************************************************************************

// Parse an address block:
//      AddressBlock =
//          "address" <LeadingNameAccess> (= <AddressBytes>)?
//              ("{" (<Attributes> <Module>)* "}" | ";")
//
// Note that "address" is not a token.
fn parse_address_block(
    attributes: Vec<Attributes>,
    tokens: &mut Lexer,
) -> Result<AddressDefinition, Diagnostic> {
    const UNEXPECTED_TOKEN: &str = "Invalid code unit. Expected 'address', 'module', or 'script'";
    if tokens.peek() != Tok::IdentifierValue {
        let start = tokens.start_loc();
        let end = start + tokens.content().len();
        let loc = make_loc(tokens.file_name(), start, end);
        let msg = format!(
            "{}. Got {}",
            UNEXPECTED_TOKEN,
            current_token_error_string(tokens)
        );
        return Err(diag!(Syntax::UnexpectedToken, (loc, msg)));
    }
    let addr_name = parse_identifier(tokens)?;
    if addr_name.value != "address" {
        let msg = format!("{}. Got '{}'", UNEXPECTED_TOKEN, addr_name.value);
        return Err(diag!(Syntax::UnexpectedToken, (addr_name.loc, msg)));
    }
    let start_loc = tokens.start_loc();
    let addr = parse_leading_name_access(tokens)?;
    let end_loc = tokens.previous_end_loc();
    let loc = make_loc(tokens.file_name(), start_loc, end_loc);

    let addr_value = match tokens.peek() {
        Tok::Equal => {
            tokens.advance()?;
            Some(parse_address_bytes(tokens)?)
        }
        _ => None,
    };

    let modules = match tokens.peek() {
        Tok::Semicolon => {
            tokens.advance()?;
            vec![]
        }
        Tok::LBrace => {
            tokens.advance()?;
            let mut modules = vec![];
            while tokens.peek() != Tok::RBrace {
                let attributes = parse_attributes(tokens)?;
                modules.push(parse_module(attributes, tokens)?);
            }
            consume_token(tokens, Tok::RBrace)?;
            modules
        }
        _ => return Err(unexpected_token_error(tokens, "one of `;` or `{{`")),
    };

    Ok(AddressDefinition {
        attributes,
        loc,
        addr,
        addr_value,
        modules,
    })
}

//**************************************************************************************************
// Friends
//**************************************************************************************************

// Parse a friend declaration:
//      FriendDecl =
//          "friend" <NameAccessChain> ";"
fn parse_friend_decl(
    attributes: Vec<Attributes>,
    tokens: &mut Lexer,
) -> Result<FriendDecl, Diagnostic> {
    let start_loc = tokens.start_loc();
    consume_token(tokens, Tok::Friend)?;
    let friend = parse_name_access_chain(tokens, || "a friend declaration")?;
    consume_token(tokens, Tok::Semicolon)?;
    let loc = make_loc(tokens.file_name(), start_loc, tokens.previous_end_loc());
    Ok(FriendDecl {
        attributes,
        loc,
        friend,
    })
}

//**************************************************************************************************
// Modules
//**************************************************************************************************

// Parse a use declaration:
//      UseDecl =
//          "use" <ModuleIdent> <UseAlias> ";" |
//          "use" <ModuleIdent> :: <UseMember> ";" |
//          "use" <ModuleIdent> :: "{" Comma<UseMember> "}" ";"
fn parse_use_decl(attributes: Vec<Attributes>, tokens: &mut Lexer) -> Result<UseDecl, Diagnostic> {
    consume_token(tokens, Tok::Use)?;
    let ident = parse_module_ident(tokens)?;
    let alias_opt = parse_use_alias(tokens)?;
    let use_ = match (&alias_opt, tokens.peek()) {
        (None, Tok::ColonColon) => {
            consume_token(tokens, Tok::ColonColon)?;
            let sub_uses = match tokens.peek() {
                Tok::LBrace => parse_comma_list(
                    tokens,
                    Tok::LBrace,
                    Tok::RBrace,
                    parse_use_member,
                    "a module member alias",
                )?,
                _ => vec![parse_use_member(tokens)?],
            };
            Use::Members(ident, sub_uses)
        }
        _ => Use::Module(ident, alias_opt.map(ModuleName)),
    };
    consume_token(tokens, Tok::Semicolon)?;
    Ok(UseDecl { attributes, use_ })
}

// Parse an alias for a module member:
//      UseMember = <Identifier> <UseAlias>
fn parse_use_member(tokens: &mut Lexer) -> Result<(Name, Option<Name>), Diagnostic> {
    let member = parse_identifier(tokens)?;
    let alias_opt = parse_use_alias(tokens)?;
    Ok((member, alias_opt))
}

// Parse an 'as' use alias:
//      UseAlias = ("as" <Identifier>)?
fn parse_use_alias(tokens: &mut Lexer) -> Result<Option<Name>, Diagnostic> {
    Ok(if tokens.peek() == Tok::As {
        tokens.advance()?;
        Some(parse_identifier(tokens)?)
    } else {
        None
    })
}

// Parse a module:
//      Module =
//          <DocComments> ( "spec" | "module") (<LeadingNameAccess>::)?<ModuleName> "{"
//              ( <Attributes>
//                  ( <UseDecl> | <FriendDecl> | <SpecBlock> |
//                    <DocComments> <ModuleMemberModifiers>
//                        (<ConstantDecl> | <StructDecl> | <FunctionDecl>) )
//                  )
//              )*
//          "}"
fn parse_module(
    attributes: Vec<Attributes>,
    tokens: &mut Lexer,
) -> Result<ModuleDefinition, Diagnostic> {
    tokens.match_doc_comments();
    let start_loc = tokens.start_loc();

    let is_spec_module = if tokens.peek() == Tok::Spec {
        tokens.advance()?;
        true
    } else {
        consume_token(tokens, Tok::Module)?;
        false
    };
    let sp!(n1_loc, n1_) = parse_leading_name_access(tokens)?;
    let (address, name) = match (n1_, tokens.peek()) {
        (addr_ @ LeadingNameAccess_::AnonymousAddress(_), _)
        | (addr_ @ LeadingNameAccess_::Name(_), Tok::ColonColon) => {
            let addr = sp(n1_loc, addr_);
            consume_token(tokens, Tok::ColonColon)?;
            let name = parse_module_name(tokens)?;
            (Some(addr), name)
        }
        (LeadingNameAccess_::Name(name), _) => (None, ModuleName(name)),
    };
    consume_token(tokens, Tok::LBrace)?;

    let mut members = vec![];
    while tokens.peek() != Tok::RBrace {
        members.push({
            let attributes = parse_attributes(tokens)?;
            match tokens.peek() {
                // Top-level specification constructs
                Tok::Invariant => {
                    tokens.match_doc_comments();
                    ModuleMember::Spec(singleton_module_spec_block(
                        tokens,
                        tokens.start_loc(),
                        attributes,
                        parse_invariant,
                    )?)
                }
                Tok::Spec => {
                    match tokens.lookahead() {
                        Ok(Tok::Fun) | Ok(Tok::Native) => {
                            tokens.match_doc_comments();
                            let start_loc = tokens.start_loc();
                            tokens.advance()?;
                            // Add an extra check for better error message
                            // if old syntax is used
                            if tokens.lookahead2() == Ok((Tok::IdentifierValue, Tok::LBrace)) {
                                return Err(unexpected_token_error(
                                    tokens,
                                    "only 'spec', drop the 'fun' keyword",
                                ));
                            }
                            ModuleMember::Spec(singleton_module_spec_block(
                                tokens,
                                start_loc,
                                attributes,
                                parse_spec_function,
                            )?)
                        }
                        _ => {
                            // Regular spec block
                            ModuleMember::Spec(parse_spec_block(attributes, tokens)?)
                        }
                    }
                }
                // Regular move constructs
                Tok::Use => ModuleMember::Use(parse_use_decl(attributes, tokens)?),
                Tok::Friend => ModuleMember::Friend(parse_friend_decl(attributes, tokens)?),
                _ => {
                    tokens.match_doc_comments();
                    let start_loc = tokens.start_loc();
                    let modifiers = parse_module_member_modifiers(tokens)?;
                    match tokens.peek() {
                        Tok::Const => ModuleMember::Constant(parse_constant_decl(
                            attributes, start_loc, modifiers, tokens,
                        )?),
                        Tok::Fun => ModuleMember::Function(parse_function_decl(
                            attributes, start_loc, modifiers, tokens,
                        )?),
                        Tok::Struct => ModuleMember::Struct(parse_struct_decl(
                            attributes, start_loc, modifiers, tokens,
                        )?),
                        _ => {
                            return Err(unexpected_token_error(
                                tokens,
                                &format!(
                                    "a module member: '{}', '{}', '{}', '{}', '{}', or '{}'",
                                    Tok::Spec,
                                    Tok::Use,
                                    Tok::Friend,
                                    Tok::Const,
                                    Tok::Fun,
                                    Tok::Struct
                                ),
                            ))
                        }
                    }
                }
            }
        })
    }
    consume_token(tokens, Tok::RBrace)?;
    let loc = make_loc(tokens.file_name(), start_loc, tokens.previous_end_loc());
    Ok(ModuleDefinition {
        attributes,
        loc,
        address,
        name,
        is_spec_module,
        members,
    })
}

//**************************************************************************************************
// Scripts
//**************************************************************************************************

// Parse a script:
//      Script =
//          "script" "{"
//              (<Attributes> <UseDecl>)*
//              (<Attributes> <ConstantDecl>)*
//              <Attributes> <DocComments> <ModuleMemberModifiers> <FunctionDecl>
//              (<Attributes> <SpecBlock>)*
//          "}"
fn parse_script(
    script_attributes: Vec<Attributes>,
    tokens: &mut Lexer,
) -> Result<Script, Diagnostic> {
    let start_loc = tokens.start_loc();

    consume_token(tokens, Tok::Script)?;
    consume_token(tokens, Tok::LBrace)?;

    let mut uses = vec![];
    let mut next_item_attributes = parse_attributes(tokens)?;
    while tokens.peek() == Tok::Use {
        uses.push(parse_use_decl(next_item_attributes, tokens)?);
        next_item_attributes = parse_attributes(tokens)?;
    }
    let mut constants = vec![];
    while tokens.peek() == Tok::Const {
        let start_loc = tokens.start_loc();
        constants.push(parse_constant_decl(
            next_item_attributes,
            start_loc,
            Modifiers::empty(),
            tokens,
        )?);
        next_item_attributes = parse_attributes(tokens)?;
    }

    tokens.match_doc_comments(); // match doc comments to script function
    let function_start_loc = tokens.start_loc();
    let modifiers = parse_module_member_modifiers(tokens)?;
    if let Some(loc) = modifiers.native {
        let msg = "'native' functions can only be declared inside a module";
        return Err(diag!(Syntax::InvalidModifier, (loc, msg)));
    }
    let function =
        parse_function_decl(next_item_attributes, function_start_loc, modifiers, tokens)?;

    let mut specs = vec![];
    while tokens.peek() == Tok::NumSign || tokens.peek() == Tok::Spec {
        let attributes = parse_attributes(tokens)?;
        specs.push(parse_spec_block(attributes, tokens)?);
    }

    if tokens.peek() != Tok::RBrace {
        let loc = current_token_loc(tokens);
        let msg = "Unexpected characters after end of 'script' function";
        return Err(diag!(Syntax::UnexpectedToken, (loc, msg)));
    }
    consume_token(tokens, Tok::RBrace)?;

    let loc = make_loc(tokens.file_name(), start_loc, tokens.previous_end_loc());
    Ok(Script {
        attributes: script_attributes,
        loc,
        uses,
        constants,
        function,
        specs,
    })
}
//**************************************************************************************************
// Specification Blocks
//**************************************************************************************************

// Parse an optional specification block:
//     SpecBlockTarget =
//          "fun" <Identifier>
//        | "struct <Identifier>
//        | "module"
//        | "schema" <Identifier> <OptionalTypeParameters>
//        | <empty>
//     SpecBlock =
//        <DocComments> "spec" ( <SpecFunction> | <SpecBlockTarget> "{" SpecBlockMember* "}" )
fn parse_spec_block(
    attributes: Vec<Attributes>,
    tokens: &mut Lexer,
) -> Result<SpecBlock, Diagnostic> {
    tokens.match_doc_comments();
    let start_loc = tokens.start_loc();
    consume_token(tokens, Tok::Spec)?;
    let target_start_loc = tokens.start_loc();
    let target_ = match tokens.peek() {
        Tok::Fun => {
            return Err(unexpected_token_error(
                tokens,
                "only 'spec', drop the 'fun' keyword",
            ));
        }
        Tok::Struct => {
            return Err(unexpected_token_error(
                tokens,
                "only 'spec', drop the 'struct' keyword",
            ));
        }
        Tok::Module => {
            tokens.advance()?;
            SpecBlockTarget_::Module
        }
        Tok::IdentifierValue if tokens.content() == "schema" => {
            tokens.advance()?;
            let name = parse_identifier(tokens)?;
            let type_parameters = parse_optional_type_parameters(tokens)?;
            SpecBlockTarget_::Schema(name, type_parameters)
        }
        Tok::IdentifierValue => {
            let name = parse_identifier(tokens)?;
            let signature = parse_spec_target_signature_opt(&name.loc, tokens)?;
            SpecBlockTarget_::Member(name, signature)
        }
        Tok::LBrace => SpecBlockTarget_::Code,
        _ => {
            return Err(unexpected_token_error(
                tokens,
                "one of `module`, `struct`, `fun`, `schema`, or `{`",
            ));
        }
    };
    let target = spanned(
        tokens.file_name(),
        target_start_loc,
        match target_ {
            SpecBlockTarget_::Code => target_start_loc,
            _ => tokens.previous_end_loc(),
        },
        target_,
    );

    consume_token(tokens, Tok::LBrace)?;
    let mut uses = vec![];
    while tokens.peek() == Tok::Use {
        uses.push(parse_use_decl(vec![], tokens)?);
    }
    let mut members = vec![];
    while tokens.peek() != Tok::RBrace {
        members.push(parse_spec_block_member(tokens)?);
    }
    consume_token(tokens, Tok::RBrace)?;
    Ok(spanned(
        tokens.file_name(),
        start_loc,
        tokens.previous_end_loc(),
        SpecBlock_ {
            attributes,
            target,
            uses,
            members,
        },
    ))
}

fn parse_spec_target_signature_opt(
    loc: &Loc,
    tokens: &mut Lexer,
) -> Result<Option<Box<FunctionSignature>>, Diagnostic> {
    match tokens.peek() {
        Tok::Less | Tok::LParen => {
            let type_parameters = parse_optional_type_parameters(tokens)?;
            // "(" Comma<Parameter> ")"
            let parameters = parse_comma_list(
                tokens,
                Tok::LParen,
                Tok::RParen,
                parse_parameter,
                "a function parameter",
            )?;
            // (":" <Type>)?
            let return_type = if match_token(tokens, Tok::Colon)? {
                parse_type(tokens)?
            } else {
                sp(*loc, Type_::Unit)
            };
            Ok(Some(Box::new(FunctionSignature {
                type_parameters,
                parameters,
                return_type,
            })))
        }
        _ => Ok(None),
    }
}

// Parse a spec block member:
//    SpecBlockMember = <DocComments> ( <Invariant> | <Condition> | <SpecFunction> | <SpecVariable>
//                                   | <SpecInclude> | <SpecApply> | <SpecPragma> | <SpecLet>
//                                   | <SpecAxiom> )
fn parse_spec_block_member(tokens: &mut Lexer) -> Result<SpecBlockMember, Diagnostic> {
    tokens.match_doc_comments();
    match tokens.peek() {
        Tok::Invariant => parse_invariant(tokens),
        Tok::Let => parse_spec_let(tokens),
        Tok::Fun | Tok::Native => parse_spec_function(tokens),
        Tok::IdentifierValue => match tokens.content() {
            "assert" | "assume" | "decreases" | "aborts_if" | "aborts_with" | "succeeds_if"
            | "modifies" | "emits" | "ensures" | "requires" | "axiom" => parse_condition(tokens),
            "include" => parse_spec_include(tokens),
            "apply" => parse_spec_apply(tokens),
            "pragma" => parse_spec_pragma(tokens),
            "global" | "local" => parse_spec_variable(tokens),
            _ => {
                // local is optional but supported to be able to declare variables which are
                // named like the weak keywords above
                parse_spec_variable(tokens)
            }
        },
        _ => Err(unexpected_token_error(
            tokens,
            "one of `assert`, `assume`, `decreases`, `aborts_if`, `aborts_with`, `succeeds_if`, \
             `modifies`, `emits`, `ensures`, `requires`, `include`, `apply`, `pragma`, `global`, \
             or a name",
        )),
    }
}

// Parse a specification condition:
//    SpecCondition =
//        ("assert" | "assume" | "decreases" | "ensures" | "requires" )
//        <ConditionProperties> <Exp> ";"
//      | "aborts_if" <ConditionProperties> <Exp> ["with" <Exp>] ";"
//      | "aborts_with" <ConditionProperties> Comma <Exp> ";"
//      | "emits" <ConditionProperties> <Exp> "to" <Exp> [If <Exp>] ";"
fn parse_condition(tokens: &mut Lexer) -> Result<SpecBlockMember, Diagnostic> {
    let start_loc = tokens.start_loc();
    let kind = match tokens.content() {
        "assert" => SpecConditionKind::Assert,
        "assume" => SpecConditionKind::Assume,
        "axiom" => SpecConditionKind::Axiom,
        "decreases" => SpecConditionKind::Decreases,
        "aborts_if" => SpecConditionKind::AbortsIf,
        "aborts_with" => SpecConditionKind::AbortsWith,
        "succeeds_if" => SpecConditionKind::SucceedsIf,
        "modifies" => SpecConditionKind::Modifies,
        "emits" => SpecConditionKind::Emits,
        "ensures" => SpecConditionKind::Ensures,
        "requires" => SpecConditionKind::Requires,
        _ => unreachable!(),
    };
    tokens.advance()?;
    let properties = parse_condition_properties(tokens)?;
    let exp = if kind == SpecConditionKind::AbortsWith || kind == SpecConditionKind::Modifies {
        // Use a dummy expression as a placeholder for this field.
        let loc = make_loc(tokens.file_name(), start_loc, start_loc + 1);
        sp(loc, Exp_::Value(sp(loc, Value_::Bool(false))))
    } else {
        parse_exp(tokens)?
    };
    let additional_exps = if kind == SpecConditionKind::AbortsIf
        && tokens.peek() == Tok::IdentifierValue
        && tokens.content() == "with"
    {
        tokens.advance()?;
        let codes = vec![parse_exp(tokens)?];
        consume_token(tokens, Tok::Semicolon)?;
        codes
    } else if kind == SpecConditionKind::AbortsWith || kind == SpecConditionKind::Modifies {
        parse_comma_list_after_start(
            tokens,
            tokens.start_loc(),
            tokens.peek(),
            Tok::Semicolon,
            parse_exp,
            "an aborts code or modifies target",
        )?
    } else if kind == SpecConditionKind::Emits {
        consume_identifier(tokens, "to")?;
        let mut additional_exps = vec![parse_exp(tokens)?];
        if match_token(tokens, Tok::If)? {
            additional_exps.push(parse_exp(tokens)?);
        }
        consume_token(tokens, Tok::Semicolon)?;
        additional_exps
    } else {
        consume_token(tokens, Tok::Semicolon)?;
        vec![]
    };
    let end_loc = tokens.previous_end_loc();
    Ok(spanned(
        tokens.file_name(),
        start_loc,
        end_loc,
        SpecBlockMember_::Condition {
            kind,
            properties,
            exp,
            additional_exps,
        },
    ))
}

// Parse properties in a condition.
//   ConditionProperties = ( "[" Comma<SpecPragmaProperty> "]" )?
fn parse_condition_properties(tokens: &mut Lexer) -> Result<Vec<PragmaProperty>, Diagnostic> {
    let properties = if tokens.peek() == Tok::LBracket {
        parse_comma_list(
            tokens,
            Tok::LBracket,
            Tok::RBracket,
            parse_spec_property,
            "a condition property",
        )?
    } else {
        vec![]
    };
    Ok(properties)
}

// Parse an invariant:
//     Invariant = "invariant" [ "update" ] <ConditionProperties> <Exp> ";"
fn parse_invariant(tokens: &mut Lexer) -> Result<SpecBlockMember, Diagnostic> {
    let start_loc = tokens.start_loc();
    consume_token(tokens, Tok::Invariant)?;
    let kind = match tokens.peek() {
        Tok::IdentifierValue if tokens.content() == "update" => {
            tokens.advance()?;
            SpecConditionKind::InvariantUpdate
        }
        _ => SpecConditionKind::Invariant,
    };
    let properties = parse_condition_properties(tokens)?;
    let exp = parse_exp(tokens)?;
    consume_token(tokens, Tok::Semicolon)?;
    Ok(spanned(
        tokens.file_name(),
        start_loc,
        tokens.previous_end_loc(),
        SpecBlockMember_::Condition {
            kind,
            properties,
            exp,
            additional_exps: vec![],
        },
    ))
}

// Parse a specification function.
//     SpecFunction = "define" <SpecFunctionSignature> ( "{" <Sequence> "}" | ";" )
//                  | "native" "define" <SpecFunctionSignature> ";"
//     SpecFunctionSignature =
//         <Identifier> <OptionalTypeParameters> "(" Comma<Parameter> ")" ":" <Type>
fn parse_spec_function(tokens: &mut Lexer) -> Result<SpecBlockMember, Diagnostic> {
    let start_loc = tokens.start_loc();
    let native_opt = consume_optional_token_with_loc(tokens, Tok::Native)?;
    consume_token(tokens, Tok::Fun)?;
    let name = FunctionName(parse_identifier(tokens)?);
    let type_parameters = parse_optional_type_parameters(tokens)?;
    // "(" Comma<Parameter> ")"
    let parameters = parse_comma_list(
        tokens,
        Tok::LParen,
        Tok::RParen,
        parse_parameter,
        "a function parameter",
    )?;

    // ":" <Type>)
    consume_token(tokens, Tok::Colon)?;
    let return_type = parse_type(tokens)?;

    let body_start_loc = tokens.start_loc();
    let no_body = tokens.peek() != Tok::LBrace;
    let (uninterpreted, body_) = if native_opt.is_some() || no_body {
        consume_token(tokens, Tok::Semicolon)?;
        (native_opt.is_none(), FunctionBody_::Native)
    } else {
        consume_token(tokens, Tok::LBrace)?;
        let seq = parse_sequence(tokens)?;
        (false, FunctionBody_::Defined(seq))
    };
    let body = spanned(
        tokens.file_name(),
        body_start_loc,
        tokens.previous_end_loc(),
        body_,
    );

    let signature = FunctionSignature {
        type_parameters,
        parameters,
        return_type,
    };

    Ok(spanned(
        tokens.file_name(),
        start_loc,
        tokens.previous_end_loc(),
        SpecBlockMember_::Function {
            signature,
            uninterpreted,
            name,
            body,
        },
    ))
}

// Parse a specification variable.
//     SpecVariable = ( "global" | "local" )? <Identifier> <OptionalTypeParameters> ":" <Type> ";"
fn parse_spec_variable(tokens: &mut Lexer) -> Result<SpecBlockMember, Diagnostic> {
    let start_loc = tokens.start_loc();
    let is_global = match tokens.content() {
        "global" => {
            consume_token(tokens, Tok::IdentifierValue)?;
            true
        }
        "local" => {
            consume_token(tokens, Tok::IdentifierValue)?;
            false
        }
        _ => false,
    };
    let name = parse_identifier(tokens)?;
    let type_parameters = parse_optional_type_parameters(tokens)?;
    consume_token(tokens, Tok::Colon)?;
    let type_ = parse_type(tokens)?;
    consume_token(tokens, Tok::Semicolon)?;
    Ok(spanned(
        tokens.file_name(),
        start_loc,
        tokens.previous_end_loc(),
        SpecBlockMember_::Variable {
            is_global,
            name,
            type_parameters,
            type_,
        },
    ))
}

// Parse a specification let.
//     SpecLet =  "let" [ "post" ] <Identifier> "=" <Exp> ";"
fn parse_spec_let(tokens: &mut Lexer) -> Result<SpecBlockMember, Diagnostic> {
    let start_loc = tokens.start_loc();
    tokens.advance()?;
    let post_state = if tokens.peek() == Tok::IdentifierValue && tokens.content() == "post" {
        tokens.advance()?;
        true
    } else {
        false
    };
    let name = parse_identifier(tokens)?;
    consume_token(tokens, Tok::Equal)?;
    let def = parse_exp(tokens)?;
    consume_token(tokens, Tok::Semicolon)?;
    Ok(spanned(
        tokens.file_name(),
        start_loc,
        tokens.previous_end_loc(),
        SpecBlockMember_::Let {
            name,
            post_state,
            def,
        },
    ))
}

// Parse a specification schema include.
//    SpecInclude = "include" <Exp>
fn parse_spec_include(tokens: &mut Lexer) -> Result<SpecBlockMember, Diagnostic> {
    let start_loc = tokens.start_loc();
    consume_identifier(tokens, "include")?;
    let properties = parse_condition_properties(tokens)?;
    let exp = parse_exp(tokens)?;
    consume_token(tokens, Tok::Semicolon)?;
    Ok(spanned(
        tokens.file_name(),
        start_loc,
        tokens.previous_end_loc(),
        SpecBlockMember_::Include { properties, exp },
    ))
}

// Parse a specification schema apply.
//    SpecApply = "apply" <Exp> "to" Comma<SpecApplyPattern>
//                                   ( "except" Comma<SpecApplyPattern> )? ";"
fn parse_spec_apply(tokens: &mut Lexer) -> Result<SpecBlockMember, Diagnostic> {
    let start_loc = tokens.start_loc();
    consume_identifier(tokens, "apply")?;
    let exp = parse_exp(tokens)?;
    consume_identifier(tokens, "to")?;
    let parse_patterns = |tokens: &mut Lexer| {
        parse_list(
            tokens,
            |tokens| {
                if tokens.peek() == Tok::Comma {
                    tokens.advance()?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
            parse_spec_apply_pattern,
        )
    };
    let patterns = parse_patterns(tokens)?;
    let exclusion_patterns =
        if tokens.peek() == Tok::IdentifierValue && tokens.content() == "except" {
            tokens.advance()?;
            parse_patterns(tokens)?
        } else {
            vec![]
        };
    consume_token(tokens, Tok::Semicolon)?;
    Ok(spanned(
        tokens.file_name(),
        start_loc,
        tokens.previous_end_loc(),
        SpecBlockMember_::Apply {
            exp,
            patterns,
            exclusion_patterns,
        },
    ))
}

// Parse a function pattern:
//     SpecApplyPattern = <SpecApplyFragment>+ <OptionalTypeArgs>
fn parse_spec_apply_pattern(tokens: &mut Lexer) -> Result<SpecApplyPattern, Diagnostic> {
    let start_loc = tokens.start_loc();
    // TODO: update the visibility parsing in the spec as well
    let public_opt = consume_optional_token_with_loc(tokens, Tok::Public)?;
    let visibility = if let Some(loc) = public_opt {
        Some(Visibility::Public(loc))
    } else if tokens.peek() == Tok::IdentifierValue && tokens.content() == "internal" {
        // Its not ideal right now that we do not have a loc here, but acceptable for what
        // we are doing with this in specs.
        tokens.advance()?;
        Some(Visibility::Internal)
    } else {
        None
    };
    let mut last_end = tokens.start_loc() + tokens.content().len();
    let name_pattern = parse_list(
        tokens,
        |tokens| {
            // We need name fragments followed by each other without space. So we do some
            // magic here similar as with `>>` based on token distance.
            let start_loc = tokens.start_loc();
            let adjacent = last_end == start_loc;
            last_end = start_loc + tokens.content().len();
            Ok(adjacent && [Tok::IdentifierValue, Tok::Star].contains(&tokens.peek()))
        },
        parse_spec_apply_fragment,
    )?;
    let type_parameters = parse_optional_type_parameters(tokens)?;
    Ok(spanned(
        tokens.file_name(),
        start_loc,
        tokens.previous_end_loc(),
        SpecApplyPattern_ {
            visibility,
            name_pattern,
            type_parameters,
        },
    ))
}

// Parse a name pattern fragment
//     SpecApplyFragment = <Identifier> | "*"
fn parse_spec_apply_fragment(tokens: &mut Lexer) -> Result<SpecApplyFragment, Diagnostic> {
    let start_loc = tokens.start_loc();
    let fragment = match tokens.peek() {
        Tok::IdentifierValue => SpecApplyFragment_::NamePart(parse_identifier(tokens)?),
        Tok::Star => {
            tokens.advance()?;
            SpecApplyFragment_::Wildcard
        }
        _ => return Err(unexpected_token_error(tokens, "a name fragment or `*`")),
    };
    Ok(spanned(
        tokens.file_name(),
        start_loc,
        tokens.previous_end_loc(),
        fragment,
    ))
}

// Parse a specification pragma:
//    SpecPragma = "pragma" Comma<SpecPragmaProperty> ";"
fn parse_spec_pragma(tokens: &mut Lexer) -> Result<SpecBlockMember, Diagnostic> {
    let start_loc = tokens.start_loc();
    consume_identifier(tokens, "pragma")?;
    let properties = parse_comma_list_after_start(
        tokens,
        start_loc,
        Tok::IdentifierValue,
        Tok::Semicolon,
        parse_spec_property,
        "a pragma property",
    )?;
    Ok(spanned(
        tokens.file_name(),
        start_loc,
        tokens.previous_end_loc(),
        SpecBlockMember_::Pragma { properties },
    ))
}

// Parse a specification pragma property:
//    SpecPragmaProperty = <Identifier> ( "=" <Value> | <NameAccessChain> )?
fn parse_spec_property(tokens: &mut Lexer) -> Result<PragmaProperty, Diagnostic> {
    let start_loc = tokens.start_loc();
    let name = match consume_optional_token_with_loc(tokens, Tok::Friend)? {
        // special treatment for `pragma friend = ...` as friend is a keyword
        // TODO: this might violate the assumption that a keyword can never be a name.
        Some(loc) => Name::new(loc, "friend".to_owned()),
        None => parse_identifier(tokens)?,
    };
    let value = if tokens.peek() == Tok::Equal {
        tokens.advance()?;
        match tokens.peek() {
            Tok::AtSign | Tok::True | Tok::False | Tok::NumTypedValue | Tok::ByteStringValue => {
                Some(PragmaValue::Literal(parse_value(tokens)?))
            }
            Tok::NumValue
                if !tokens
                    .lookahead()
                    .map(|tok| tok == Tok::ColonColon)
                    .unwrap_or(false) =>
            {
                Some(PragmaValue::Literal(parse_value(tokens)?))
            }
            _ => {
                // Parse as a module access for a possibly qualified identifier
                Some(PragmaValue::Ident(parse_name_access_chain(tokens, || {
                    "an identifier as pragma value"
                })?))
            }
        }
    } else {
        None
    };
    Ok(spanned(
        tokens.file_name(),
        start_loc,
        tokens.previous_end_loc(),
        PragmaProperty_ { name, value },
    ))
}

/// Creates a module spec block for a single member.
fn singleton_module_spec_block(
    tokens: &mut Lexer,
    start_loc: usize,
    attributes: Vec<Attributes>,
    member_parser: impl Fn(&mut Lexer) -> Result<SpecBlockMember, Diagnostic>,
) -> Result<SpecBlock, Diagnostic> {
    let member = member_parser(tokens)?;
    let end_loc = tokens.previous_end_loc();
    Ok(spanned(
        tokens.file_name(),
        start_loc,
        end_loc,
        SpecBlock_ {
            attributes,
            target: spanned(
                tokens.file_name(),
                start_loc,
                start_loc,
                SpecBlockTarget_::Module,
            ),
            uses: vec![],
            members: vec![member],
        },
    ))
}

//**************************************************************************************************
// File
//**************************************************************************************************

// Parse a file:
//      File =
//          (<Attributes> (<AddressBlock> | <Module> | <Script>))*
fn parse_file(tokens: &mut Lexer) -> Result<Vec<Definition>, Diagnostic> {
    let mut defs = vec![];
    while tokens.peek() != Tok::EOF {
        let attributes = parse_attributes(tokens)?;
        defs.push(match tokens.peek() {
            Tok::Spec | Tok::Module => Definition::Module(parse_module(attributes, tokens)?),
            Tok::Script => Definition::Script(parse_script(attributes, tokens)?),
            _ => Definition::Address(parse_address_block(attributes, tokens)?),
        })
    }
    Ok(defs)
}

/// Parse the `input` string as a file of Move source code and return the
/// result as either a pair of FileDefinition and doc comments or some Diagnostics. The `file` name
/// is used to identify source locations in error messages.
pub fn parse_file_string(
    file: &'static str,
    input: &str,
    comment_map: BTreeMap<Span, String>,
) -> Result<(Vec<Definition>, BTreeMap<ByteIndex, String>), Diagnostics> {
    let mut tokens = Lexer::new(input, file, comment_map);
    match tokens.advance() {
        Err(err) => Err(Diagnostics::from(vec![err])),
        Ok(..) => Ok(()),
    }?;
    match parse_file(&mut tokens) {
        Err(err) => Err(Diagnostics::from(vec![err])),
        Ok(def) => {
            let doc_comments = tokens.check_and_get_doc_comments()?;
            Ok((def, doc_comments))
        }
    }
}
