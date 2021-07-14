// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//**************************************************************************************************
// Main types
//**************************************************************************************************

#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash, PartialOrd, Ord)]
pub enum Severity {
    Warning = 0,
    NonblockingError = 1,
    BlockingError = 2,
}

#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub(crate) struct DiagnosticInfo {
    pub(crate) severity: Severity,
    category: Category,
    code: u8,
    message: &'static str,
}

pub(crate) trait DiagnosticCode: Copy {
    const CATEGORY: Category;

    fn severity(self) -> Severity;

    fn code_and_message(self) -> (u8, &'static str);

    fn into_info(self) -> DiagnosticInfo {
        let severity = self.severity();
        let category = Self::CATEGORY;
        let (code, message) = self.code_and_message();
        DiagnosticInfo {
            severity,
            category,
            code,
            message,
        }
    }
}

//**************************************************************************************************
// Categories and Codes
//**************************************************************************************************

macro_rules! codes {
    ($($cat:ident: [
        $($code:ident: { msg: $code_msg:literal, severity:$sev:ident $(,)? }),* $(,)?
    ]),* $(,)?) => {
        #[derive(PartialEq, Eq, Clone, Copy, Debug, Hash)]
        #[repr(u8)]
        pub enum Category {
            $($cat,)*
        }

        $(
            #[derive(PartialEq, Eq, Clone, Copy, Debug, Hash)]
            #[repr(u8)]
            pub enum $cat {
                DontStartAtZeroPlaceholder,
                $($code,)*
            }

            impl DiagnosticCode for $cat {
                const CATEGORY: Category = {
                    // hacky check that $cat_num <= 99
                    let cat_is_leq_99 = (Category::$cat as u8) <= 99;
                    ["Diagnostic Category must be a u8 <= 99"][!cat_is_leq_99 as usize];
                    Category::$cat
                };

                fn severity(self) -> Severity {
                    match self {
                        Self::DontStartAtZeroPlaceholder =>
                            panic!("ICE do not use placeholder error code"),
                        $(Self::$code => Severity::$sev,)*
                    }
                }

                fn code_and_message(self) -> (u8, &'static str) {
                    let code = self as u8;
                    debug_assert!(code > 0);
                    match self {
                        Self::DontStartAtZeroPlaceholder =>
                            panic!("ICE do not use placeholder error code"),
                        $(Self::$code => (code, $code_msg),)*
                    }
                }
            }
        )*

    };
}

codes!(
    // bucket for random one off errors. unlikely to be used
    Uncategorized: [],
    // syntax errors
    Syntax: [
        InvalidCharacter: { msg: "invalid character", severity: BlockingError },
        UnexpectedToken: { msg: "unexpected token", severity: BlockingError },
        InvalidModifier: { msg: "invalid modifier", severity: BlockingError },
        InvalidDocComment: { msg: "invalid documentation comment", severity: Warning },
        InvalidAddress: { msg: "invalid address", severity: BlockingError },
        InvalidNumber: { msg: "invalid number literal", severity: BlockingError },
        InvalidByteString: { msg: "invalid byte string", severity: BlockingError },
        InvalidHexString: { msg: "invalid hex string", severity: BlockingError },
        InvalidLValue: { msg: "invalid assignment", severity: BlockingError },
        SpecContextRestricted:
            { msg: "syntax item restricted to spec contexts", severity: BlockingError },
    ],
    // errors for any rules around declaration items
    Declarations: [
        DuplicateItem:
            { msg: "duplicate declaration, item, or annotation", severity: NonblockingError },
        UnnecessaryItem: { msg: "unnecessary or extraneous item", severity: NonblockingError },
        InvalidAddress: { msg: "invalid 'address' declaration", severity: NonblockingError },
        InvalidModule: { msg: "invalid 'module' declaration", severity: NonblockingError },
        InvalidScript: { msg: "invalid 'script' declaration", severity: NonblockingError },
        InvalidConstant: { msg: "invalid 'const' declaration", severity: NonblockingError },
        InvalidFunction: { msg: "invalid 'fun' declaration", severity: NonblockingError },
        InvalidStruct: { msg: "invalid 'struct' declaration", severity: NonblockingError },
        InvalidName: { msg: "invalid name", severity: BlockingError },
        InvalidFriendDeclaration:
            { msg: "invalid 'friend' declaration", severity: NonblockingError },
        InvalidAcquiresItem: { msg: "invalid 'acquires' item", severity: NonblockingError },
        InvalidPhantomUse: { msg: "invalid phantom type parameter usage", severity: NonblockingError },
    ],
    // errors name resolution, mostly expansion/translate and naming/translate
    NameResolution: [
        UnboundAddress: { msg: "unbound address", severity: BlockingError },
        UnboundModule: { msg: "unbound module", severity: BlockingError },
        UnboundModuleMember: { msg: "unbound module member", severity: BlockingError },
        UnboundType: { msg: "unbound type", severity: BlockingError },
        UnboundUnscopedName: { msg: "unbound unscoped name", severity: BlockingError },
        NamePositionMismatch: { msg: "unexpected name in this position", severity: BlockingError },
        TooManyTypeArguments: { msg: "too many type arguments", severity: NonblockingError },
        TooFewTypeArguments: { msg: "too few type arguments", severity: BlockingError },
        UnboundVariable: { msg: "unbound variable", severity: BlockingError },
        UnboundField: { msg: "unbound field", severity: BlockingError },
    ],
    // errors for typing rules. mostly typing/translate
    TypeSafety: [
        Visibility: { msg: "restricted visibility", severity: NonblockingError },
        ScriptContext: { msg: "requires script context", severity: NonblockingError },
        BuiltinOperation: { msg: "built-in operation not supported", severity: BlockingError },
        ExpectedBaseType: { msg: "expected a single non-reference type", severity: BlockingError },
        ExpectedSingleType: { msg: "expected a single type", severity: BlockingError },
        SubtypeError: { msg: "invalid subtype", severity: BlockingError },
        JoinError: { msg: "incompatible types", severity: BlockingError },
        RecursiveType: { msg: "invalid type. recursive type found", severity: BlockingError },
        ExpectedSpecificType: { msg: "expected specific type", severity: BlockingError },
        UninferredType: { msg: "cannot infer type", severity: BlockingError },
        ScriptSignature: { msg: "invalid script signature", severity: NonblockingError },
        TypeForConstant: { msg: "invalid type for constant", severity: BlockingError },
        UnsupportedConstant:
            { msg: "invalid statement or expression in constant", severity: BlockingError },
        InvalidLoopControl: { msg: "invalid loop control", severity: BlockingError },
        InvalidNativeUsage: { msg: "invalid use of native item", severity: BlockingError },
        TooFewArguments: { msg: "too few arguments", severity: NonblockingError },
        TooManyArguments: { msg: "too many arguments", severity: NonblockingError },
        CyclicData: { msg: "cyclic data", severity: NonblockingError },
        CyclicInstantiation:
            { msg: "cyclic type instantiation", severity: NonblockingError },
        MissingAcquires: { msg: "missing acquires annotation", severity: NonblockingError },
        InvalidNum: { msg: "invalid number after type inference", severity: NonblockingError },
    ],
    // errors for ability rules. mostly typing/translate
    AbilitySafety: [
        Constraint: { msg: "ability constraint not satisfied", severity: NonblockingError },
        ImplicitlyCopyable: { msg: "type not implicitly copyable", severity: NonblockingError },
    ],
    // errors for move rules. mostly cfgir/locals
    MoveSafety: [],
    // errors for move rules. mostly cfgir/borrows
    ReferenceSafety: [
        RefTrans: { msg: "referential transparency violated", severity: BlockingError },
    ],
    // errors for any unused code or items
    UnusedItem: [
        Alias: { msg: "unused alias", severity: Warning },
    ],
);

//**************************************************************************************************
// impls
//**************************************************************************************************

impl DiagnosticInfo {
    pub fn render(self) -> (/* code */ String, /* message */ &'static str) {
        let Self {
            severity,
            category,
            code,
            message,
        } = self;
        let sev_prefix = match severity {
            Severity::BlockingError | Severity::NonblockingError => "E",
            Severity::Warning => "W",
        };
        let cat_prefix: u8 = category as u8;
        debug_assert!(cat_prefix <= 99);
        let string_code = format!("{}{:02}{:03}", sev_prefix, cat_prefix, code);
        (string_code, message)
    }
}

impl Severity {
    pub const MIN: Self = Self::Warning;
    pub const MAX: Self = Self::BlockingError;

    pub fn into_codespan_severity(self) -> codespan_reporting_new::diagnostic::Severity {
        use codespan_reporting_new::diagnostic::Severity as CSRSeverity;
        match self {
            Severity::BlockingError | Severity::NonblockingError => CSRSeverity::Error,
            Severity::Warning => CSRSeverity::Warning,
        }
    }
}

impl Default for Severity {
    fn default() -> Self {
        Self::MIN
    }
}
