// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::errors::diagnostic_codes::{DiagnosticCode, DiagnosticInfo, Severity};
use codespan_reporting_new::{
    self as csr,
    files::SimpleFiles,
    term::{emit, termcolor::WriteColor, Config},
};
use move_ir_types::location::*;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    iter::FromIterator,
    ops::Range,
};

//**************************************************************************************************
// Types
//**************************************************************************************************

pub type FileId = usize;

pub type FilesSourceText = HashMap<&'static str, String>;
type FileMapping = HashMap<&'static str, FileId>;

#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub struct Diagnostic {
    pub(crate) info: DiagnosticInfo,
    pub(crate) primary_label: (Loc, String),
    pub(crate) secondary_labels: Vec<(Loc, String)>,
}

#[derive(PartialEq, Eq, Hash, Clone, Debug, Default)]
pub struct Diagnostics {
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) severity_count: BTreeMap<Severity, usize>,
}

//**************************************************************************************************
// Reporting
//**************************************************************************************************

pub(crate) fn output_diagnostics<W: WriteColor>(
    writer: &mut W,
    sources: &FilesSourceText,
    diags: Diagnostics,
) {
    let mut files = SimpleFiles::new();
    let mut file_mapping = HashMap::new();
    for (fname, source) in sources {
        let id = files.add(*fname, source.as_str());
        file_mapping.insert(*fname, id);
    }
    render_diagnostics(writer, &files, &file_mapping, diags);
}

fn render_diagnostics(
    writer: &mut dyn WriteColor,
    files: &SimpleFiles<&'static str, &str>,
    file_mapping: &FileMapping,
    mut diags: Diagnostics,
) {
    diags.diagnostics.sort_by(|e1, e2| {
        let loc1: &Loc = &e1.primary_label.0;
        let loc2: &Loc = &e2.primary_label.0;
        loc1.cmp(loc2)
    });
    let mut seen: HashSet<Diagnostic> = HashSet::new();
    for diag in diags.diagnostics {
        if seen.contains(&diag) {
            continue;
        }
        seen.insert(diag.clone());
        let rendered = render_diagnostic(file_mapping, diag);
        emit(writer, &Config::default(), files, &rendered).unwrap()
    }
}

fn convert_loc(file_mapping: &FileMapping, loc: Loc) -> (FileId, Range<usize>) {
    let fname = loc.file();
    let id = *file_mapping.get(fname).unwrap();
    let start = loc.span().start().to_usize();
    let end = loc.span().end().to_usize();
    (id, Range { start, end })
}

fn render_diagnostic(
    file_mapping: &FileMapping,
    diag: Diagnostic,
) -> csr::diagnostic::Diagnostic<FileId> {
    use csr::diagnostic::{Label, LabelStyle};
    let mk_lbl = |style: LabelStyle, msg: (Loc, String)| -> Label<FileId> {
        let (id, range) = convert_loc(file_mapping, msg.0);
        csr::diagnostic::Label::new(style, id, range).with_message(msg.1)
    };
    let Diagnostic {
        info,
        primary_label,
        secondary_labels,
    } = diag;
    let mut diag = csr::diagnostic::Diagnostic::new(info.severity.into_codespan_severity());
    let (code, message) = info.render();
    diag = diag.with_code(code);
    diag = diag.with_message(message);
    diag = diag.with_labels(vec![mk_lbl(LabelStyle::Primary, primary_label)]);
    diag = diag.with_labels(
        secondary_labels
            .into_iter()
            .map(|msg| mk_lbl(LabelStyle::Secondary, msg))
            .collect(),
    );
    diag
}

//**************************************************************************************************
// impls
//**************************************************************************************************

impl Diagnostics {
    pub fn new() -> Self {
        Self {
            diagnostics: vec![],
            severity_count: BTreeMap::new(),
        }
    }

    pub fn max_severity(&self) -> Severity {
        debug_assert!(self.severity_count.values().all(|count| *count > 0));
        self.severity_count
            .iter()
            .max_by_key(|(sev, _count)| **sev)
            .map(|(sev, _count)| *sev)
            .unwrap_or(Severity::MIN)
    }

    pub fn is_empty(&self) -> bool {
        self.diagnostics.is_empty()
    }

    pub fn len(&self) -> usize {
        self.diagnostics.len()
    }

    pub fn add(&mut self, diag: Diagnostic) {
        *self.severity_count.entry(diag.info.severity).or_insert(0) += 1;
        self.diagnostics.push(diag)
    }

    pub fn extend(&mut self, other: Self) {
        let Self {
            diagnostics,
            severity_count,
        } = other;
        for (sev, count) in severity_count {
            *self.severity_count.entry(sev).or_insert(0) += count;
        }
        self.diagnostics.extend(diagnostics)
    }

    pub fn into_vec(self) -> Vec<Diagnostic> {
        self.diagnostics
    }
}

impl Diagnostic {
    pub(crate) fn new(
        code: impl DiagnosticCode,
        (loc, label): (Loc, impl ToString),
        secondary_labels: impl IntoIterator<Item = (Loc, impl ToString)>,
    ) -> Self {
        Diagnostic {
            info: code.into_info(),
            primary_label: (loc, label.to_string()),
            secondary_labels: secondary_labels
                .into_iter()
                .map(|(loc, msg)| (loc, msg.to_string()))
                .collect(),
        }
    }

    #[allow(unused)]
    pub(crate) fn add_secondary_labels(
        &mut self,
        additional_labels: impl IntoIterator<Item = (Loc, impl ToString)>,
    ) {
        self.secondary_labels.extend(
            additional_labels
                .into_iter()
                .map(|(loc, msg)| (loc, msg.to_string())),
        )
    }

    pub(crate) fn add_secondary_label(&mut self, (loc, msg): (Loc, impl ToString)) {
        self.secondary_labels.push((loc, msg.to_string()))
    }
}

#[macro_export]
macro_rules! diag {
    ($code: expr, $primary: expr $(,)?) => {{
        #[allow(unused)]
        use crate::errors::diagnostic_codes::*;
        crate::errors::new::Diagnostic::new($code, $primary, std::iter::empty::<(Loc, String)>())
    }};
    ($code: expr, $primary: expr, $($secondary: expr),+ $(,)?) => {{
        #[allow(unused)]
        use crate::errors::diagnostic_codes::*;
        crate::errors::new::Diagnostic::new($code, $primary, vec![$($secondary, )*])
    }};
}

//**************************************************************************************************
// traits
//**************************************************************************************************

impl FromIterator<Diagnostic> for Diagnostics {
    fn from_iter<I: IntoIterator<Item = Diagnostic>>(iter: I) -> Self {
        let diagnostics = iter.into_iter().collect::<Vec<_>>();
        Self::from(diagnostics)
    }
}

impl From<Vec<Diagnostic>> for Diagnostics {
    fn from(diagnostics: Vec<Diagnostic>) -> Self {
        let mut severity_count = BTreeMap::new();
        for diag in &diagnostics {
            *severity_count.entry(diag.info.severity).or_insert(0) += 1;
        }
        Self {
            diagnostics,
            severity_count,
        }
    }
}
