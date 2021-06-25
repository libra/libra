// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    function_target::{FunctionData, FunctionTarget},
    print_targets_for_test,
    stackless_bytecode_generator::StacklessBytecodeGenerator,
    stackless_control_flow_graph::generate_cfg_in_dot_format,
};
use core::fmt;
use itertools::Itertools;
use log::debug;
use move_model::model::{FunId, FunctionEnv, GlobalEnv, QualifiedId};
use std::{collections::BTreeMap, fmt::Formatter, fs};

/// A data structure which holds data for multiple function targets, and allows to
/// manipulate them as part of a transformation pipeline.
#[derive(Debug, Default)]
pub struct FunctionTargetsHolder {
    targets: BTreeMap<QualifiedId<FunId>, BTreeMap<FunctionVariant, FunctionData>>,
}

/// Describes a function verification flavor.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerificationFlavor {
    Regular,
    Inconsistency,
}

impl std::fmt::Display for VerificationFlavor {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationFlavor::Regular => write!(f, ""),
            VerificationFlavor::Inconsistency => write!(f, "inconsistency"),
        }
    }
}

/// Describes a function target variant.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum FunctionVariant {
    /// The baseline variant which was created from the original Move bytecode and is then
    /// subject of multiple transformations.
    Baseline,
    /// A variant which is instrumented for verification. Only functions which are target
    /// of verification have one of those. There can be multiple verification variants,
    /// each identified by a unique flavor.
    Verification(VerificationFlavor),
}

impl FunctionVariant {
    pub fn is_verified(&self) -> bool {
        matches!(self, FunctionVariant::Verification(..))
    }
}

impl std::fmt::Display for FunctionVariant {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use FunctionVariant::*;
        match self {
            Baseline => write!(f, "baseline"),
            Verification(VerificationFlavor::Regular) => write!(f, "verification"),
            Verification(v) => write!(f, "verification[{}]", v),
        }
    }
}

/// A trait describing a function target processor.
pub trait FunctionTargetProcessor {
    /// Processes a function variant. Takes as parameter a target holder which can be mutated, the
    /// env of the function being processed, and the target data. During the time the processor is
    /// called, the target data is removed from the holder, and added back once transformation
    /// has finished. This allows the processor to take ownership on the target data.
    fn process(
        &self,
        _targets: &mut FunctionTargetsHolder,
        _fun_env: &FunctionEnv<'_>,
        _data: FunctionData,
    ) -> FunctionData {
        unimplemented!()
    }

    /// Same as `process` but can return None to indicate that the function variant is
    /// removed. By default, this maps to `Some(self.process(..))`. One needs to implement
    /// either this function or `process`.
    fn process_and_maybe_remove(
        &self,
        targets: &mut FunctionTargetsHolder,
        func_env: &FunctionEnv<'_>,
        data: FunctionData,
    ) -> Option<FunctionData> {
        Some(self.process(targets, func_env, data))
    }

    /// Returns a name for this processor. This should be suitable as a file suffix.
    fn name(&self) -> String;

    /// A function which is called once before any `process` call is issued.
    fn initialize(&self, _env: &GlobalEnv, _targets: &mut FunctionTargetsHolder) {}

    /// A function which is called once after the last `process` call.
    fn finalize(&self, _env: &GlobalEnv, _targets: &mut FunctionTargetsHolder) {}

    /// A function which can be implemented to indicate that instead of a sequence of initialize,
    /// process, and finalize, this processor has a single `run` function for the analysis of the
    /// whole set of functions.
    fn is_single_run(&self) -> bool {
        false
    }

    /// To be implemented if `is_single_run()` is true.
    fn run(&self, _env: &GlobalEnv, _targets: &mut FunctionTargetsHolder) {
        unimplemented!()
    }

    /// A function which creates a dump of the processors results, for debugging.
    fn dump_result(
        &self,
        _f: &mut Formatter<'_>,
        _env: &GlobalEnv,
        _targets: &FunctionTargetsHolder,
    ) -> fmt::Result {
        Ok(())
    }
}

pub struct ProcessorResultDisplay<'a> {
    pub env: &'a GlobalEnv,
    pub targets: &'a FunctionTargetsHolder,
    pub processor: &'a dyn FunctionTargetProcessor,
}

impl<'a> fmt::Display for ProcessorResultDisplay<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.processor.dump_result(f, self.env, self.targets)
    }
}

/// A processing pipeline for function targets.
#[derive(Default)]
pub struct FunctionTargetPipeline {
    processors: Vec<Box<dyn FunctionTargetProcessor>>,
}

impl FunctionTargetsHolder {
    /// Get an iterator for all functions this holder.
    pub fn get_funs(&self) -> impl Iterator<Item = QualifiedId<FunId>> + '_ {
        self.targets.keys().cloned()
    }

    /// Gets an iterator for all functions and variants in this holder.
    pub fn get_funs_and_variants(
        &self,
    ) -> impl Iterator<Item = (QualifiedId<FunId>, FunctionVariant)> + '_ {
        self.targets
            .iter()
            .map(|(id, vs)| vs.keys().map(move |v| (*id, v.clone())))
            .flatten()
    }

    /// Adds a new function target. The target will be initialized from the Move byte code.
    pub fn add_target(&mut self, func_env: &FunctionEnv<'_>) {
        let generator = StacklessBytecodeGenerator::new(func_env);
        let data = generator.generate_function();
        self.targets
            .entry(func_env.get_qualified_id())
            .or_default()
            .insert(FunctionVariant::Baseline, data);
    }

    /// Gets a function target for read-only consumption, for the given variant.
    pub fn get_target<'env>(
        &'env self,
        func_env: &'env FunctionEnv<'env>,
        variant: &FunctionVariant,
    ) -> FunctionTarget<'env> {
        let data = self
            .get_data(&func_env.get_qualified_id(), variant)
            .unwrap_or_else(|| {
                panic!(
                    "expected function target: {} ({:?})",
                    func_env.get_full_name_str(),
                    variant
                )
            });
        FunctionTarget::new(func_env, &data)
    }

    /// Gets all available variants for function.
    pub fn get_target_variants(&self, func_env: &FunctionEnv<'_>) -> Vec<FunctionVariant> {
        self.targets
            .get(&func_env.get_qualified_id())
            .expect("function targets exist")
            .keys()
            .cloned()
            .collect_vec()
    }

    /// Gets targets for all available variants.
    pub fn get_targets<'env>(
        &'env self,
        func_env: &'env FunctionEnv<'env>,
    ) -> Vec<(FunctionVariant, FunctionTarget<'env>)> {
        self.targets
            .get(&func_env.get_qualified_id())
            .expect("function targets exist")
            .iter()
            .map(|(v, d)| (v.clone(), FunctionTarget::new(func_env, d)))
            .collect_vec()
    }

    /// Gets function data for a variant.
    pub fn get_data(
        &self,
        id: &QualifiedId<FunId>,
        variant: &FunctionVariant,
    ) -> Option<&FunctionData> {
        self.targets.get(id).and_then(|vs| vs.get(&variant))
    }

    /// Gets mutable function data for a variant.
    pub fn get_data_mut(
        &mut self,
        id: &QualifiedId<FunId>,
        variant: &FunctionVariant,
    ) -> Option<&mut FunctionData> {
        self.targets.get_mut(id).and_then(|vs| vs.get_mut(&variant))
    }

    /// Removes function data for a variant.
    pub fn remove_target_data(
        &mut self,
        id: &QualifiedId<FunId>,
        variant: &FunctionVariant,
    ) -> FunctionData {
        self.targets
            .get_mut(id)
            .expect("function target exists")
            .remove(&variant)
            .expect("variant exists")
    }

    /// Sets function data for a function's variant.
    pub fn insert_target_data(
        &mut self,
        id: &QualifiedId<FunId>,
        variant: FunctionVariant,
        data: FunctionData,
    ) {
        self.targets.entry(*id).or_default().insert(variant, data);
    }

    /// Processes the function target data for given function.
    fn process(&mut self, func_env: &FunctionEnv<'_>, processor: &dyn FunctionTargetProcessor) {
        let id = func_env.get_qualified_id();
        for variant in self.get_target_variants(func_env) {
            // Remove data so we can own it.
            let data = self.remove_target_data(&id, &variant);
            if let Some(processed_data) = processor.process_and_maybe_remove(self, func_env, data) {
                // Put back processed data.
                self.insert_target_data(&id, variant, processed_data);
            }
        }
    }
}

impl FunctionTargetPipeline {
    /// Adds a processor to this pipeline. Processor will be called in the order they have been
    /// added.
    pub fn add_processor(&mut self, processor: Box<dyn FunctionTargetProcessor>) {
        self.processors.push(processor)
    }

    /// Gets the last processor in the pipeline, for testing.
    pub fn last_processor(&self) -> &dyn FunctionTargetProcessor {
        self.processors
            .iter()
            .last()
            .expect("pipeline not empty")
            .as_ref()
    }

    /// Sort functions in topological order. This is important for the function target processors.
    /// In programs without recursion or mutual recursion, processing functions in topological order
    /// means that when a processor sees a caller function, it is guaranteed that all the callees
    /// have already been analyzed.
    pub fn sort_targets_in_topological_order<'env>(
        env: &'env GlobalEnv,
        targets: &FunctionTargetsHolder,
    ) -> Vec<FunctionEnv<'env>> {
        let mut worklist = vec![];
        for fun in targets.get_funs() {
            let fun_env = env.get_function(fun);
            worklist.push((
                fun,
                fun_env.get_called_functions().into_iter().collect_vec(),
            ));
        }
        let mut to_remove = vec![];
        let mut topological_order = vec![];
        // analyze bottom-up from the leaves of the call graph
        loop {
            let last = worklist.last();
            if last.is_none() {
                break;
            }
            // front of the worklist has a nonempty list of callees to analyze. walk through the
            // worklist and remove the analyzed callees from `to_remove` from each entry in the
            // worklist.
            if !last.unwrap().1.is_empty() {
                for (_f, f_callees) in &mut worklist {
                    for f in &to_remove {
                        f_callees.retain(|e| e != f);
                    }
                }
                // Put functions with 0 calls first in line, at the end of the vector
                worklist
                    .sort_by(|(_, callees1), (_, callees2)| callees2.len().cmp(&callees1.len()));
            }
            let (call_id, callees) = worklist.pop().unwrap();
            // At this point, one of two things is true:
            // 1. callees is empty (common case)
            // 2. callees is nonempty and mid is part of a recursive or mutually recursive
            //    intra-module call cycle (possible in theory, but doesn't happen in the current
            //    implementation of the Diem framework).
            to_remove.push(call_id);
            let func_env = env.get_function(call_id);
            if !callees.is_empty() {
                // The right long-term thing to do here is to allow analysis in case (2) and ask the
                // analysis processors to deal gracefully with the absence of summaries. But for
                // now, we intentionally fail because recursion is not expected in Diem Framework
                // code
                unimplemented!(
                    "Recursion or mutual recursion detected in {:?}. \
                     Make sure that all analyses in processors are prepared to handle recursion",
                    func_env.get_identifier()
                );
            }
            topological_order.push(func_env);
        }
        topological_order
    }

    /// Runs the pipeline on all functions in the targets holder. Processors are run on each
    /// individual function in breadth-first fashion; i.e. a processor can expect that processors
    /// preceding it in the pipeline have been executed for all functions before it is called.
    pub fn run_with_hook<H1, H2>(
        &self,
        env: &GlobalEnv,
        targets: &mut FunctionTargetsHolder,
        hook_before_pipeline: H1,
        hook_after_each_processor: H2,
    ) where
        H1: Fn(&FunctionTargetsHolder),
        H2: Fn(usize, &dyn FunctionTargetProcessor, &FunctionTargetsHolder),
    {
        let topological_order = Self::sort_targets_in_topological_order(env, targets);

        hook_before_pipeline(targets);
        for (step_count, processor) in self.processors.iter().enumerate() {
            if processor.is_single_run() {
                processor.run(env, targets);
            } else {
                processor.initialize(env, targets);
                for func_env in &topological_order {
                    targets.process(func_env, processor.as_ref());
                }
                processor.finalize(env, targets);
            }
            hook_after_each_processor(step_count + 1, processor.as_ref(), targets);
        }
    }

    /// Run the pipeline on all functions in the targets holder, with no hooks in effect
    pub fn run(&self, env: &GlobalEnv, targets: &mut FunctionTargetsHolder) {
        self.run_with_hook(env, targets, |_| {}, |_, _, _| {})
    }

    /// Runs the pipeline on all functions in the targets holder, dump the bytecode before the
    /// pipeline as well as after each processor pass. If `dump_cfg` is set, dump the per-function
    /// control-flow graph (in dot format) too.
    pub fn run_with_dump(
        &self,
        env: &GlobalEnv,
        targets: &mut FunctionTargetsHolder,
        dump_base_name: &str,
        dump_cfg: bool,
    ) {
        self.run_with_hook(
            env,
            targets,
            |holders| {
                Self::dump_to_file(
                    dump_base_name,
                    0,
                    "stackless",
                    &Self::get_pre_pipeline_dump(env, holders),
                )
            },
            |step_count, processor, holders| {
                let suffix = processor.name();
                Self::dump_to_file(
                    dump_base_name,
                    step_count,
                    &suffix,
                    &Self::get_per_processor_dump(env, holders, processor),
                );
                if dump_cfg {
                    Self::dump_cfg(env, holders, dump_base_name, step_count, &suffix);
                }
            },
        );
    }

    fn print_targets(env: &GlobalEnv, name: &str, targets: &FunctionTargetsHolder) -> String {
        print_targets_for_test(env, &format!("after processor `{}`", name), targets)
    }

    fn get_pre_pipeline_dump(env: &GlobalEnv, targets: &FunctionTargetsHolder) -> String {
        Self::print_targets(env, "stackless", targets)
    }

    fn get_per_processor_dump(
        env: &GlobalEnv,
        targets: &FunctionTargetsHolder,
        processor: &dyn FunctionTargetProcessor,
    ) -> String {
        let mut dump = format!(
            "{}",
            ProcessorResultDisplay {
                env,
                targets,
                processor
            }
        );
        if !processor.is_single_run() {
            if !dump.is_empty() {
                dump = format!("\n\n{}", dump);
            }
            dump.push_str(&Self::print_targets(env, &processor.name(), targets));
        }
        dump
    }

    fn dump_to_file(base_name: &str, step_count: usize, suffix: &str, content: &str) {
        let dump = format!("{}\n", content.trim());
        let file_name = format!("{}_{}_{}.bytecode", base_name, step_count, suffix);
        debug!("dumping bytecode to `{}`", file_name);
        fs::write(&file_name, &dump).expect("dumping bytecode");
    }

    /// Generate dot files for control-flow graphs.
    fn dump_cfg(
        env: &GlobalEnv,
        targets: &FunctionTargetsHolder,
        base_name: &str,
        step_count: usize,
        suffix: &str,
    ) {
        for (fun_id, variants) in &targets.targets {
            let func_env = env.get_function(*fun_id);
            let func_name = func_env.get_full_name_str();
            let func_name = func_name.replace("::", "__");
            for (variant, data) in variants {
                if !data.code.is_empty() {
                    let dot_file = format!(
                        "{}_{}_{}_{}_{}_cfg.dot",
                        base_name, step_count, suffix, func_name, variant
                    );
                    debug!("generating dot graph for cfg in `{}`", dot_file);
                    let func_target = FunctionTarget::new(&func_env, data);
                    let dot_graph = generate_cfg_in_dot_format(&func_target);
                    fs::write(&dot_file, &dot_graph).expect("generating dot file for CFG");
                }
            }
        }
    }
}
