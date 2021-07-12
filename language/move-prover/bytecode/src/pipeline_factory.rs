// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    borrow_analysis::BorrowAnalysisProcessor,
    clean_and_optimize::CleanAndOptimizeProcessor,
    data_invariant_instrumentation::DataInvariantInstrumentationProcessor,
    debug_instrumentation::DebugInstrumenter,
    eliminate_imm_refs::EliminateImmRefsProcessor,
    function_target_pipeline::{FunctionTargetPipeline, FunctionTargetProcessor},
    global_invariant_instrumentation::GlobalInvariantInstrumentationProcessor,
    global_invariant_instrumentation_v2::GlobalInvariantInstrumentationProcessorV2,
    livevar_analysis::LiveVarAnalysisProcessor,
    loop_analysis::LoopAnalysisProcessor,
    memory_instrumentation::MemoryInstrumentationProcessor,
    mono_analysis::MonoAnalysisProcessor,
    mut_ref_instrumentation::MutRefInstrumenter,
    mutation_tester::MutationTester,
    options::ProverOptions,
    reaching_def_analysis::ReachingDefProcessor,
    spec_instrumentation::SpecInstrumentationProcessor,
    usage_analysis::UsageProcessor,
    verification_analysis::VerificationAnalysisProcessor,
    verification_analysis_v2::VerificationAnalysisProcessorV2,
};

pub fn default_pipeline_with_options(options: &ProverOptions) -> FunctionTargetPipeline {
    // NOTE: the order of these processors is import!
    let mut processors: Vec<Box<dyn FunctionTargetProcessor>> = vec![
        DebugInstrumenter::new(),
        // transformation and analysis
        EliminateImmRefsProcessor::new(),
        MutRefInstrumenter::new(),
        ReachingDefProcessor::new(),
        LiveVarAnalysisProcessor::new(),
        BorrowAnalysisProcessor::new(),
        MemoryInstrumentationProcessor::new(),
        CleanAndOptimizeProcessor::new(),
        UsageProcessor::new(),
        if options.invariants_v2 {
            VerificationAnalysisProcessorV2::new()
        } else {
            VerificationAnalysisProcessor::new()
        },
        LoopAnalysisProcessor::new(),
        // spec instrumentation
        SpecInstrumentationProcessor::new(),
        DataInvariantInstrumentationProcessor::new(),
        if options.invariants_v2 {
            GlobalInvariantInstrumentationProcessorV2::new()
        } else {
            GlobalInvariantInstrumentationProcessor::new()
        },
    ];
    if options.mutation {
        processors.insert(0, MutationTester::new()); // pass which may do nothing
    }
    if options.run_mono {
        processors.push(MonoAnalysisProcessor::new());
    }

    let mut res = FunctionTargetPipeline::default();
    for p in processors {
        res.add_processor(p);
    }
    res
}

pub fn default_pipeline() -> FunctionTargetPipeline {
    default_pipeline_with_options(&ProverOptions::default())
}

pub fn experimental_pipeline() -> FunctionTargetPipeline {
    // Enter your pipeline here
    unimplemented!("No experimental pipeline set");
}
