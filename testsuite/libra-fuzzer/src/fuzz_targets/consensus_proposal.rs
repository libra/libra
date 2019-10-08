use crate::FuzzTargetImpl;
use libra_consensus::event_processor_fuzzing::{fuzz_proposal, generate_corpus_proposal};
use proptest_helpers::ValueGenerator;

#[derive(Clone, Debug, Default)]
pub struct ConsensusProposal;

impl FuzzTargetImpl for ConsensusProposal {
    fn name(&self) -> &'static str {
        module_name!()
    }

    fn description(&self) -> &'static str {
        "Consensus proposal messages"
    }

    fn generate(&self, _idx: usize, _gen: &mut ValueGenerator) -> Option<Vec<u8>> {
        Some(generate_corpus_proposal())
    }

    fn fuzz(&self, data: &[u8]) {
        fuzz_proposal(data);
    }
}
