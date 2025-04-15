use ark_bls12_381::Fr;
use ark_crypto_primitives::crh::rescue::CRH;
use ark_crypto_primitives::crh::CRHScheme;
use ark_relations::gr1cs::{self, ConstraintSystem, OptimizationGoal};
use ark_relations::gr1cs::instance_outliner::outline_r1cs;
use ark_relations::gr1cs::instance_outliner::InstanceOutliner;
use ark_relations::gr1cs::ConstraintSynthesizer;
use ark_relations::gr1cs::R1CS_PREDICATE_LABEL;
use ark_std::{end_timer, start_timer};
use ark_std::rc::Rc;
use ark_std::UniformRand;
use ark_std::{
    rand::{RngCore, SeedableRng},
    test_rng,
};

use garuda_bench::{create_test_rescue_parameter, RescueDemo};



fn main() {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let config = create_test_rescue_parameter(&mut rng);
    let mut input = Vec::new();
    for _ in 0..9 {
        input.push(Fr::rand(&mut rng));
    }
    let mut expected_image = CRH::<Fr>::evaluate(&config, input.clone()).unwrap();
    let num_invocations = 16384;
    let input_size =  20;

    for _i in 0..(num_invocations - 1) {
        let output = vec![expected_image; 9];
        expected_image = CRH::evaluate(&config, output.clone()).unwrap();
    }
    let circuit = RescueDemo::<Fr> {
        input: Some(input.clone()),
        image: Some(expected_image),
        config: config.clone(),
        num_invocations,
        num_instances: input_size,
    };
    // Start up the constraint System and synthesize the circuit
    let timer_cs_startup = start_timer!(|| "Building Constraint System");
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    // cs.set_mode(gr1cs::SynthesisMode::Setup);
    cs.set_mode(gr1cs::SynthesisMode::Prove {
        construct_matrices: true,
        generate_lc_assignments: false,
    });
    cs.set_instance_outliner(InstanceOutliner {
        pred_label: R1CS_PREDICATE_LABEL.to_string(),
        func: Rc::new(outline_r1cs),
    });
    let timer_synthesize_circuit = start_timer!(|| "Synthesize Circuit");
    circuit.generate_constraints(cs.clone()).unwrap();
    end_timer!(timer_synthesize_circuit);
    let timer_inlining = start_timer!(|| "Inlining constraints");
    cs.finalize();
    end_timer!(timer_inlining);
    end_timer!(timer_cs_startup);
}