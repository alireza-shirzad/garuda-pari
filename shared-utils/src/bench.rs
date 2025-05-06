use ark_relations::utils::IndexMap;
use csv::Writer;
use std::error::Error;
use std::fs::{metadata, OpenOptions};
use std::time::Duration;

#[derive(Debug)]
pub struct BenchResult {
    pub curve: String,
    pub num_thread: usize,
    pub input_size: usize,
    pub num_invocations: usize,
    pub num_keygen_iterations: usize,
    pub num_prover_iterations: usize,
    pub num_verifier_iterations: usize,
    pub predicate_constraints: IndexMap<String, usize>,
    pub num_constraints: usize,
    pub keygen_time: Duration,
    pub keygen_prep_time: Duration,
    pub keygen_corrected_time: Duration,
    pub pk_size: usize,
    pub vk_size: usize,
    pub prover_time: Duration,
    pub prover_prep_time: Duration,
    pub prover_corrected_time: Duration,
    pub proof_size: usize,
    pub verifier_time: Duration,
}

impl BenchResult {
    pub fn save_to_csv(&self, filename: &str) -> Result<(), Box<dyn Error>> {
        let file_exists = metadata(filename).is_ok();

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(filename)?;

        let mut writer = Writer::from_writer(file);

        // If the file is newly created, write headers
        if !file_exists {
            writer.write_record([
                "Curve",
                "Num Threads",
                "Num Invocations",
                "Input Size",
                "Num Constraints",
                "Predicate Constraints",
                "Num KeyGen Iterations",
                "Setup Time (s)",
                "Setup Preparation Time (s)",
                "Setup Corrected Time (s)",
                "PK Size (bytes)",
                "VK Size (bytes)",
                "Num Prover Iterations",
                "Prover Time (s)",
                "Prover preparation Time (s)",
                "Prover Corrected Time (s)",
                "Proof Size (bytes)",
                "Num Verifier Iterations",
                "Verifier Time (ms)",
            ])?;
        }

        // Serialize data
        let predicate_constraints_str = serde_json::to_string(
            &self
                .predicate_constraints
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<Vec<_>>(),
        )?;
        let keygen_time_ms = self.keygen_time.as_secs_f64();
        let prover_time_ms = self.prover_time.as_secs_f64();
        let keygen_prep_time_ms = self.keygen_prep_time.as_secs_f64();
        let prover_prep_time_ms = self.prover_prep_time.as_secs_f64();
        let keygen_corrected_time_ms = self.keygen_corrected_time.as_secs_f64();
        let prover_corrected_time_ms = self.prover_corrected_time.as_secs_f64();
        let verifier_time_ms = self.verifier_time.as_secs_f64() * 1000.0;

        writer.write_record(&[
            Self::extract_curve_name(&self.curve).unwrap_or("-".to_string()),
            self.num_thread.to_string(),
            self.num_invocations.to_string(),
            self.input_size.to_string(),
            self.num_constraints.to_string(),
            predicate_constraints_str,
            self.num_keygen_iterations.to_string(),
            keygen_time_ms.to_string(),
            keygen_prep_time_ms.to_string(),
            keygen_corrected_time_ms.to_string(),
            match self.pk_size {
                0 => "-".to_string(),
                _ => self.pk_size.to_string(),
            },
            match self.vk_size {
                0 => "-".to_string(),
                _ => self.vk_size.to_string(),
            },
            self.num_prover_iterations.to_string(),
            prover_time_ms.to_string(),
            prover_prep_time_ms.to_string(),
            prover_corrected_time_ms.to_string(),
            match self.proof_size {
                0 => "-".to_string(),
                _ => self.proof_size.to_string(),
            },
            self.num_verifier_iterations.to_string(),
            verifier_time_ms.to_string(),
        ])?;

        writer.flush()?;

        println!("✅ Benchmark result saved to {filename}");
        Ok(())
    }

    fn extract_curve_name(input: &str) -> Option<String> {
        // Find the start and end of the first angle bracket pair
        let start = input.find('<')?;
        let end = input.find('>')?;

        // Slice the content inside the angle brackets
        let inside = &input[start + 1..end];

        // Split by "::" and take the first part
        let first_part = inside.split("::").next()?.to_string();

        Some(first_part)
    }
}
