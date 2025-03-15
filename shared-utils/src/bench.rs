use std::{collections::BTreeMap, time::Duration};

use csv::Writer;
use std::error::Error;
use std::fs::OpenOptions;

#[derive(Debug)]
pub struct BenchResult {
    pub curve: String,
    pub num_thread: usize,
    pub input_size: usize,
    pub num_invocations: usize,
    pub num_keygen_iterations: usize,
    pub num_prover_iterations: usize,
    pub num_verifier_iterations: usize,
    pub predicate_constraints: BTreeMap<String, usize>,
    pub num_constraints: usize,
    pub keygen_time: Duration,
    pub pk_size: usize,
    pub vk_size: usize,
    pub prover_time: Duration,
    pub proof_size: usize,
    pub verifier_time: Duration,
}

impl BenchResult {
    pub fn save_to_csv(&self, filename: &str, append: bool) -> Result<(), Box<dyn Error>> {
        // Configure file mode based on `append` flag
        let file = OpenOptions::new()
            .create(true)
            .append(append)
            .write(true)
            .truncate(!append) // If not appending, truncate the file (overwrite it)
            .open(filename)?;

        let mut writer = Writer::from_writer(file);

        // If creating a new file, write the headers
        if !append {
            writer.write_record(&[
                "Curve",
                "Num Threads",
                "Num Invocations",
                "Input Size",
                "Num Constraints",
                "Predicate Constraints",
                "Num KeyGen Iterations",
                "Setup Time (s)",
                "PK Size",
                "VK Size",
                "Num Prover Iterations",
                "Prover Time (s)",
                "Proof Size",
                "Num Verifier Iterations",
                "Verifier Time (ms)",
            ])?;
        }

        // Convert BTreeMap predicate constraints to a JSON-like string
        let predicate_constraints_str = serde_json::to_string(&self.predicate_constraints)?;

        // Convert durations to milliseconds
        let keygen_time_ms = self.keygen_time.as_secs_f64();
        let prover_time_ms = self.prover_time.as_secs_f64();
        let verifier_time_ms = self.verifier_time.as_secs_f64() * 1000.0;

        // Write the benchmark results as a row
        writer.write_record(&[
            &self.curve,
            &self.num_thread.to_string(),
            &self.num_invocations.to_string(),
            &self.input_size.to_string(),
            &self.num_constraints.to_string(),
            &predicate_constraints_str,
            &self.num_keygen_iterations.to_string(),
            &keygen_time_ms.to_string(),
            &self.pk_size.to_string(),
            &self.vk_size.to_string(),
            &self.num_prover_iterations.to_string(),
            &prover_time_ms.to_string(),
            &self.proof_size.to_string(),
            &self.num_verifier_iterations.to_string(),
            &verifier_time_ms.to_string(),
        ])?;

        writer.flush()?; // Ensure data is written

        println!(
            "✅ Benchmark result {} to {filename}",
            if append {
                "appended"
            } else {
                "saved (overwritten)"
            },
        );

        Ok(())
    }
}
