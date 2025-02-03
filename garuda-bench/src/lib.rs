use std::{collections::BTreeMap, time::Duration};

use std::fs::OpenOptions;
use std::io::Write;
use std::error::Error;
use csv::Writer;

#[derive(Debug)]
pub struct BenchResult {
    pub curve: String,
    pub num_thread: usize,
    pub num_iterations: usize,
    pub num_invocations: usize,
    pub predicate_constraints: BTreeMap<String, usize>,
    pub num_constraints: usize,
    pub setup_time: Duration,
    pub pk_size: usize,
    pub vk_size: usize,
    pub prover_time: Duration,
    pub proof_size: usize,
    pub verifier_time: Duration,
}


impl BenchResult {

    pub fn save_to_csv(&self, append: bool) -> Result<(), Box<dyn Error>> {
        let filename = "benchmarks.csv";
    
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
                "Num Iterations",
                "Num Invocations",
                "Num Constraints",
                "Predicate Constraints",
                "Setup Time (ms)",
                "PK Size",
                "VK Size",
                "Prover Time (ms)",
                "Proof Size",
                "Verifier Time (ms)",
            ])?;
        }
    
        // Convert BTreeMap predicate constraints to a JSON-like string
        let predicate_constraints_str = serde_json::to_string(&self.predicate_constraints)?;
    
        // Convert durations to milliseconds
        let setup_time_ms = self.setup_time.as_secs();
        let prover_time_ms = self.prover_time.as_secs();
        let verifier_time_ms = self.verifier_time.as_millis();
    
        // Write the benchmark results as a row
        writer.write_record(&[
            &self.curve,
            &self.num_thread.to_string(),
            &self.num_iterations.to_string(),
            &self.num_invocations.to_string(),
            &self.num_constraints.to_string(),
            &predicate_constraints_str,
            &setup_time_ms.to_string(),
            &self.pk_size.to_string(),
            &self.vk_size.to_string(),
            &prover_time_ms.to_string(),
            &self.proof_size.to_string(),
            &verifier_time_ms.to_string(),
        ])?;
    
        writer.flush()?; // Ensure data is written
    
        println!(
            "✅ Benchmark result {} to {}",
            if append { "appended" } else { "saved (overwritten)" },
            filename
        );
    
        Ok(())
    }
}
