# Garuda Bench

This repository contains benchmarks for the Garuda Pari project. This README guides you through running and interpreting the benchmarks.

## Running Benchmarks

All benchmarks are located in the `benches` folder. You can run them using Cargo's benchmark feature.

To run a specific benchmark file:

```bash
cargo bench --bench [benchmark_name]
```

For example, to run the benchmark in `aptos-garuda.rs`:

```bash
cargo bench --bench aptos-groth16;
```