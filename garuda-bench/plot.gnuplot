
set datafile separator ","

set xtics 2 nomirror font ",17"
set ytics nomirror font ",17"

set xrange [*:*]
set grid back lt 1 dt 3 lc rgb 'grey'
set border 3 back

set style line 1 lc rgb "#000000" linewidth 3 pointtype 5 pointsize 1.2
set style line 2 lc rgb "#F13F19" linewidth 2 pointtype 7 pointsize 1
set style line 3 lc rgb "#0020FF" linewidth 2 pointtype 9 pointsize 1
set style line 4 lc rgb "#008000" linewidth 2 pointtype 11 pointsize 1
set style line 5 lc rgb "#FF8000" linewidth 2 pointtype 13 pointsize 1
set style line 6 lc rgb "#8000FF" linewidth 2 pointtype 3 pointsize 1


set bmargin at screen 0.21
set key at screen 0.5, 0.04 center horizontal nobox font ",12" spacing 1
set key spacing 1.5
set key samplen 4

set logscale x 2
set logscale y 10
set format x "2^{%L}"
set format y "10^{%L}"

set terminal pdfcairo enhanced color font "Helvetica,15" size 5,5 background rgb 'white'

set xlabel "Number of Rescue invocations" offset 0,-1,0 font ",13"
set ylabel "Prover time (s)" offset -1,0,0 font ",13"
set output "plots/prover_4t.pdf"
plot \
     "results/rescue-garuda-gr1cs-4t.csv" using 3:($19) title 'Garuda (GR1CS)' with lp ls 1, \
     "results/rescue-garuda-r1cs-4t.csv" using 3:($17) title 'Garuda (R1CS)' with lp ls 2, \
     "results/rescue-spartan-ccs-4t.csv" using 3:($13) title 'SuperSpartan (CCS)' with lp ls 3, \
     "results/rescue-spartan-r1cs-4t.csv" using 3:($12) title 'Spartan (R1CS)' with lp ls 4, \
     "results/rescue-hyperplonk-plonkish-4t.csv" using 3:($12) title 'HP (Plonkish)' with lp ls 5, \
     "results/rescue-groth16-r1cs-4t.csv" using 3:($12) title 'Groth16 (R1CS)' with lp ls 6


set xlabel "Number of Rescue invocations" offset 0,-1,0 font ",13"
set ylabel "Prover time (s)" offset -1,0,0 font ",13"
set output "plots/prover_1t.pdf"
plot \
     "results/rescue-garuda-gr1cs-1t.csv" using 3:($19) title 'Garuda (GR1CS)' with lp ls 1, \
     "results/rescue-garuda-r1cs-1t.csv" using 3:($17) title 'Garuda (R1CS)' with lp ls 2, \
     "results/rescue-spartan-ccs-1t.csv" using 3:($13) title 'SuperSpartan (CCS)' with lp ls 3, \
     "results/rescue-spartan-r1cs-1t.csv" using 3:($12) title 'Spartan (R1CS)' with lp ls 4, \
     "results/rescue-hyperplonk-plonkish-1t.csv" using 3:($12) title 'HP (Plonkish)' with lp ls 5, \
     "results/rescue-groth16-r1cs-1t.csv" using 3:($12) title 'Groth16 (R1CS)' with lp ls 6





set yrange [*:*]
set xlabel "Number of Rescue invocations" offset 0,-1,0 font ",13"
set ylabel "Setup time (s)" offset -1,0,0 font ",13"
set output "plots/setup_1t.pdf"
plot \
     "results/rescue-garuda-gr1cs-1t.csv" using 3:($9) title 'Garuda (GR1CS)' with lp ls 1, \
     "results/rescue-garuda-r1cs-1t.csv" using 3:($8) title 'Garuda (R1CS)' with lp ls 2, \
     "results/rescue-spartan-ccs-1t.csv" using 3:($9) title 'SuperSpartan (CCS)' with lp ls 3, \
     "results/rescue-spartan-r1cs-1t.csv" using 3:($8) title 'Spartan (R1CS)' with lp ls 4, \
     "results/rescue-hyperplonk-plonkish-1t.csv" using 3:($8) title 'HP (Plonkish)' with lp ls 5



set yrange [*:*]
set xlabel "Number of Rescue invocations" offset 0,-1,0 font ",13"
set ylabel "Setup time (s)" offset -1,0,0 font ",13"
set output "plots/setup_4t.pdf"
plot \
     "results/rescue-garuda-gr1cs-4t.csv" using 3:($9) title 'Garuda (GR1CS)' with lp ls 1, \
     "results/rescue-garuda-r1cs-4t.csv" using 3:($8) title 'Garuda (R1CS)' with lp ls 2, \
     "results/rescue-spartan-ccs-4t.csv" using 3:($9) title 'SuperSpartan (CCS)' with lp ls 3, \
     "results/rescue-spartan-r1cs-4t.csv" using 3:($8) title 'Spartan (R1CS)' with lp ls 4, \
     "results/rescue-hyperplonk-plonkish-4t.csv" using 3:($8) title 'HP (Plonkish)' with lp ls 5




set yrange [120:28000]
set xlabel "Number of Rescue invocations" offset 0,-1,0 font ",13"
set ylabel "Proof size (Bytes)" offset -1,0,0 font ",13"
set output "plots/proof.pdf"
plot \
     "results/rescue-garuda-gr1cs-1t.csv" using 3:($20) title 'Garuda (GR1CS)' with lp ls 1, \
     "results/rescue-garuda-r1cs-1t.csv" using 3:($18) title 'Garuda (R1CS)' with lp ls 2, \
     "results/rescue-hyperplonk-plonkish-1t.csv" using 3:($13) title 'HP' with lp ls 5, \
     "results/rescue-groth16-r1cs-1t.csv" using 3:($13) title 'Groth16 (R1CS)' with lp ls 6
     # "results/rescue-spartan-ccs-1t.csv" using 3:($14) title 'SuperSpartan' with lp ls 3, \
     # "results/rescue-spartan-r1cs-1t.csv" using 3:($13) title 'Spartan' with lp ls 4, \


unset format y
set yrange [2.6:15.1]
set xlabel "Number of Rescue invocations" offset 0,-1,0 font ",13"
set ylabel "Verification time (ms)" offset -1,0,0 font ",13"
set output "plots/verifier.pdf"
plot \
     "results/rescue-garuda-gr1cs-1t.csv" using 3:($22) title 'Garuda (GR1CS)' with lp ls 1, \
     "results/rescue-garuda-r1cs-1t.csv" using 3:($20) title 'Garuda (R1CS)' with lp ls 2, \
     "results/rescue-hyperplonk-plonkish-1t.csv" using 3:($15) title 'Hyperplonk (Plonkish)' with lp ls 5, \
     "results/rescue-groth16-r1cs-1t.csv" using 3:($15) title 'Groth16 (R1CS)' with lp ls 6
     # "results/rescue-spartan-ccs-1t.csv" using 3:($16) title 'SuperSpartan' with lp ls 3, \
     # "results/rescue-spartan-r1cs-1t.csv" using 3:($15) title 'Spartan' with lp ls 4, \
