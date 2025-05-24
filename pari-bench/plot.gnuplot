
set datafile separator ","

set xtics 2 nomirror font ",20"
set ytics nomirror font ",20"

set xrange [*:*]
set yrange [*:*]
set grid back lt 1 dt 3 lc rgb 'grey'
set border 3 back
set bmargin at screen 0.21
set key at screen 0.5, 0.04 center horizontal nobox font ",20" spacing 1

set style line 1 lc rgb "#000000" linewidth 3 pointtype 5 pointsize 1.2
set style line 2 lc rgb "#F13F19" linewidth 2 pointtype 7 pointsize 1
set style line 3 lc rgb "#0020FF" linewidth 2 pointtype 9 pointsize 1
set style line 4 lc rgb "#008000" linewidth 2 pointtype 11 pointsize 1
set style line 5 lc rgb "#FF8000" linewidth 2 pointtype 13 pointsize 1
set style line 6 lc rgb "#8000FF" linewidth 2 pointtype 3 pointsize 1



set key spacing 1.5
set key samplen 4

set logscale x 2
set logscale y 10
set format x "2^{%L}"
# set format y "10^{%L}"

set terminal pdfcairo enhanced color font "Helvetica,15" size 5,5 background rgb 'white'

set xlabel "Input Size" offset 0,-1,0 font ",24"
set ylabel "Gas Cost (×10⁴)" offset 0,0,0 font ",24"
set output "plots/gas-comparison.pdf"
plot \
     "results/gas-comparison.csv" using 1:($2/100000) title 'Pari' with lp ls 1, \
     "results/gas-comparison.csv" using 1:($3/100000) title 'Groth16' with lp ls 3, \
     "results/gas-comparison.csv" using 1:($5/100000) title 'Polymath' with lp ls 4, \
     "results/gas-comparison.csv" using 1:($4/100000) title 'FFLONK' with lp ls 2


# Verification Time Plot for Pari and Groth16
set output "plots/verification_time.pdf"
set xlabel "Input Size" offset 0,-1,0 font ",24"
set ylabel "Verification Time (ms)" offset 0,0,0 font ",24"

plot \
     "results/rescue-pari-1t-input.csv" using 4:($16/1) title 'Pari' with lp ls 1, \
     "results/rescue-groth16-1t-input.csv" using 4:($15/1) title 'Groth16' with lp ls 3, \
     "results/rescue-polymath-1t-input.csv" using 4:($15/1) title 'Polymath' with lp ls 4

set format x "%L"
# Prover Time Plot for Pari and Groth16 vs Number of Constraints
set output "plots/prover_time_1.pdf"
set xlabel "Log of Number of R1CS Constraints" offset 0,-1,0 font ",24"
set ylabel "Prover Time (s)" offset -0.5,0,0 font ",24"

plot \
     "results/rescue-pari-1t.csv" using 5:($13) title 'Pari' with lp ls 1, \
     "results/rescue-groth16-1t.csv" using 5:($12) title 'Groth16' with lp ls 3, \
     "results/rescue-polymath-1t.csv" using 5:($12) title 'Polymath' with lp ls 4



# # Prover Time Plot for Pari and Groth16 vs Number of Constraints
# set output "prover_time_4.pdf"
# set xlabel "Log of Number of R1CS Constraints" offset 0,-1,0 font ",13"
# set ylabel "Prover Time (s)" offset -1,0,0 font ",13"

# plot \
#      "pari_cnst_input_4.csv" using 5:($13) title 'Pari' with lp ls 1, \
#      "groth16_cnst_input_4.csv" using 5:($12) title 'Groth16' with lp ls 3, \
#      "polymath_cnst_input_4.csv" using 5:($12) title 'Polymath' with lp ls 4


#      # Verification Key Size Plot for Pari and Groth16 vs Number of Constraints
# set output "verification_key_size.pdf"
# set xlabel "Log of Number of R1CS Constraints" offset 0,-1,0 font ",13"
# set ylabel "Verification Key Size (Bytes)" offset -1,0,0 font ",13"

# plot \
#      "pari_cnst_input_1.csv" using 5:($10) title 'Pari Verification Key Size' with lp ls 1, \
#      "groth16_cnst_input_1.csv" using 5:($10) title 'Groth16 Verification Key Size' with lp ls 3

# # Proving Key Size Plot for Pari and Groth16 vs Number of Constraints
# set output "proving_key_size.pdf"
# set xlabel "Log of Number of R1CS Constraints" offset 0,-1,0 font ",13"
# set ylabel "Proving Key Size (Bytes)" offset -1,0,0 font ",13"

# plot \
#      "pari_cnst_input_1.csv" using 5:($9) title 'Pari Proving Key Size' with lp ls 1, \
#      "groth16_cnst_input_1.csv" using 5:($9) title 'Groth16 Proving Key Size' with lp ls 3


