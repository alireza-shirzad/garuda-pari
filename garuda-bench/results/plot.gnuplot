# --- Terminal and Output Setup ---
# Set the terminal to pdfcairo for high-quality PDF output.
# The size is adjusted to 12x5 to accommodate the shared key below the plots.
set terminal pdfcairo enhanced color font "Times New Roman,15" size 12,6 background rgb 'white'
set output "prover_proof_verifier_shared_key.pdf"

# --- Global Settings for All Plots ---
set datafile separator ","
set xtics 2 nomirror font ",17"
set ytics nomirror font ",17"
set xrange [*:*] # Use autoscale for the main plots
set grid back lt 1 dt 3 lc rgb 'grey'
set border 3 back

# Define line styles. These will be used by the plots and the shared key.
set style line 1 lc rgb "#000000" linewidth 3 pointtype 5 pointsize 1.2
set style line 2 lc rgb "#F13F19" linewidth 2 pointtype 7 pointsize 1
set style line 3 lc rgb "#0020FF" linewidth 2 pointtype 9 pointsize 1
set style line 4 lc rgb "#008000" linewidth 2 pointtype 11 pointsize 1
set style line 5 lc rgb "#FF8000" linewidth 2 pointtype 13 pointsize 1
set style line 6 lc rgb "#F080F0" linewidth 2 pointtype 16 pointsize 1

# Set logarithmic scales and formatting for the main plots.
set logscale x 2
set logscale y 10
set format x "2^{%L}"
set format y "10^{%L}"

# --- Multiplot Layout ---
# Arrange plots in a 2-row, 3-column grid.
# Vertical spacing is minimized to place the key right under the plots.
set multiplot layout 2, 3 spacing 0.08, 0.0

# Disable the key for the main plots, as we will draw a shared one later.
set key off

# ======================================================================
# --- Plot 1 (Top-Left): Prover Time ---
# ======================================================================
set xlabel "Number of Rescue invocations" offset 0,-1,0 font ",25"
set ylabel "Prover time (s)" offset -1,0,0 font ",25"
set yrange [*:*]
set xrange [2**2:2**12]

# Note: The 'title' attribute is removed from the plot commands.
# set size ratio 1
plot \
    "rescue-garuda-gr1cs--1t.csv" using 3:($13) with lp ls 1, \
    "rescue-garuda-r1cs--1t.csv" using 3:($12) with lp ls 2, \
    "rescue-spartan-ccs-nizk--1t.csv" using 3:($18) with lp ls 3, \
    "rescue-spartan-nizk-r1cs-1t.csv" using 3:($18) with lp ls 4, \
    "hyperplonk.csv" using 3:($17) with lp ls 5, \
    "rescue-groth16-1t.csv" using 3:($12) with lp ls 6
# ======================================================================
# --- Plot 2 (Top-Middle): Proof Size ---
# ======================================================================
# set size ratio 1
set yrange [*:*]
set xlabel "Number of Rescue invocations" offset 0,-1,0 font ",25"
set ylabel "Proof size (Bytes)" offset -1,0,0 font ",25"

plot \
    "rescue-garuda-gr1cs--1t.csv" using 3:($21) with lp ls 1, \
    "rescue-garuda-r1cs--1t.csv" using 3:($19) with lp ls 2, \
    "rescue-spartan-ccs-nizk--1t.csv" using 3:($21) with lp ls 3, \
    "rescue-spartan-nizk-r1cs-1t.csv" using 3:($19) with lp ls 4, \
    "hyperplonk.csv" using 3:($18) with lp ls 5,\
    "rescue-groth16-1t.csv" using 3:($19) with lp ls 6
# ======================================================================
# --- Plot 3 (Top-Right): Verification Time ---
# ======================================================================
# set size ratio 1
set yrange [*:*]
set xlabel "Number of Rescue invocations" offset 0,-1,0 font ",25"
set ylabel "Verification time (ms)" offset -1,0,0 font ",25"

plot     "rescue-garuda-gr1cs--1t.csv" using 3:($23) with lp ls 1, \
         "rescue-garuda-r1cs--1t.csv" using 3:($21) with lp ls 2, \
         "rescue-spartan-ccs-nizk--1t.csv" using 3:($23) with lp ls 3, \
         "rescue-spartan-nizk-r1cs-1t.csv" using 3:($21) with lp ls 4, \
         "hyperplonk.csv" using 3:($20) with lp ls 5,\
     "rescue-groth16-1t.csv" using 3:($21) with lp ls 6
# ======================================================================
# --- Row 2: Placeholders and Shared Key ---
# ======================================================================

# Unset log scales and formats for the placeholder plots.
unset logscale
unset format

# --- Plot 4 (Bottom-Left): Empty Placeholder ---
# Make this plot cell invisible to leave the space blank.
set border 0
unset tics
unset xlabel
unset ylabel
set xrange [0:1] # Set a dummy range
set yrange [0:1]
plot -10 notitle # Plot an out-of-range point

# --- Plot 5 (Bottom-Middle): Shared Key ---
# This invisible plot's only purpose is to draw the shared legend.
set border 0
unset tics
unset xlabel
unset ylabel
set xrange [0:1] # Set a dummy range for the key plot
set yrange [0:1]

# Configure the key to be horizontal and centered at the top of this cell.
# set key vertical center top 

# # Make the key more compact to fit on one line
# # set key spacing 0.9
# set key samplen 2
# set key font ",19"
set key outside maxrows 2 top center font ",22" samplen 2 spacing 1.2

# Plot an out-of-range point (-10) for each line style to force the
# key entry to be drawn without any visible data points.
plot \
    -10 with lp ls 1 title 'Garuda (GR1CS)', \
    -10 with lp ls 2 title 'Garuda (R1CS)', \
    -10 with lp ls 3 title 'SuperSpartan (CCS)', \
    -10 with lp ls 4 title 'Spartan (R1CS)', \
    -10 with lp ls 5 title 'HP (Plonkish)',\
    -10 with lp ls 6 title 'Groth16 (R1CS)'

# Reset key options to default after use.
set key default

# --- Plot 6 (Bottom-Right): Empty Placeholder ---
# Use the same technique to keep this cell blank.
set border 0
unset tics
set xrange [0:1]
set yrange [0:1]
plot -10 notitle

# --- End Multiplot ---
unset multiplot

# # ======================================================================
# # --- Additional Plot: Combined Random Prover Times ---
# # ======================================================================
# set terminal pdfcairo enhanced color font "Times New Roman,15" size 12,6 background rgb 'white'
# set output "random.pdf"
# set datafile separator ","

# set grid back lt 1 dt 3 lc rgb 'grey'
# set border 3 back
# set xtics 2 nomirror font ",17"
# set ytics nomirror font ",17"
# set key top left font ",18"

# set xlabel "Number of constraints" offset 0,-1,0 font ",25"
# set ylabel "Prover time (s)" offset -1,0,0 font ",25"

# set logscale x 2
# set logscale y 10
# set format x "2^{%L}"
# set format y "10^{%L}"
# set xrange [*:4096]
# set yrange [*:*]

# plot \
#     "random-garuda-1t.csv" using 6:($18) with lp ls 1 title "Garuda (R1CS)", \
#     "random-spartan-1t.csv" using 6:($18) with lp ls 4 title "Spartan (R1CS)", \
#     "random-garuda-gr1cs-1t.csv" using 6:($20) with lp ls 2 title "Garuda (GR1CS)", \
#     "random-spartan-ccs-1t.csv" using 6:($20) with lp ls 3 title "Spartan (CCS)"
# unset output

# # ======================================================================
# # --- Additional Plot: Prover Corrected Time vs. Nonzero Entries ---
# # ======================================================================
# set terminal pdfcairo enhanced color font "Times New Roman,15" size 12,6 background rgb 'white'
# set output "random_addition.pdf"
# set datafile separator ","

# set grid back lt 1 dt 3 lc rgb 'grey'
# set border 3 back
# set xtics 2 nomirror font ",17"
# set ytics nomirror font ",17"
# set key top left font ",18"

# set xlabel "Number of nonzero entries" offset 0,-1,0 font ",25"
# set ylabel "Prover corrected time (s)" offset -1,0,0 font ",25"

# set logscale x 2
# set logscale y 10
# set format x "2^{%L}"
# set format y "10^{%L}"
# set xrange [*:*]
# set yrange [*:*]

# plot \
#     "random-garuda-addition-1t.csv" using 5:($18) with lp ls 1 title "Garuda (R1CS)", \
#     "random-garuda-gr1cs-addition-1t.csv" using 5:($20) with lp ls 2 title "Garuda (GR1CS)", \
#     "random-spartan-addition-1t.csv" using 5:($18) with lp ls 4 title "Spartan (R1CS)", \
#     "random-spartan-ccs-addition-1t.csv" using 5:($18) with lp ls 3 title "Spartan (CCS)"
# unset output

# # ======================================================================
# # --- Additional Plot: Random + Addition with Shared Key ---
# # ======================================================================
# set terminal pdfcairo enhanced color font "Times New Roman,15" size 9,6 background rgb 'white'
# set output "random_shared_key.pdf"
# set datafile separator ","

# set grid back lt 1 dt 3 lc rgb 'grey'
# set border 3 back
# set xtics 2 nomirror font ",17"
# set ytics nomirror font ",17"

# set multiplot layout 2,2 spacing 0.08,0.0
# set key off

# # Random prover time
# set logscale x 2
# set logscale y 10
# set format x "2^{%L}"
# set format y "10^{%L}"
# set xrange [*:4096]
# set yrange [*:*]
# set xlabel "Number of constraints" offset 0,-1,0 font ",25"
# set ylabel "Prover time (s)" offset -1,0,0 font ",25"
# plot \
#     "random-garuda-1t.csv" using 6:($18) with lp ls 1, \
#     "random-spartan-1t.csv" using 6:($18) with lp ls 4, \
#     "random-garuda-gr1cs-1t.csv" using 6:($20) with lp ls 2, \
#     "random-spartan-ccs-1t.csv" using 6:($20) with lp ls 3

# # Random addition prover corrected time
# set xrange [*:*]
# set yrange [*:*]
# set xlabel "Number of nonzero entries" offset 0,-1,0 font ",25"
# set ylabel "Prover corrected time (s)" offset -1,0,0 font ",25"
# plot \
#     "random-garuda-addition-1t.csv" using 5:($18) with lp ls 1, \
#     "random-garuda-gr1cs-addition-1t.csv" using 5:($20) with lp ls 2, \
#     "random-spartan-addition-1t.csv" using 5:($18) with lp ls 4, \
#     "random-spartan-ccs-addition-1t.csv" using 5:($18) with lp ls 3

# # Empty cell
# unset logscale
# unset format
# set border 0
# unset tics
# unset xlabel
# unset ylabel
# set xrange [0:1]
# set yrange [0:1]
# plot -10 notitle

# # Shared key
# set border 0
# unset tics
# unset xlabel
# unset ylabel
# set xrange [0:1]
# set yrange [0:1]
# set key at screen 0.5,0.46 center center horizontal maxrows 1 font ",18" samplen 1.5 spacing 1.0
# plot \
#     1/0 with lp ls 1 title 'Garuda R1CS', \
#     1/0 with lp ls 2 title 'Garuda GR1CS', \
#     1/0 with lp ls 3 title 'Spartan CCS', \
#     1/0 with lp ls 4 title 'Spartan R1CS'

# set key default
# unset multiplot
# unset output
