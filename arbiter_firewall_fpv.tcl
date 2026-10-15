# =============================================================================
# File        : arbiter_firewall_fpv.tcl
# Purpose     : Synopsys VC Formal (FPV) setup and execution for the integrated
#               fixed-priority arbiter, AXI4 security firewall, and subordinate
#               routing architecture described in the accompanying manuscript.
#
# Design under verification:
#   Top module             : arbiter_firewall_top
#   Default configuration  : 6 AXI4 managers; 7 protected subordinates;
#                            policy timeout enabled, 32 cycles.
#   These defaults are declared in arbiter_firewall_top.sv, not overridden here.
#
# Source files (all six are required in the script's working directory):
#   arbiter_fp_rtl.sv         Fixed-priority arbiter RTL
#   arbiter_fp_assertions.sv  Arbiter assertions and cover properties
#   axi_firewall.sv          Transaction-level AXI4 firewall RTL
#   axi_firewall_sva.sv      Firewall assertions and cover properties
#   arbiter_firewall_top.sv  Integrated RTL wrapper and subordinate decoder
#   arbiter_firewall_top_sva.sv
#                            End-to-end checker, including the external
#                            interface assumptions and integration properties
#
# Proof boundary:
#   The integrated RTL and bound checkers are elaborated. External AXI4
#   managers, subordinates, and policy-interface behaviors are constrained by
#   the SVA assumptions defined in the checker source files. The correctness
#   of the external policy-decision algorithm is not proved by this script.
#
# Verification setup:
#   FPV mode; vacuity and witness checks enabled; clock 'clk'; active-low
#   reset 'rst_n'. The stable state is reached and saved before proof begins.
#   The manuscript-reported integrated run has 60 elaborated SVA assumptions plus
#   one saved-reset constraint (61 formal constraints), 409 elaborated
#   assertions, and 149 cover-property instances. These are reported results,
#   not values enforced by this TCL script.
# =============================================================================

# 1. Enable Formal Property Verification (FPV) application mode.
set_app_var fml_mode_on true
set_fml_appmode FPV

# Enable vacuity analysis and witness generation for the reported proof run.
set_fml_var fml_vacuity_on true
set_fml_var fml_witness_on true

# 2. Runtime and resource limits. The auto-scale task count and the grid
# worker allocation below are different settings; retain both as evaluated.
set_fml_var fml_max_time 200H
set_fml_var fml_max_mem 12GB
set_fml_var fml_auto_scale_task_count 16

# Allocate 12 remote-shell VC Formal workers on the evaluation machine.
set_grid_usage -type rsh=12

# Record the selected settings in the tool log for run reproducibility.
puts "Max time         = [get_fml_var fml_max_time]"
puts "Memory           = [get_fml_var fml_max_mem]"
puts "Auto-scale tasks = [get_fml_var fml_auto_scale_task_count]"

# Record the effective grid/worker configuration.
report_grid_usage

# 3. Read the three RTL modules and their three matching SVA checker modules.
# The default integrated task uses the top-level checker plus component
# checker bindings, with integration mode selected by the wrapper instance.
# Relative filenames require launching VC Formal from the source directory
# (or first setting the working directory to that directory).
# No separate standalone arbiter or firewall proof is invoked by this script.
analyze -format sverilog -vcs \
{
    arbiter_fp_rtl.sv
    arbiter_fp_assertions.sv

    axi_firewall.sv
    axi_firewall_sva.sv

    arbiter_firewall_top.sv
    arbiter_firewall_top_sva.sv
}

# 4. Elaborate the integrated wrapper as the proof top with SVA enabled.
# The six-manager, seven-subordinate, 32-cycle-timeout defaults come from RTL.
elaborate arbiter_firewall_top -sva

# 5. Declare the formal clock and active-low reset. Preserve the clock period
# exactly as used by the VC Formal setup; it is not the separate FPGA/ASIC
# synthesis target-clock setting discussed in the implementation results.
create_clock clk -period 4000
create_reset rst_n -low

# 6. Establish and save a stable reset state before starting formal proof.
# The saved post-reset state contributes the additional reset constraint
# documented in the Formal Assumption Catalog.
sim_run -stable
sim_save_reset

# 7. Start the integrated formal verification run (assertions, covers,
# vacuity analysis, and witnesses under the active formal constraints).
check_fv
