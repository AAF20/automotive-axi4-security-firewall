// =============================================================================
// File        : arbiter_fp_assertions.sv
// Module      : arbiter_fp_assertions
// Purpose     : Safety assertions and reachability covers for the parameterized
//               combinational fixed-priority arbiter (arbiter_fp_rtl.sv).
//
// Verification integration:
//   - Attached to arbiter_fp_rtl by the unchanged bind statement in that file.
//   - clk provides the default positive-edge property sampling clock.
//   - req[0] is highest priority; a grant may be given only to a requesting
//     input that has no active higher-priority (lower-indexed) competitor.
//   - NUM_REQS is the request/grant vector width (six in the integrated run).
//   - SVA_INTEGRATION_MODE disables only the standalone sequential-yield cover;
//     it does not disable the six safety-assertion templates or three active
//     integrated cover templates.
//
// Catalog cross-reference:
//   - Six source-level assertion labels: Formal Assertion Catalog, Family 2
//     (Arbitration and Ownership).
//   - Three active cover templates: Formal Cover Property Catalog,
//     Fixed-Priority Arbiter Reachability; these elaborate to twelve instances
//     for the evaluated six-requester integrated configuration.
//   - cov_yield_to_lower is standalone-only, so it is excluded from the
//     integrated configuration's active-cover catalog and result totals.
//   - Each active assertion/cover description below reproduces the corresponding
//     finalized manuscript appendix description verbatim.
//
// =============================================================================
// Bound checker: all inputs are observed; this module drives no DUT outputs.
module arbiter_fp_assertions #(
    parameter int NUM_REQS = 6,
    parameter bit SVA_INTEGRATION_MODE = 1'b0
)(
    input logic clk,
    input logic [NUM_REQS-1:0] req,
    input logic [NUM_REQS-1:0] grant
);

    // Properties use the rising edge of clk unless explicitly overridden.
    default clocking cb @(posedge clk); endclocking

    // Formal Assertion Catalog -- Family 2: Arbitration and Ownership
    // ast_idle_silence: Requires no grant when no arbitration request is active.
    ast_idle_silence: assert property (
        (req == '0) |-> (grant == '0)
    );

    // ast_mutual_exclusion: Allows at most one arbiter grant at a time.
    ast_mutual_exclusion: assert property (
        $onehot0(grant)
    );

    // ast_work_conservation: Requires a grant whenever at least one request is active.
    ast_work_conservation: assert property (
        (|req) |-> (|grant)
    );

    generate
        for (genvar i = 0; i < NUM_REQS; i++) begin : gen_grant_validity
            
            // Formal Assertion Catalog -- Family 2 (one instance per requester)
            // ast_grant_validity: Allows a grant only to a requester that is currently requesting.
            ast_grant_validity: assert property (
                grant[i] |-> req[i]
            );
            
        end
    endgenerate

    generate
        for (genvar i = 0; i < NUM_REQS; i++) begin : gen_strict_priority
            
            if (i == 0) begin
                // The highest-priority requester occupies vector index zero.
                // ast_prio_highest_exact: Requires the highest-priority requester to receive the grant whenever it requests.
                ast_prio_highest_exact: assert property (
                    grant[0] == req[0]
                );
            end 
            else begin
                // Elaborated for each lower-priority requester.
                // ast_prio_strict_adherence: Requires each lower-priority grant to yield to every active higher-priority request.
                ast_prio_strict_adherence: assert property (
                    grant[i] == (req[i] && !(|req[i-1:0]))
                );
            end
            
        end
    endgenerate


    generate
        for (genvar i = 0; i < NUM_REQS; i++) begin : gen_cov_basic
            // Formal Cover Property Catalog -- Fixed-Priority Arbiter Reachability
            // cov_grant_issued: Shows that each requester can receive a grant.
            cov_grant_issued: cover property (
                grant[i] == 1'b1
            );
        end
    endgenerate

    generate
        for (genvar i = 1; i < NUM_REQS; i++) begin : gen_cov_contention
            // One cover instance for each adjacent priority pair.
            // cov_adjacent_contention: Exercises simultaneous requests from each adjacent priority pair.
            cov_adjacent_contention: cover property (
                req[i] && req[i-1]
            );
        end
    endgenerate

    // Global extreme-contention cover.
    // cov_all_reqs_active: Exercises the extreme-contention case in which all requesters are active.
    cov_all_reqs_active: cover property (
        req == {NUM_REQS{1'b1}}
    );

    generate
        if (!SVA_INTEGRATION_MODE && (NUM_REQS >= 2)) begin : g_yield_cover
            // Standalone-only (excluded from the final integrated cover catalog).
            // Exercises the highest-priority requester yielding to the next
            // requester on the following cycle after its own request drops.
            cov_yield_to_lower: cover property (
                (req[0] && req[1] && grant[0])
                ##1 (!req[0] && req[1] && grant[1])
            );
        end
    endgenerate
endmodule

