// =============================================================================
// File        : arbiter_fp_rtl.sv
// Module      : arbiter_fp_rtl
// Purpose     : Parameterized combinational fixed-priority request arbitration
//               for the shared transaction path in the integrated AXI4
//               automotive security architecture.
//
// Priority and interface contract:
//   - req[i] indicates that requester (manager) i is asking for the shared path.
//   - Lower vector indices have higher priority: req[0] is highest.
//   - grant is one-hot (or all zero when no request is asserted).
//   - A grant is asserted for the lowest-index active request in that cycle;
//     this module does not itself store transaction ownership or queue work.
//   - The integrated top-level wrapper regulates when requests are eligible
//     and retains transaction ownership until the appropriate completion.
//
// Parameters:
//   NUM_REQS              : Width of req/grant (six in the evaluated wrapper).
//   SVA_INTEGRATION_MODE  : Passed unchanged to the bound formal checker to
//                           select integration-specific coverage behavior;
//                           it does not change the arbitration datapath.
//
// Verification integration:
//   The bind below attaches arbiter_fp_assertions to arbiter_fp_rtl instances.
//   Its assertions and cover properties are documented in the manuscript's
//   Formal Assertion Catalog and Formal Cover Property Catalog, respectively.
//   clk is consumed by the checker; arbitration equations are combinational.
//
// =============================================================================

module arbiter_fp_rtl #(
    parameter int NUM_REQS = 6,
    parameter bit SVA_INTEGRATION_MODE = 1'b0
)(
    input logic clk,
    input  logic [NUM_REQS-1:0] req,    // Vector of input requests
    output logic [NUM_REQS-1:0] grant   // One-hot encoded grant vector
);

    // Prefix-OR priority mask: bit i indicates whether any higher-priority
    // (lower-indexed) requester is currently active. Bit 0 has no predecessor.
    logic [NUM_REQS-1:0] higher_pri_reqs;

    // Combinational carry chain logic
    // higher_pri_reqs[i] will be '1' if any bit lower than 'i' is active
    assign higher_pri_reqs[0] = 1'b0;
    
    // Build the mask from lower to higher indices: bit i accumulates the
    // presence of all requests in the range [0, i-1].
    generate
        for (genvar i = 1; i < NUM_REQS; i++) begin : gen_pri_chain
            assign higher_pri_reqs[i] = higher_pri_reqs[i-1] | req[i-1];
        end
    endgenerate

    // A requester (manager) wins only if it requests AND no higher priority request exists
    // Mask every active requester that has a higher-priority competitor.
    // When req is zero, grant is zero; otherwise exactly one bit survives.
    assign grant = req & ~higher_pri_reqs;

endmodule

//==============================================================================
// Assertion Binding
//==============================================================================

// Bind the checker to each arbiter instance without adding arbitration logic.
// Pass both arbiter parameters through unchanged so the checker observes the
// same vector width and standalone/integrated verification configuration.
bind arbiter_fp_rtl arbiter_fp_assertions #(
    .NUM_REQS(NUM_REQS),
    .SVA_INTEGRATION_MODE(SVA_INTEGRATION_MODE)
)
u_arbiter_fp_assertions (
    .clk   (clk),
    .req   (req),
    .grant (grant)
);
