// =============================================================================
// File        : arbiter_firewall_top_sva.sv
// Module      : arbiter_firewall_top_sva
// Purpose     : Interface-based formal checker for the integrated fixed-priority
//               arbiter, centralized AXI4 firewall, and protected-side decoder.
//
// Verification boundary:
//   - Reference state is derived from accepted external and public component-
//     boundary AXI4/policy handshakes, not private DUT FSM or owner state.
//   - Checks arbitration, physical-port-based trusted identity, owner locking,
//     burst policy footprint, timeout/cancellation isolation, subordinate routing,
//     response ownership, framing, and end-to-end transaction conservation.
//   - External manager and protected-subordinate AXI4 behavior is constrained by
//     the stated interface assumptions. Policy interface assumptions belong to
//     the firewall's component checker and are not duplicated here.
//
// Property documentation:
//   - Individual active assertion, assumption, and cover comments reproduce
//     their descriptions in the finalized manuscript's corresponding catalogs.
//   - 105 source-level assertions, nine assumption templates, and 37 cover
//     templates appear in this integration checker. The nine assumptions
//     elaborate to 57 instances (6 x 6 managers + 3 x 7 subordinates); three
//     additional singleton policy-interface assumptions are in axi_firewall_sva.
//   - The 37 integration-level covers elaborate to 74 instances for the
//     evaluated six-manager/seven-subordinate configuration.
//   - The existing commented-out asm_subordinate_b_stable is NOT an active
//     assumption and is preserved exactly as in the formally proven source.
//
//
// =============================================================================

`timescale 1ns / 1ps

// Black-box composition contract for arbiter_firewall_top.
//
// All reference state is derived from accepted signals at the upstream-manager,
// arbiter, firewall-component, policy, and protected-subordinate interfaces. No RTL
// owner state, firewall FSM/timer state, or decoder state is used as a proof
// oracle. The standalone arbiter and firewall checkers remain bound to their
// component instances; this checker concentrates on cross-component identity,
// ownership, routing, quarantine, and end-to-end conservation.

module arbiter_firewall_top_sva #(
    parameter int NUM_MANAGERS   = 6,
    parameter int NUM_SUBORDINATES = 7,
    parameter int AXI_ID_W      = 4,
    parameter int AXI_ADDR_W    = 32,
    parameter int AXI_DATA_W    = 32,
    parameter int AXI_STRB_W    = AXI_DATA_W / 8,
    parameter int MANAGER_ID_W   = 4,
    parameter int SUBORDINATE_ID_W = 8,
    parameter int AXI_USER_W    = MANAGER_ID_W + SUBORDINATE_ID_W,
    parameter int MANAGER_IDX_W  = (NUM_MANAGERS <= 1) ? 1 : $clog2(NUM_MANAGERS),
    parameter int SUBORDINATE_IDX_W = (NUM_SUBORDINATES <= 1) ? 1 : $clog2(NUM_SUBORDINATES),
    parameter bit POLICY_TIMEOUT_ENABLE = 1'b1,
    parameter int unsigned POLICY_TIMEOUT_CYCLES = 32,
    parameter logic [NUM_MANAGERS*MANAGER_ID_W-1:0] MANAGER_ID_MAP =
        24'h65_43_21,
    parameter logic [NUM_SUBORDINATES*SUBORDINATE_ID_W-1:0] SUBORDINATE_ID_MAP =
        56'h60_51_50_40_30_20_10
) (
    input logic clk,
    input logic rst_n,

    input logic                     policy_req_valid,
    input logic                     policy_req_ready,
    input logic [MANAGER_ID_W-1:0]   policy_req_manager_id,
    input logic [SUBORDINATE_ID_W-1:0] policy_req_subordinate_id,
    input logic                     policy_req_is_write,
    input logic [AXI_ADDR_W-1:0]    policy_req_start_addr,
    input logic [AXI_ADDR_W-1:0]    policy_req_end_addr,
    input logic                     policy_rsp_valid,
    input logic                     policy_rsp_ready,
    input logic                     policy_rsp_allow,
    input logic                     policy_cancel_valid,
    input logic                     policy_cancel_ready,
    input logic                     policy_revoke_valid,

    input logic [NUM_MANAGERS-1:0][AXI_ID_W-1:0]     s_axi_awid,
    input logic [NUM_MANAGERS-1:0][AXI_ADDR_W-1:0]   s_axi_awaddr,
    input logic [NUM_MANAGERS-1:0][7:0]              s_axi_awlen,
    input logic [NUM_MANAGERS-1:0][2:0]              s_axi_awsize,
    input logic [NUM_MANAGERS-1:0][1:0]              s_axi_awburst,
    input logic [NUM_MANAGERS-1:0][AXI_USER_W-1:0]   s_axi_awuser,
    input logic [NUM_MANAGERS-1:0]                   s_axi_awvalid,
    input logic [NUM_MANAGERS-1:0]                   s_axi_awready,
    input logic [NUM_MANAGERS-1:0][AXI_DATA_W-1:0]   s_axi_wdata,
    input logic [NUM_MANAGERS-1:0][AXI_STRB_W-1:0]   s_axi_wstrb,
    input logic [NUM_MANAGERS-1:0]                   s_axi_wlast,
    input logic [NUM_MANAGERS-1:0]                   s_axi_wvalid,
    input logic [NUM_MANAGERS-1:0]                   s_axi_wready,
    input logic [NUM_MANAGERS-1:0][AXI_ID_W-1:0]     s_axi_bid,
    input logic [NUM_MANAGERS-1:0][1:0]              s_axi_bresp,
    input logic [NUM_MANAGERS-1:0]                   s_axi_bvalid,
    input logic [NUM_MANAGERS-1:0]                   s_axi_bready,
    input logic [NUM_MANAGERS-1:0][AXI_ID_W-1:0]     s_axi_arid,
    input logic [NUM_MANAGERS-1:0][AXI_ADDR_W-1:0]   s_axi_araddr,
    input logic [NUM_MANAGERS-1:0][7:0]              s_axi_arlen,
    input logic [NUM_MANAGERS-1:0][2:0]              s_axi_arsize,
    input logic [NUM_MANAGERS-1:0][1:0]              s_axi_arburst,
    input logic [NUM_MANAGERS-1:0][AXI_USER_W-1:0]   s_axi_aruser,
    input logic [NUM_MANAGERS-1:0]                   s_axi_arvalid,
    input logic [NUM_MANAGERS-1:0]                   s_axi_arready,
    input logic [NUM_MANAGERS-1:0][AXI_ID_W-1:0]     s_axi_rid,
    input logic [NUM_MANAGERS-1:0][AXI_DATA_W-1:0]   s_axi_rdata,
    input logic [NUM_MANAGERS-1:0][1:0]              s_axi_rresp,
    input logic [NUM_MANAGERS-1:0]                   s_axi_rlast,
    input logic [NUM_MANAGERS-1:0]                   s_axi_rvalid,
    input logic [NUM_MANAGERS-1:0]                   s_axi_rready,

    input logic [NUM_SUBORDINATES-1:0][AXI_ID_W-1:0]    m_axi_awid,
    input logic [NUM_SUBORDINATES-1:0][AXI_ADDR_W-1:0]  m_axi_awaddr,
    input logic [NUM_SUBORDINATES-1:0][7:0]             m_axi_awlen,
    input logic [NUM_SUBORDINATES-1:0][2:0]             m_axi_awsize,
    input logic [NUM_SUBORDINATES-1:0][1:0]             m_axi_awburst,
    input logic [NUM_SUBORDINATES-1:0][AXI_USER_W-1:0]  m_axi_awuser,
    input logic [NUM_SUBORDINATES-1:0]                  m_axi_awvalid,
    input logic [NUM_SUBORDINATES-1:0]                  m_axi_awready,
    input logic [NUM_SUBORDINATES-1:0][AXI_DATA_W-1:0]  m_axi_wdata,
    input logic [NUM_SUBORDINATES-1:0][AXI_STRB_W-1:0]  m_axi_wstrb,
    input logic [NUM_SUBORDINATES-1:0]                  m_axi_wlast,
    input logic [NUM_SUBORDINATES-1:0]                  m_axi_wvalid,
    input logic [NUM_SUBORDINATES-1:0]                  m_axi_wready,
    input logic [NUM_SUBORDINATES-1:0][AXI_ID_W-1:0]    m_axi_bid,
    input logic [NUM_SUBORDINATES-1:0][1:0]             m_axi_bresp,
    input logic [NUM_SUBORDINATES-1:0]                  m_axi_bvalid,
    input logic [NUM_SUBORDINATES-1:0]                  m_axi_bready,
    input logic [NUM_SUBORDINATES-1:0][AXI_ID_W-1:0]    m_axi_arid,
    input logic [NUM_SUBORDINATES-1:0][AXI_ADDR_W-1:0]  m_axi_araddr,
    input logic [NUM_SUBORDINATES-1:0][7:0]             m_axi_arlen,
    input logic [NUM_SUBORDINATES-1:0][2:0]             m_axi_arsize,
    input logic [NUM_SUBORDINATES-1:0][1:0]             m_axi_arburst,
    input logic [NUM_SUBORDINATES-1:0][AXI_USER_W-1:0]  m_axi_aruser,
    input logic [NUM_SUBORDINATES-1:0]                  m_axi_arvalid,
    input logic [NUM_SUBORDINATES-1:0]                  m_axi_arready,
    input logic [NUM_SUBORDINATES-1:0][AXI_ID_W-1:0]    m_axi_rid,
    input logic [NUM_SUBORDINATES-1:0][AXI_DATA_W-1:0]  m_axi_rdata,
    input logic [NUM_SUBORDINATES-1:0][1:0]             m_axi_rresp,
    input logic [NUM_SUBORDINATES-1:0]                  m_axi_rlast,
    input logic [NUM_SUBORDINATES-1:0]                  m_axi_rvalid,
    input logic [NUM_SUBORDINATES-1:0]                  m_axi_rready,

    // Public component-boundary interfaces inside the wrapper.
    input logic [NUM_MANAGERS-1:0] arb_req,
    input logic [NUM_MANAGERS-1:0] arb_grant,
    input logic [AXI_ID_W-1:0]    fw_awid,
    input logic [AXI_ADDR_W-1:0]  fw_awaddr,
    input logic [7:0]             fw_awlen,
    input logic [2:0]             fw_awsize,
    input logic [1:0]             fw_awburst,
    input logic [AXI_USER_W-1:0]  fw_awuser,
    input logic                   fw_awvalid,
    input logic                   fw_awready,
    input logic [AXI_DATA_W-1:0]  fw_wdata,
    input logic [AXI_STRB_W-1:0]  fw_wstrb,
    input logic                   fw_wlast,
    input logic                   fw_wvalid,
    input logic                   fw_wready,
    input logic [AXI_ID_W-1:0]    fw_bid,
    input logic [1:0]             fw_bresp,
    input logic                   fw_bvalid,
    input logic                   fw_bready,
    input logic [AXI_ID_W-1:0]    fw_arid,
    input logic [AXI_ADDR_W-1:0]  fw_araddr,
    input logic [7:0]             fw_arlen,
    input logic [2:0]             fw_arsize,
    input logic [1:0]             fw_arburst,
    input logic [AXI_USER_W-1:0]  fw_aruser,
    input logic                   fw_arvalid,
    input logic                   fw_arready,
    input logic [AXI_ID_W-1:0]    fw_rid,
    input logic [AXI_DATA_W-1:0]  fw_rdata,
    input logic [1:0]             fw_rresp,
    input logic                   fw_rlast,
    input logic                   fw_rvalid,
    input logic                   fw_rready,

    input logic [AXI_ID_W-1:0]    fw_m_awid,
    input logic [AXI_ADDR_W-1:0]  fw_m_awaddr,
    input logic [7:0]             fw_m_awlen,
    input logic [2:0]             fw_m_awsize,
    input logic [1:0]             fw_m_awburst,
    input logic [AXI_USER_W-1:0]  fw_m_awuser,
    input logic                   fw_m_awvalid,
    input logic                   fw_m_awready,
    input logic [AXI_DATA_W-1:0]  fw_m_wdata,
    input logic [AXI_STRB_W-1:0]  fw_m_wstrb,
    input logic                   fw_m_wlast,
    input logic                   fw_m_wvalid,
    input logic                   fw_m_wready,
    input logic [AXI_ID_W-1:0]    fw_m_bid,
    input logic [1:0]             fw_m_bresp,
    input logic                   fw_m_bvalid,
    input logic                   fw_m_bready,
    input logic [AXI_ID_W-1:0]    fw_m_arid,
    input logic [AXI_ADDR_W-1:0]  fw_m_araddr,
    input logic [7:0]             fw_m_arlen,
    input logic [2:0]             fw_m_arsize,
    input logic [1:0]             fw_m_arburst,
    input logic [AXI_USER_W-1:0]  fw_m_aruser,
    input logic                   fw_m_arvalid,
    input logic                   fw_m_arready,
    input logic [AXI_ID_W-1:0]    fw_m_rid,
    input logic [AXI_DATA_W-1:0]  fw_m_rdata,
    input logic [1:0]             fw_m_rresp,
    input logic                   fw_m_rlast,
    input logic                   fw_m_rvalid,
    input logic                   fw_m_rready
);

    localparam logic [1:0] AXI_RESP_DECERR = 2'b11;
    localparam int RANGE_W = AXI_ADDR_W + 16;
    localparam int POLICY_TIMEOUT_CNT_W =
        (POLICY_TIMEOUT_CYCLES <= 1) ? 1 : $clog2(POLICY_TIMEOUT_CYCLES);
    localparam logic [POLICY_TIMEOUT_CNT_W-1:0]
        POLICY_TIMEOUT_COUNT_ONE = 1;
    localparam logic [POLICY_TIMEOUT_CNT_W-1:0]
        POLICY_TIMEOUT_LAST_COUNT = (POLICY_TIMEOUT_CYCLES > 0) ?
                                    (POLICY_TIMEOUT_CYCLES - 1) : '0;

    default clocking cb @(posedge clk); endclocking
    default disable iff (!rst_n);

    // Small independent helpers reconstruct the selected physical manager,
    //     // priority grant, and trusted identity mapping from observable interfaces.
    function automatic logic [MANAGER_IDX_W-1:0] manager_onehot_index(
        input logic [NUM_MANAGERS-1:0] onehot
    );
        logic [MANAGER_IDX_W-1:0] result;
        begin
            result = '0;
            for (int k = 0; k < NUM_MANAGERS; k++)
                if (onehot[k]) result = k[MANAGER_IDX_W-1:0];
            return result;
        end
    endfunction

    function automatic logic [NUM_MANAGERS-1:0] ref_manager_onehot(
        input logic [MANAGER_IDX_W-1:0] index
    );
        logic [NUM_MANAGERS-1:0] result;
        begin
            result = '0;
            for (int k = 0; k < NUM_MANAGERS; k++)
                if (index == k[MANAGER_IDX_W-1:0]) result[k] = 1'b1;
            return result;
        end
    endfunction

    function automatic logic [MANAGER_ID_W-1:0] ref_manager_id(
        input logic [MANAGER_IDX_W-1:0] index
    );
        logic [MANAGER_ID_W-1:0] result;
        begin
            result = '0;
            for (int k = 0; k < NUM_MANAGERS; k++)
                if (index == k[MANAGER_IDX_W-1:0])
                    result = MANAGER_ID_MAP[k*MANAGER_ID_W +: MANAGER_ID_W];
            return result;
        end
    endfunction

    function automatic logic [NUM_MANAGERS-1:0] ref_priority_grant(
        input logic [NUM_MANAGERS-1:0] requests
    );
        logic found;
        logic [NUM_MANAGERS-1:0] result;
        begin
            found  = 1'b0;
            result = '0;
            for (int k = 0; k < NUM_MANAGERS; k++) begin
                if (requests[k] && !found) begin
                    result[k] = 1'b1;
                    found = 1'b1;
                end
            end
            return result;
        end
    endfunction

    function automatic logic [NUM_SUBORDINATES-1:0] ref_subordinate_decode(
        input logic [SUBORDINATE_ID_W-1:0] subordinate_id
    );
        logic [NUM_SUBORDINATES-1:0] result;
        begin
            result = '0;
            for (int k = 0; k < NUM_SUBORDINATES; k++)
                if (subordinate_id ==
                    SUBORDINATE_ID_MAP[k*SUBORDINATE_ID_W +: SUBORDINATE_ID_W])
                    result[k] = 1'b1;
            return result;
        end
    endfunction

    function automatic logic ref_subordinate_implemented(
        input logic [SUBORDINATE_ID_W-1:0] subordinate_id
    );
        begin
            ref_subordinate_implemented = |ref_subordinate_decode(subordinate_id);
        end
    endfunction

    // Independent burst-footprint helpers model FIXED, INCR, and WRAP address
    //     // ranges and encode illegal bursts as the deny/invalid policy range.
    function automatic logic [AXI_ADDR_W-1:0] ref_burst_start(
        input logic [AXI_ADDR_W-1:0] addr,
        input logic [7:0] len,
        input logic [2:0] size,
        input logic [1:0] burst
    );
        logic [RANGE_W-1:0] addr_x;
        logic [RANGE_W-1:0] span;
        logic [RANGE_W-1:0] wrap_base;
        begin
            addr_x    = {{(RANGE_W-AXI_ADDR_W){1'b0}}, addr};
            span      = ({{(RANGE_W-8){1'b0}}, len} + 1'b1) << size;
            wrap_base = addr_x & ~(span - 1'b1);
            case (burst)
                2'b00, 2'b01: ref_burst_start = addr;
                2'b10:        ref_burst_start = wrap_base[AXI_ADDR_W-1:0];
                default:      ref_burst_start = '0;
            endcase
        end
    endfunction

    function automatic logic [AXI_ADDR_W-1:0] ref_burst_end(
        input logic [AXI_ADDR_W-1:0] addr,
        input logic [7:0] len,
        input logic [2:0] size,
        input logic [1:0] burst
    );
        logic [RANGE_W-1:0] addr_x;
        logic [RANGE_W-1:0] beat;
        logic [RANGE_W-1:0] span;
        logic [RANGE_W-1:0] aligned_addr;
        logic [RANGE_W-1:0] wrap_base;
        logic [RANGE_W-1:0] end_x;
        begin
            addr_x       = {{(RANGE_W-AXI_ADDR_W){1'b0}}, addr};
            beat         = {{(RANGE_W-1){1'b0}}, 1'b1} << size;
            span         = ({{(RANGE_W-8){1'b0}}, len} + 1'b1) << size;
            aligned_addr = addr_x & ~(beat - 1'b1);
            wrap_base    = addr_x & ~(span - 1'b1);
            case (burst)
                2'b00:   end_x = aligned_addr + beat - 1'b1;
                2'b01:   end_x = aligned_addr + span - 1'b1;
                2'b10:   end_x = wrap_base + span - 1'b1;
                default: end_x = {RANGE_W{1'b1}};
            endcase
            ref_burst_end = |end_x[RANGE_W-1:AXI_ADDR_W] ?
                            {AXI_ADDR_W{1'b1}} :
                            end_x[AXI_ADDR_W-1:0];
        end
    endfunction

    function automatic logic ref_burst_legal(
        input logic [AXI_ADDR_W-1:0] addr,
        input logic [7:0] len,
        input logic [2:0] size,
        input logic [1:0] burst
    );
        logic [RANGE_W-1:0] addr_x;
        logic [RANGE_W-1:0] beat;
        logic [RANGE_W-1:0] span;
        logic [RANGE_W-1:0] aligned_addr;
        logic [RANGE_W-1:0] wrap_base;
        logic [RANGE_W-1:0] first_x;
        logic [RANGE_W-1:0] last_x;
        begin
            addr_x       = {{(RANGE_W-AXI_ADDR_W){1'b0}}, addr};
            beat         = {{(RANGE_W-1){1'b0}}, 1'b1} << size;
            span         = ({{(RANGE_W-8){1'b0}}, len} + 1'b1) << size;
            aligned_addr = addr_x & ~(beat - 1'b1);
            wrap_base    = addr_x & ~(span - 1'b1);
            first_x      = addr_x;
            last_x       = addr_x;
            ref_burst_legal = 1'b1;
            if (beat > AXI_STRB_W) ref_burst_legal = 1'b0;
            case (burst)
                2'b00: begin
                    last_x = aligned_addr + beat - 1'b1;
                    if (len > 8'd15) ref_burst_legal = 1'b0;
                end
                2'b01: last_x = aligned_addr + span - 1'b1;
                2'b10: begin
                    first_x = wrap_base;
                    last_x  = wrap_base + span - 1'b1;
                    if (!((len == 8'd1) || (len == 8'd3) ||
                          (len == 8'd7) || (len == 8'd15)))
                        ref_burst_legal = 1'b0;
                    if ((addr_x & (beat - 1'b1)) != '0)
                        ref_burst_legal = 1'b0;
                end
                default: ref_burst_legal = 1'b0;
            endcase
            if (|last_x[RANGE_W-1:AXI_ADDR_W])
                ref_burst_legal = 1'b0;
            if ((first_x >> 12) != (last_x >> 12))
                ref_burst_legal = 1'b0;
        end
    endfunction

    function automatic logic [AXI_ADDR_W-1:0] ref_policy_start(
        input logic [AXI_ADDR_W-1:0] addr,
        input logic [7:0] len,
        input logic [2:0] size,
        input logic [1:0] burst
    );
        begin
            ref_policy_start = ref_burst_legal(addr, len, size, burst) ?
                               ref_burst_start(addr, len, size, burst) : '0;
        end
    endfunction

    function automatic logic [AXI_ADDR_W-1:0] ref_policy_end(
        input logic [AXI_ADDR_W-1:0] addr,
        input logic [7:0] len,
        input logic [2:0] size,
        input logic [1:0] burst
    );
        begin
            ref_policy_end = ref_burst_legal(addr, len, size, burst) ?
                             ref_burst_end(addr, len, size, burst) :
                             {AXI_ADDR_W{1'b1}};
        end
    endfunction

    // Handshake aliases separate accepted transfers from VALID-only activity.
    //     // They drive the reference ledgers, assumptions, and property antecedents.
    wire [NUM_MANAGERS-1:0] s_aw_hs = s_axi_awvalid & s_axi_awready;
    wire [NUM_MANAGERS-1:0] s_w_hs  = s_axi_wvalid  & s_axi_wready;
    wire [NUM_MANAGERS-1:0] s_b_hs  = s_axi_bvalid  & s_axi_bready;
    wire [NUM_MANAGERS-1:0] s_ar_hs = s_axi_arvalid & s_axi_arready;
    wire [NUM_MANAGERS-1:0] s_r_hs  = s_axi_rvalid  & s_axi_rready;
    wire [NUM_SUBORDINATES-1:0] m_aw_hs = m_axi_awvalid & m_axi_awready;
    wire [NUM_SUBORDINATES-1:0] m_w_hs  = m_axi_wvalid  & m_axi_wready;
    wire [NUM_SUBORDINATES-1:0] m_b_hs  = m_axi_bvalid  & m_axi_bready;
    wire [NUM_SUBORDINATES-1:0] m_ar_hs = m_axi_arvalid & m_axi_arready;
    wire [NUM_SUBORDINATES-1:0] m_r_hs  = m_axi_rvalid  & m_axi_rready;
    wire fw_s_aw_hs = fw_awvalid && fw_awready;
    wire fw_s_w_hs  = fw_wvalid && fw_wready;
    wire fw_s_b_hs  = fw_bvalid && fw_bready;
    wire fw_s_ar_hs = fw_arvalid && fw_arready;
    wire fw_s_r_hs  = fw_rvalid && fw_rready;
    wire fw_m_aw_hs = fw_m_awvalid && fw_m_awready;
    wire fw_m_w_hs  = fw_m_wvalid && fw_m_wready;
    wire fw_m_b_hs  = fw_m_bvalid && fw_m_bready;
    wire fw_m_ar_hs = fw_m_arvalid && fw_m_arready;
    wire fw_m_r_hs  = fw_m_rvalid && fw_m_rready;
    wire policy_req_hs = policy_req_valid && policy_req_ready;
    wire policy_rsp_hs = policy_rsp_valid && policy_rsp_ready;
    wire policy_cancel_hs = policy_cancel_valid && policy_cancel_ready;
    wire policy_addr_hs = fw_s_aw_hs || fw_s_ar_hs;
    wire policy_axi_complete_hs = fw_s_b_hs ||
                                  (fw_s_r_hs && fw_rlast);

    // Interface-derived manager owner and AXI ledgers.
    logic f_owner_valid;
    logic f_owner_write;
    logic [MANAGER_IDX_W-1:0] f_owner_index;
    logic f_aw_seen;
    logic f_ar_seen;
    logic [AXI_ID_W-1:0] f_awid;
    logic [AXI_ADDR_W-1:0] f_awaddr;
    logic [7:0] f_awlen;
    logic [2:0] f_awsize;
    logic [1:0] f_awburst;
    logic [SUBORDINATE_ID_W-1:0] f_subordinate_id;
    logic [AXI_ID_W-1:0] f_arid;
    logic [AXI_ADDR_W-1:0] f_araddr;
    logic [7:0] f_arlen;
    logic [2:0] f_arsize;
    logic [1:0] f_arburst;
    logic [8:0] f_w_expected;
    logic [8:0] f_s_w_count;
    logic f_s_wlast_seen;
    logic [8:0] f_r_expected;
    logic [8:0] f_s_r_count;

    // Independent upstream-manager write ledgers.  These exist solely to state
    // each external manager's WLAST contract from that manager's own accepted
    // AW/W/B events; they deliberately do not depend on the wrapper owner
    // scoreboard, so an ownership or cross-routing defect cannot make an
    // environment assumption self-fulfilling.
    logic [NUM_MANAGERS-1:0] f_manager_aw_active;
    logic [NUM_MANAGERS-1:0][8:0] f_manager_w_expected;
    logic [NUM_MANAGERS-1:0][8:0] f_manager_w_count;
    logic [NUM_MANAGERS-1:0] f_manager_wlast_seen;

    // Policy-generation ledger and independent whole-operation timer.
    logic f_policy_active;
    logic f_policy_is_write;
    logic f_policy_legal;
    logic [MANAGER_ID_W-1:0] f_policy_manager_id;
    logic [SUBORDINATE_ID_W-1:0] f_policy_subordinate_id;
    logic [AXI_ADDR_W-1:0] f_policy_start_addr;
    logic [AXI_ADDR_W-1:0] f_policy_end_addr;
    logic f_policy_req_seen;
    logic f_policy_rsp_seen;
    logic f_policy_effective_allow;
    logic f_policy_timed_out;
    logic f_policy_timeout_after_req;
    logic f_policy_cancel_seen;
    logic f_policy_axi_complete_seen;
    logic f_policy_timer_active;
    logic [POLICY_TIMEOUT_CNT_W-1:0] f_policy_timeout_count;

    // Firewall-to-subordinate route scoreboards.
    logic f_wr_route_valid;
    logic f_wr_route_implemented;
    logic [NUM_SUBORDINATES-1:0] f_wr_route_onehot;
    logic [SUBORDINATE_ID_W-1:0] f_wr_route_subordinate_id;
    logic [AXI_ID_W-1:0] f_wr_route_id;
    logic [8:0] f_fw_w_expected;
    logic [8:0] f_fw_w_count;
    logic f_rd_route_valid;
    logic f_rd_route_implemented;
    logic [NUM_SUBORDINATES-1:0] f_rd_route_onehot;
    logic [SUBORDINATE_ID_W-1:0] f_rd_route_subordinate_id;
    logic [AXI_ID_W-1:0] f_rd_route_id;
    logic [8:0] f_fw_r_expected;
    logic [8:0] f_fw_r_count;

    // Independent physical-subordinate ledgers used only to constrain legal peer
    // responses. They do not depend on the decoder or firewall-side ledgers.
    logic [NUM_SUBORDINATES-1:0] f_res_write_active;
    logic [NUM_SUBORDINATES-1:0][AXI_ID_W-1:0] f_res_awid;
    logic [NUM_SUBORDINATES-1:0][8:0] f_res_w_expected;
    logic [NUM_SUBORDINATES-1:0][8:0] f_res_w_count;
    logic [NUM_SUBORDINATES-1:0] f_res_read_active;
    logic [NUM_SUBORDINATES-1:0][AXI_ID_W-1:0] f_res_arid;
    logic [NUM_SUBORDINATES-1:0][8:0] f_res_r_expected;
    logic [NUM_SUBORDINATES-1:0][8:0] f_res_r_count;

    logic f_history_valid;
    logic [MANAGER_IDX_W-1:0] f_history_manager;
    logic [SUBORDINATE_ID_W-1:0] f_history_subordinate;

    wire [MANAGER_IDX_W-1:0] f_selected_manager = f_owner_valid ?
        f_owner_index : manager_onehot_index(arb_grant);

    // An ALLOW only becomes effective with local burst legality and no
    //     // coincident revocation; the timeout model tracks the whole operation.
    wire policy_rsp_effective_allow = policy_rsp_allow &&
                                      f_policy_legal &&
                                      !policy_revoke_valid;
    wire policy_timeout_final_cycle = POLICY_TIMEOUT_ENABLE &&
        ((policy_addr_hs && (POLICY_TIMEOUT_CYCLES == 1)) ||
         (f_policy_timer_active &&
          (f_policy_timeout_count == POLICY_TIMEOUT_LAST_COUNT)));
    wire policy_timeout_fire = policy_timeout_final_cycle && !policy_rsp_hs;

    // Owner/reference accounting follows observed manager-side admissions and
    //     // retires on the upstream B or final read-beat handshake.
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            f_owner_valid    <= 1'b0;
            f_owner_write    <= 1'b0;
            f_owner_index    <= '0;
            f_aw_seen        <= 1'b0;
            f_ar_seen        <= 1'b0;
            f_awid           <= '0;
            f_awaddr         <= '0;
            f_awlen          <= '0;
            f_awsize         <= '0;
            f_awburst        <= '0;
            f_subordinate_id    <= '0;
            f_arid           <= '0;
            f_araddr         <= '0;
            f_arlen          <= '0;
            f_arsize         <= '0;
            f_arburst        <= '0;
            f_w_expected     <= '0;
            f_s_w_count      <= '0;
            f_s_wlast_seen   <= 1'b0;
            f_r_expected     <= '0;
            f_s_r_count      <= '0;
            f_history_valid  <= 1'b0;
            f_history_manager <= '0;
            f_history_subordinate <= '0;
        end
        else begin
            if (!f_owner_valid && ((|s_aw_hs) || (|s_w_hs))) begin
                f_owner_valid <= 1'b1;
                f_owner_write <= 1'b1;
                f_owner_index <= manager_onehot_index(s_aw_hs | s_w_hs);
            end
            else if (!f_owner_valid && (|s_ar_hs)) begin
                f_owner_valid <= 1'b1;
                f_owner_write <= 1'b0;
                f_owner_index <= manager_onehot_index(s_ar_hs);
            end

            if (|s_aw_hs) begin
                f_aw_seen     <= 1'b1;
                f_awid        <= fw_awid;
                f_awaddr      <= fw_awaddr;
                f_awlen       <= fw_awlen;
                f_awsize      <= fw_awsize;
                f_awburst     <= fw_awburst;
                f_subordinate_id <= fw_awuser[SUBORDINATE_ID_W-1:0];
                f_w_expected  <= {1'b0, fw_awlen} + 9'd1;
            end
            if (|s_w_hs) begin
                f_s_w_count <= f_s_w_count + 9'd1;
                if (|(s_w_hs & s_axi_wlast))
                    f_s_wlast_seen <= 1'b1;
            end

            if (|s_ar_hs) begin
                f_ar_seen     <= 1'b1;
                f_arid        <= fw_arid;
                f_araddr      <= fw_araddr;
                f_arlen       <= fw_arlen;
                f_arsize      <= fw_arsize;
                f_arburst     <= fw_arburst;
                f_subordinate_id <= fw_aruser[SUBORDINATE_ID_W-1:0];
                f_r_expected  <= {1'b0, fw_arlen} + 9'd1;
            end
            if (|s_r_hs)
                f_s_r_count <= f_s_r_count + 9'd1;

            if (|s_b_hs) begin
                f_history_valid    <= f_owner_valid;
                f_history_manager   <= f_owner_index;
                f_history_subordinate <= f_subordinate_id;
                f_owner_valid    <= 1'b0;
                f_owner_write    <= 1'b0;
                f_owner_index    <= '0;
                f_aw_seen        <= 1'b0;
                f_awid           <= '0;
                f_awaddr         <= '0;
                f_awlen          <= '0;
                f_awsize         <= '0;
                f_awburst        <= '0;
                f_subordinate_id    <= '0;
                f_w_expected     <= '0;
                f_s_w_count      <= '0;
                f_s_wlast_seen   <= 1'b0;
            end
            else if (|(s_r_hs & s_axi_rlast)) begin
                f_history_valid    <= f_owner_valid;
                f_history_manager   <= f_owner_index;
                f_history_subordinate <= f_subordinate_id;
                f_owner_valid    <= 1'b0;
                f_owner_write    <= 1'b0;
                f_owner_index    <= '0;
                f_ar_seen        <= 1'b0;
                f_arid           <= '0;
                f_araddr         <= '0;
                f_arlen          <= '0;
                f_arsize         <= '0;
                f_arburst        <= '0;
                f_subordinate_id    <= '0;
                f_r_expected     <= '0;
                f_s_r_count      <= '0;
            end
        end
    end

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            f_manager_aw_active  <= '0;
            f_manager_w_expected <= '0;
            f_manager_w_count    <= '0;
            f_manager_wlast_seen <= '0;
        end
        else begin
            for (int i = 0; i < NUM_MANAGERS; i++) begin
                if (s_aw_hs[i]) begin
                    f_manager_aw_active[i]  <= 1'b1;
                    f_manager_w_expected[i] <=
                        {1'b0, s_axi_awlen[i]} + 9'd1;
                end
                if (s_w_hs[i]) begin
                    f_manager_w_count[i] <= f_manager_w_count[i] + 9'd1;
                    if (s_axi_wlast[i])
                        f_manager_wlast_seen[i] <= 1'b1;
                end
                if (s_b_hs[i]) begin
                    f_manager_aw_active[i]  <= 1'b0;
                    f_manager_w_expected[i] <= '0;
                    f_manager_w_count[i]    <= '0;
                    f_manager_wlast_seen[i] <= 1'b0;
                end
            end
        end
    end

    // ------------------------------------------------------------------
    // External peer assumptions only
    // ------------------------------------------------------------------
    // Policy responder causality/stability/retirement assumptions are supplied
    // by the bound firewall checker. They are intentionally not duplicated.
    generate
        for (genvar i = 0; i < NUM_MANAGERS; i++) begin : g_manager_contracts
            // Holds AWVALID and the write-address payload stable while the manager is
            // stalled by backpressure.
            asm_manager_aw_stable: assume property (
                s_axi_awvalid[i] && !s_axi_awready[i]
                |=> s_axi_awvalid[i] &&
                    $stable({s_axi_awid[i], s_axi_awaddr[i],
                             s_axi_awlen[i], s_axi_awsize[i],
                             s_axi_awburst[i], s_axi_awuser[i]})
            );

            // Holds WVALID, WDATA, WSTRB, and WLAST stable while the write-data channel is
            // stalled.
            asm_manager_w_stable: assume property (
                s_axi_wvalid[i] && !s_axi_wready[i]
                |=> s_axi_wvalid[i] &&
                    $stable({s_axi_wdata[i], s_axi_wstrb[i],
                             s_axi_wlast[i]})
            );

            // Holds ARVALID and the read-address payload stable while the manager is
            // stalled by backpressure.
            asm_manager_ar_stable: assume property (
                s_axi_arvalid[i] && !s_axi_arready[i]
                |=> s_axi_arvalid[i] &&
                    $stable({s_axi_arid[i], s_axi_araddr[i],
                             s_axi_arlen[i], s_axi_arsize[i],
                             s_axi_arburst[i], s_axi_aruser[i]})
            );

            // Requires WLAST to identify exactly the expected final write-data beat after
            // the corresponding write address has been accepted.
            asm_manager_wlast_after_aw: assume property (
                f_manager_aw_active[i] && s_w_hs[i]
                |-> (s_axi_wlast[i] ==
                     ((f_manager_w_count[i] + 9'd1) ==
                      f_manager_w_expected[i]))
            );

            // Requires correct WLAST framing when the write address and a write-data beat
            // are accepted in the same cycle.
            asm_manager_wlast_with_aw: assume property (
                s_aw_hs[i] && s_w_hs[i]
                |-> (s_axi_wlast[i] ==
                     ((f_manager_w_count[i] + 9'd1) ==
                      ({1'b0, s_axi_awlen[i]} + 9'd1)))
            );

            // Constrains write-data accepted before the write address so that the buffered
            // beat count and observed WLAST remain consistent with the subsequently
            // accepted AWLEN.
            asm_manager_w_before_aw_framing: assume property (
                s_aw_hs[i] && (f_manager_w_count[i] != 0)
                |-> (f_manager_w_count[i] <=
                     ({1'b0, s_axi_awlen[i]} + 9'd1)) &&
                    (f_manager_wlast_seen[i] ==
                     (f_manager_w_count[i] ==
                      ({1'b0, s_axi_awlen[i]} + 9'd1)))
            );

            // Wrapper-generated response channels must be stable under each
            // independent manager's backpressure.
            // Keeps each manager-facing B response stable while that manager stalls.
            ast_manager_b_stable: assert property (
                s_axi_bvalid[i] && !s_axi_bready[i]
                |=> s_axi_bvalid[i] &&
                    $stable({s_axi_bid[i], s_axi_bresp[i]})
            );

            // Keeps each manager-facing R response stable while that manager stalls.
            ast_manager_r_stable: assert property (
                s_axi_rvalid[i] && !s_axi_rready[i]
                |=> s_axi_rvalid[i] &&
                    $stable({s_axi_rid[i], s_axi_rdata[i],
                             s_axi_rresp[i], s_axi_rlast[i]})
            );
        end

        for (genvar r = 0; r < NUM_SUBORDINATES; r++) begin : g_subordinate_contracts

            // Allows a write response only for an active write after the expected number
            // of write-data beats has been accepted, with BID matching the accepted AWID.
            asm_subordinate_b_causal: assume property (
                m_axi_bvalid[r]
                |-> f_res_write_active[r] &&
                    (f_res_w_count[r] == f_res_w_expected[r]) &&
                    (m_axi_bid[r] == f_res_awid[r])
            );

            // Holds RVALID and the read-response payload stable while the read response is
            // stalled by backpressure.
            asm_subordinate_r_stable: assume property (
                m_axi_rvalid[r] && !m_axi_rready[r]
                |=> m_axi_rvalid[r] &&
                    $stable({m_axi_rid[r], m_axi_rdata[r],
                             m_axi_rresp[r], m_axi_rlast[r]})
            );

            // Allows read data only for an active read, requires RID to match the accepted
            // ARID, and requires RLAST only on the expected final beat.
            asm_subordinate_r_causal: assume property (
                m_axi_rvalid[r]
                |-> f_res_read_active[r] &&
                    (f_res_r_count[r] < f_res_r_expected[r]) &&
                    (m_axi_rid[r] == f_res_arid[r]) &&
                    (m_axi_rlast[r] ==
                     ((f_res_r_count[r] + 9'd1) ==
                      f_res_r_expected[r]))
            );

            // The DUT, not the environment, owns subordinate request stability.
            // Keeps each protected-subordinate AW request stable under backpressure.
            ast_subordinate_aw_stable: assert property (
                m_axi_awvalid[r] && !m_axi_awready[r]
                |=> m_axi_awvalid[r] &&
                    $stable({m_axi_awid[r], m_axi_awaddr[r],
                             m_axi_awlen[r], m_axi_awsize[r],
                             m_axi_awburst[r], m_axi_awuser[r]})
            );

            // Keeps each protected-subordinate W transfer stable under backpressure.
            ast_subordinate_w_stable: assert property (
                m_axi_wvalid[r] && !m_axi_wready[r]
                |=> m_axi_wvalid[r] &&
                    $stable({m_axi_wdata[r], m_axi_wstrb[r],
                             m_axi_wlast[r]})
            );

            // Keeps each protected-subordinate AR request stable under backpressure.
            ast_subordinate_ar_stable: assert property (
                m_axi_arvalid[r] && !m_axi_arready[r]
                |=> m_axi_arvalid[r] &&
                    $stable({m_axi_arid[r], m_axi_araddr[r],
                             m_axi_arlen[r], m_axi_arsize[r],
                             m_axi_arburst[r], m_axi_aruser[r]})
            );
        end
    endgenerate

    // ------------------------------------------------------------------
    // Configuration, arbitration, and owner routing
    // ------------------------------------------------------------------
    // Checks valid system dimensions and identifier, index, USER-field, and timeout
    // parameter widths.
    ast_configuration_widths: assert property (
        (NUM_MANAGERS > 0) && (NUM_SUBORDINATES > 0) &&
        (MANAGER_IDX_W >=
         ((NUM_MANAGERS <= 1) ? 1 : $clog2(NUM_MANAGERS))) &&
        (SUBORDINATE_IDX_W >=
         ((NUM_SUBORDINATES <= 1) ? 1 : $clog2(NUM_SUBORDINATES))) &&
        (AXI_USER_W == (MANAGER_ID_W + SUBORDINATE_ID_W)) &&
        (!POLICY_TIMEOUT_ENABLE || (POLICY_TIMEOUT_CYCLES > 0))
    );

    // Forms arbitration requests only when no owner or cancellation fence is active.
    ast_arbiter_request_boundary: assert property (
        arb_req == ((!f_owner_valid && !policy_cancel_valid) ?
                   (s_axi_awvalid | s_axi_wvalid | s_axi_arvalid) : '0)
    );

    // Requires the integrated arbiter grant to match the fixed-priority reference model.
    ast_fixed_priority_exact: assert property (
        arb_grant == ref_priority_grant(arb_req)
    );

    // Allows at most one manager to receive transaction acceptance in a cycle.
    ast_onehot_manager_admission: assert property (
        $onehot0(s_axi_awready | s_axi_wready | s_axi_arready)
    );

    // Allows at most one manager to receive a B response and at most one to receive an R
    // response.
    ast_onehot_manager_response: assert property (
        $onehot0(s_axi_bvalid) && $onehot0(s_axi_rvalid)
    );

    // Prevents simultaneous read and write admission across all managers.
    ast_no_read_write_accept_same_cycle: assert property (
        !(((|s_aw_hs) || (|s_w_hs)) && (|s_ar_hs))
    );

    // Requires simultaneous AW and W handshakes to come from the same manager.
    ast_aw_w_same_source: assert property (
        (|s_aw_hs) && (|s_w_hs)
        |-> s_aw_hs == s_w_hs
    );

    // Requires every issued grant to produce an accepted firewall-side transaction
    // transfer.
    ast_new_grant_is_accepted: assert property (
        (|arb_grant)
        |-> fw_s_aw_hs || fw_s_w_hs || fw_s_ar_hs
    );

    // Gives the selected manager's pending write precedence over its simultaneous read.
    ast_selected_manager_write_priority: assert property (
        !f_owner_valid && (|arb_grant) &&
        ((s_axi_awvalid | s_axi_wvalid) & arb_grant) != '0
        |-> !(|s_ar_hs)
    );

    // Forwards AW from the selected manager while replacing its identity with the trusted
    // physical-port MANAGER_ID.
    ast_fw_aw_source_and_trusted_user: assert property (
        fw_awvalid
        |-> s_axi_awvalid[f_selected_manager] &&
            (fw_awid == s_axi_awid[f_selected_manager]) &&
            (fw_awaddr == s_axi_awaddr[f_selected_manager]) &&
            (fw_awlen == s_axi_awlen[f_selected_manager]) &&
            (fw_awsize == s_axi_awsize[f_selected_manager]) &&
            (fw_awburst == s_axi_awburst[f_selected_manager]) &&
            (fw_awuser[AXI_USER_W-1 -: MANAGER_ID_W] ==
             ref_manager_id(f_selected_manager)) &&
            (fw_awuser[SUBORDINATE_ID_W-1:0] ==
             s_axi_awuser[f_selected_manager][SUBORDINATE_ID_W-1:0])
    );

    // Requires forwarded write data to come from the selected manager without payload
    // alteration.
    ast_fw_w_source: assert property (
        fw_wvalid
        |-> s_axi_wvalid[f_selected_manager] &&
            (fw_wdata == s_axi_wdata[f_selected_manager]) &&
            (fw_wstrb == s_axi_wstrb[f_selected_manager]) &&
            (fw_wlast == s_axi_wlast[f_selected_manager])
    );

    // Forwards AR from the selected manager while replacing its identity with the trusted
    // physical-port MANAGER_ID.
    ast_fw_ar_source_and_trusted_user: assert property (
        fw_arvalid
        |-> s_axi_arvalid[f_selected_manager] &&
            (fw_arid == s_axi_arid[f_selected_manager]) &&
            (fw_araddr == s_axi_araddr[f_selected_manager]) &&
            (fw_arlen == s_axi_arlen[f_selected_manager]) &&
            (fw_arsize == s_axi_arsize[f_selected_manager]) &&
            (fw_arburst == s_axi_arburst[f_selected_manager]) &&
            (fw_aruser[AXI_USER_W-1 -: MANAGER_ID_W] ==
             ref_manager_id(f_selected_manager)) &&
            (fw_aruser[SUBORDINATE_ID_W-1:0] ==
             s_axi_aruser[f_selected_manager][SUBORDINATE_ID_W-1:0])
    );

    // Requires firewall-side handshakes to match the aggregate handshakes at the manager
    // ports.
    ast_fw_handshakes_match_manager_ports: assert property (
        fw_s_aw_hs == (|s_aw_hs) &&
        fw_s_w_hs  == (|s_w_hs) &&
        fw_s_ar_hs == (|s_ar_hs) &&
        fw_s_b_hs  == (|s_b_hs) &&
        fw_s_r_hs  == (|s_r_hs)
    );

    // Prevents a captured write address from being presented to the firewall again.
    ast_captured_aw_not_represented: assert property (
        f_aw_seen |-> !fw_awvalid
    );

    // Prevents a captured read address from being presented to the firewall again.
    ast_captured_ar_not_represented: assert property (
        f_ar_seen |-> !fw_arvalid
    );

    // Stops presenting write data after the accepted WLAST beat.
    ast_wlast_closes_manager_w_channel: assert property (
        f_s_wlast_seen |-> !fw_wvalid
    );

    generate
        for (genvar i = 0; i < NUM_MANAGERS; i++) begin : g_owner_routing
            // Drives request readiness only to the currently selected manager.
            ast_ready_only_to_selected_manager: assert property (
                (s_axi_awready[i] || s_axi_wready[i] || s_axi_arready[i])
                |-> (f_selected_manager == i)
            );

            // Prevents nonowners from being accepted while transaction ownership is
            // locked.
            ast_locked_owner_excludes_other_requests: assert property (
                f_owner_valid && (f_owner_index != i)
                |-> !s_axi_awready[i] && !s_axi_wready[i] &&
                    !s_axi_arready[i]
            );

            // Returns each B response only to the locked write owner with matching
            // payload.
            ast_bvalid_only_to_write_owner: assert property (
                s_axi_bvalid[i]
                |-> f_owner_valid && f_owner_write &&
                    (f_owner_index == i) &&
                    (s_axi_bid[i] == fw_bid) &&
                    (s_axi_bresp[i] == fw_bresp)
            );

            // Returns each R response only to the locked read owner with matching payload.
            ast_rvalid_only_to_read_owner: assert property (
                s_axi_rvalid[i]
                |-> f_owner_valid && !f_owner_write &&
                    (f_owner_index == i) &&
                    (s_axi_rid[i] == fw_rid) &&
                    (s_axi_rdata[i] == fw_rdata) &&
                    (s_axi_rresp[i] == fw_rresp) &&
                    (s_axi_rlast[i] == fw_rlast)
            );

            // Uses only the write owner's BREADY for the firewall response.
            ast_owner_bready_is_selected: assert property (
                f_owner_valid && f_owner_write && (f_owner_index == i)
                |-> fw_bready == s_axi_bready[i]
            );

            // Uses only the read owner's RREADY for the firewall response.
            ast_owner_rready_is_selected: assert property (
                f_owner_valid && !f_owner_write && (f_owner_index == i)
                |-> fw_rready == s_axi_rready[i]
            );

            // Keeps BVALID low for every nonowner manager.
            ast_nonowner_bvalid_low: assert property (
                f_owner_valid && (f_owner_index != i)
                |-> !s_axi_bvalid[i]
            );

            // Keeps RVALID low for every nonowner manager.
            ast_nonowner_rvalid_low: assert property (
                f_owner_valid && (f_owner_index != i)
                |-> !s_axi_rvalid[i]
            );
        end
    endgenerate

    // Keeps write ownership unchanged until the write response completes.
    ast_owner_write_persists_without_b: assert property (
        f_owner_valid && f_owner_write && !fw_s_b_hs
        |=> f_owner_valid && f_owner_write && $stable(f_owner_index)
    );

    // Keeps read ownership unchanged until the final read beat completes.
    ast_owner_read_persists_without_final_r: assert property (
        f_owner_valid && !f_owner_write &&
        !(fw_s_r_hs && fw_rlast)
        |=> f_owner_valid && !f_owner_write && $stable(f_owner_index)
    );

    // Keeps a W-before-AW transaction associated with its original manager.
    ast_w_before_aw_locks_source: assert property (
        f_owner_valid && f_owner_write && !f_aw_seen
        |-> !fw_arvalid &&
            (fw_awvalid ->
             (fw_awuser[AXI_USER_W-1 -: MANAGER_ID_W] ==
              ref_manager_id(f_owner_index)))
    );

    // ------------------------------------------------------------------
    // Trusted identity and policy-request ownership
    // ------------------------------------------------------------------
    // Requires every policy request to match the captured owner and transaction context.
    ast_policy_request_has_captured_owner: assert property (
        policy_req_valid
        |-> f_policy_active &&
            (policy_req_manager_id == f_policy_manager_id) &&
            (policy_req_subordinate_id == f_policy_subordinate_id) &&
            (policy_req_is_write == f_policy_is_write) &&
            (policy_req_start_addr == f_policy_start_addr) &&
            (policy_req_end_addr == f_policy_end_addr)
    );

    // Requires the policy MANAGER_ID to equal the trusted identity of the physical
    // transaction owner.
    ast_policy_manager_is_physical_owner: assert property (
        policy_req_valid
        |-> (policy_req_manager_id == ref_manager_id(f_owner_index))
    );

    // Requires the policy SUBORDINATE_ID to equal the subordinate metadata captured from the
    // selected manager.
    ast_policy_subordinate_is_selected_manager_metadata: assert property (
        policy_req_valid
        |-> (policy_req_subordinate_id == f_subordinate_id)
    );

    // Requires the integrated write policy range to match the captured write burst.
    ast_write_policy_footprint: assert property (
        policy_req_valid && policy_req_is_write
        |-> f_aw_seen &&
            (policy_req_start_addr == ref_policy_start(
                f_awaddr, f_awlen, f_awsize, f_awburst)) &&
            (policy_req_end_addr == ref_policy_end(
                f_awaddr, f_awlen, f_awsize, f_awburst))
    );

    // Requires the integrated read policy range to match the captured read burst.
    ast_read_policy_footprint: assert property (
        policy_req_valid && !policy_req_is_write
        |-> f_ar_seen &&
            (policy_req_start_addr == ref_policy_start(
                f_araddr, f_arlen, f_arsize, f_arburst)) &&
            (policy_req_end_addr == ref_policy_end(
                f_araddr, f_arlen, f_arsize, f_arburst))
    );

    // Prevents the integrated path from issuing a policy request for W data without a
    // captured AW.
    ast_no_policy_request_from_w_alone: assert property (
        f_owner_valid && f_owner_write && !f_aw_seen
        |-> !policy_req_valid
    );

    // Prevents the integrated policy transaction from being both responded to and timed
    // out.
    ast_response_or_timeout_exclusive: assert property (
        !(f_policy_rsp_seen && f_policy_timed_out)
    );

    // Requires the integrated timeout event to produce the reference-model timed-out
    // state.
    ast_timeout_matches_reference_deadline: assert property (
        policy_timeout_fire
        |=> f_policy_timed_out && !f_policy_rsp_seen
    );

    // Requires a policy response on the deadline cycle to win over timeout in the
    // integrated design.
    ast_final_cycle_response_wins_integration: assert property (
        policy_timeout_final_cycle && policy_rsp_hs
        |=> f_policy_rsp_seen && !f_policy_timed_out
    );

    // Keeps the transaction owner and operation type unchanged when timeout occurs.
    ast_timeout_never_changes_owner: assert property (
        policy_timeout_fire && f_owner_valid
        |=> f_owner_valid && $stable(f_owner_index) &&
            $stable(f_owner_write)
    );

    // Blocks arbitration grants and new address admission while the cancellation fence is
    // active.
    ast_quarantine_blocks_all_new_admission: assert property (
        policy_cancel_valid
        |-> (arb_req == '0) && (arb_grant == '0) &&
            !(|s_axi_awready) && !(|s_axi_arready)
    );

    // Blocks new write-data admission after local completion while cancellation remains
    // pending.
    ast_completed_quarantine_blocks_w_owner: assert property (
        f_policy_axi_complete_seen && policy_cancel_valid
        |-> !(|s_axi_wready)
    );

    // Keeps the cancellation fence active after local completion until an accepted
    // timed-out request is retired.
    ast_accepted_timeout_completion_keeps_cancel_fence: assert property (
        f_policy_timed_out && f_policy_timeout_after_req &&
        policy_axi_complete_hs && !f_policy_cancel_seen &&
        !policy_cancel_hs
        |=> policy_cancel_valid && (arb_req == '0)
    );

    // Keeps policy-response readiness low while the integrated cancellation fence is
    // active.
    ast_quarantine_rejects_stale_response: assert property (
        policy_cancel_valid |-> !policy_rsp_ready
    );

    // Prevents policy-interface reuse until cancellation retires the timed-out accepted
    // request.
    ast_cancel_retirement_precedes_reuse: assert property (
        f_policy_timed_out && f_policy_timeout_after_req &&
        !f_policy_cancel_seen
        |-> !policy_req_valid
    );

    // ------------------------------------------------------------------
    // Resource decode, lock, response mux, and structural error target
    // ------------------------------------------------------------------
    // Requires each encoded SUBORDINATE_ID to decode to at most one protected-subordinate
    // port.
    ast_subordinate_map_decode_onehot: assert property (
        $onehot0(ref_subordinate_decode(
            fw_m_awuser[SUBORDINATE_ID_W-1:0])) &&
        $onehot0(ref_subordinate_decode(
            fw_m_aruser[SUBORDINATE_ID_W-1:0]))
    );

    // Allows at most one protected subordinate to receive an AW or AR address, and never both
    // address types simultaneously.
    ast_at_most_one_subordinate_address: assert property (
        $onehot0(m_axi_awvalid) && $onehot0(m_axi_arvalid) &&
        !((|m_axi_awvalid) && (|m_axi_arvalid))
    );

    // Allows write data, write-response readiness, and read-response readiness to target
    // at most one protected subordinate.
    ast_at_most_one_subordinate_data_or_response: assert property (
        $onehot0(m_axi_wvalid) && $onehot0(m_axi_bready) &&
        $onehot0(m_axi_rready)
    );

    // Prevents simultaneous write and read responses on the firewall and manager-facing
    // interfaces.
    ast_upstream_response_channel_mutex: assert property (
        !(fw_bvalid && fw_rvalid) &&
        !((|s_axi_bvalid) && (|s_axi_rvalid))
    );

    // Requires the physical AW-valid vector to equal the exact decode of the requested
    // SUBORDINATE_ID.
    ast_write_address_decode_exact: assert property (
        m_axi_awvalid ==
        ({NUM_SUBORDINATES{fw_m_awvalid}} &
         ref_subordinate_decode(
             fw_m_awuser[SUBORDINATE_ID_W-1:0]))
    );

    // Requires the physical AR-valid vector to equal the exact decode of the requested
    // SUBORDINATE_ID.
    ast_read_address_decode_exact: assert property (
        m_axi_arvalid ==
        ({NUM_SUBORDINATES{fw_m_arvalid}} &
         ref_subordinate_decode(
             fw_m_aruser[SUBORDINATE_ID_W-1:0]))
    );

    // Routes an unimplemented write address to the local target and selects no physical
    // subordinate.
    ast_unimplemented_aw_selects_no_subordinate: assert property (
        fw_m_awvalid &&
        !ref_subordinate_implemented(
            fw_m_awuser[SUBORDINATE_ID_W-1:0])
        |-> !(|m_axi_awvalid) && fw_m_awready
    );

    // Routes an unimplemented read address to the local target and selects no physical
    // subordinate.
    ast_unimplemented_ar_selects_no_subordinate: assert property (
        fw_m_arvalid &&
        !ref_subordinate_implemented(
            fw_m_aruser[SUBORDINATE_ID_W-1:0])
        |-> !(|m_axi_arvalid) && fw_m_arready
    );

    // Prevents simultaneous active write and read subordinate routes.
    ast_subordinate_route_mutex: assert property (
        !(f_wr_route_valid && f_rd_route_valid)
    );

    // Requires the locked write route and implementation status to match the captured
    // SUBORDINATE_ID.
    ast_write_route_matches_captured_subordinate: assert property (
        f_wr_route_valid
        |-> (f_wr_route_onehot ==
             ref_subordinate_decode(f_wr_route_subordinate_id)) &&
            (f_wr_route_implemented ==
             ref_subordinate_implemented(f_wr_route_subordinate_id)) &&
            (f_wr_route_subordinate_id == f_subordinate_id)
    );

    // Requires the locked read route and implementation status to match the captured
    // SUBORDINATE_ID.
    ast_read_route_matches_captured_subordinate: assert property (
        f_rd_route_valid
        |-> (f_rd_route_onehot ==
             ref_subordinate_decode(f_rd_route_subordinate_id)) &&
            (f_rd_route_implemented ==
             ref_subordinate_implemented(f_rd_route_subordinate_id)) &&
            (f_rd_route_subordinate_id == f_subordinate_id)
    );

    // Keeps the write-subordinate route and transaction ID stable until the upstream B
    // handshake completes.
    ast_write_route_locked_until_manager_b: assert property (
        f_wr_route_valid && !fw_s_b_hs
        |=> f_wr_route_valid &&
            $stable({f_wr_route_implemented, f_wr_route_onehot,
                     f_wr_route_subordinate_id,
                     f_wr_route_id})
    );

    // Keeps the read-subordinate route and transaction ID stable until the final upstream R
    // handshake completes.
    ast_read_route_locked_until_manager_final_r: assert property (
        f_rd_route_valid && !(fw_s_r_hs && fw_rlast)
        |=> f_rd_route_valid &&
            $stable({f_rd_route_implemented, f_rd_route_onehot,
                     f_rd_route_subordinate_id,
                     f_rd_route_id})
    );

    // Routes WVALID only to the locked implemented write subordinate.
    ast_write_data_route_exact: assert property (
        f_wr_route_valid
        |-> m_axi_wvalid ==
            ({NUM_SUBORDINATES{fw_m_wvalid}} &
             (f_wr_route_implemented ? f_wr_route_onehot : '0))
    );

    // Routes BREADY only to the locked implemented write subordinate.
    ast_write_response_ready_route_exact: assert property (
        f_wr_route_valid
        |-> m_axi_bready ==
            ({NUM_SUBORDINATES{fw_m_bready}} &
             (f_wr_route_implemented ? f_wr_route_onehot : '0))
    );

    // Routes RREADY only to the locked implemented read subordinate.
    ast_read_response_ready_route_exact: assert property (
        f_rd_route_valid
        |-> m_axi_rready ==
            ({NUM_SUBORDINATES{fw_m_rready}} &
             (f_rd_route_implemented ? f_rd_route_onehot : '0))
    );

    // Keeps write-data and write-response routing quiet when no write route is active.
    ast_no_write_route_is_quiet: assert property (
        !f_wr_route_valid
        |-> !(|m_axi_wvalid) && !(|m_axi_bready) && !fw_m_bvalid
    );

    // Keeps read-response routing quiet when no read route is active.
    ast_no_read_route_is_quiet: assert property (
        !f_rd_route_valid
        |-> !(|m_axi_rready) && !fw_m_rvalid
    );

    generate
        for (genvar r = 0; r < NUM_SUBORDINATES; r++) begin : g_subordinate_routing
            // Requires the selected protected subordinate to receive the exact firewall AW
            // payload.
            ast_aw_payload_to_selected_subordinate: assert property (
                m_axi_awvalid[r]
                |-> (fw_m_awuser[SUBORDINATE_ID_W-1:0] ==
                     SUBORDINATE_ID_MAP[r*SUBORDINATE_ID_W +: SUBORDINATE_ID_W]) &&
                    (m_axi_awid[r] == fw_m_awid) &&
                    (m_axi_awaddr[r] == fw_m_awaddr) &&
                    (m_axi_awlen[r] == fw_m_awlen) &&
                    (m_axi_awsize[r] == fw_m_awsize) &&
                    (m_axi_awburst[r] == fw_m_awburst) &&
                    (m_axi_awuser[r] == fw_m_awuser)
            );

            // Returns AWREADY from exactly the protected subordinate selected by
            // SUBORDINATE_ID.
            ast_aw_ready_from_selected_subordinate: assert property (
                fw_m_awvalid &&
                (fw_m_awuser[SUBORDINATE_ID_W-1:0] ==
                 SUBORDINATE_ID_MAP[r*SUBORDINATE_ID_W +: SUBORDINATE_ID_W])
                |-> fw_m_awready == m_axi_awready[r]
            );

            // Requires the locked write subordinate to receive the exact firewall W payload.
            ast_w_payload_to_locked_subordinate: assert property (
                m_axi_wvalid[r]
                |-> f_wr_route_valid && f_wr_route_implemented &&
                    f_wr_route_onehot[r] &&
                    (m_axi_wdata[r] == fw_m_wdata) &&
                    (m_axi_wstrb[r] == fw_m_wstrb) &&
                    (m_axi_wlast[r] == fw_m_wlast)
            );

            // Returns WREADY from the locked implemented write subordinate.
            ast_w_ready_from_locked_subordinate: assert property (
                f_wr_route_valid && f_wr_route_implemented &&
                f_wr_route_onehot[r]
                |-> fw_m_wready == m_axi_wready[r]
            );

            // Returns BVALID, BID, and BRESP from the locked implemented write subordinate.
            ast_b_from_locked_subordinate: assert property (
                f_wr_route_valid && f_wr_route_implemented &&
                f_wr_route_onehot[r]
                |-> (fw_m_bvalid == m_axi_bvalid[r]) &&
                    (!fw_m_bvalid ||
                     ((fw_m_bid == m_axi_bid[r]) &&
                      (fw_m_bresp == m_axi_bresp[r])))
            );

            // Requires the selected protected subordinate to receive the exact firewall AR
            // payload.
            ast_ar_payload_to_selected_subordinate: assert property (
                m_axi_arvalid[r]
                |-> (fw_m_aruser[SUBORDINATE_ID_W-1:0] ==
                     SUBORDINATE_ID_MAP[r*SUBORDINATE_ID_W +: SUBORDINATE_ID_W]) &&
                    (m_axi_arid[r] == fw_m_arid) &&
                    (m_axi_araddr[r] == fw_m_araddr) &&
                    (m_axi_arlen[r] == fw_m_arlen) &&
                    (m_axi_arsize[r] == fw_m_arsize) &&
                    (m_axi_arburst[r] == fw_m_arburst) &&
                    (m_axi_aruser[r] == fw_m_aruser)
            );

            // Returns ARREADY from exactly the protected subordinate selected by
            // SUBORDINATE_ID.
            ast_ar_ready_from_selected_subordinate: assert property (
                fw_m_arvalid &&
                (fw_m_aruser[SUBORDINATE_ID_W-1:0] ==
                 SUBORDINATE_ID_MAP[r*SUBORDINATE_ID_W +: SUBORDINATE_ID_W])
                |-> fw_m_arready == m_axi_arready[r]
            );

            // Returns RVALID and the complete R payload from the locked implemented read
            // subordinate.
            ast_r_from_locked_subordinate: assert property (
                f_rd_route_valid && f_rd_route_implemented &&
                f_rd_route_onehot[r]
                |-> (fw_m_rvalid == m_axi_rvalid[r]) &&
                    (!fw_m_rvalid ||
                     ((fw_m_rid == m_axi_rid[r]) &&
                      (fw_m_rdata == m_axi_rdata[r]) &&
                      (fw_m_rresp == m_axi_rresp[r]) &&
                      (fw_m_rlast == m_axi_rlast[r])))
            );

            // Prevents an unselected or unmapped subordinate from completing a write
            // response handshake.
            ast_unselected_subordinate_cannot_handshake_b: assert property (
                f_wr_route_valid &&
                (!f_wr_route_implemented || !f_wr_route_onehot[r])
                |-> !m_axi_bready[r]
            );

            // Prevents an unselected or unmapped subordinate from completing a read
            // response handshake.
            ast_unselected_subordinate_cannot_handshake_r: assert property (
                f_rd_route_valid &&
                (!f_rd_route_implemented || !f_rd_route_onehot[r])
                |-> !m_axi_rready[r]
            );
        end
    endgenerate

    // Permits physical-subordinate AXI activity only after effective authorization of a
    // legal, non-timed-out transaction.
    ast_no_physical_subordinate_before_effective_allow: assert property (
        (|m_axi_awvalid) || (|m_axi_wvalid) || (|m_axi_bready) ||
        (|m_axi_arvalid) || (|m_axi_rready)
        |-> f_policy_rsp_seen && f_policy_effective_allow &&
            f_policy_legal && !f_policy_timed_out
    );

    // Keeps every physical protected subordinate inactive after initial denial or timeout.
    ast_initial_denial_isolates_all_subordinates: assert property (
        (f_policy_rsp_seen && !f_policy_effective_allow) ||
        f_policy_timed_out
        |-> !(|m_axi_awvalid) && !(|m_axi_wvalid) &&
            !(|m_axi_bready) && !(|m_axi_arvalid) &&
            !(|m_axi_rready)
    );

    // Keeps every physical protected subordinate inactive when an externally allowed
    // transaction is locally illegal.
    ast_illegal_allow_never_reaches_subordinate: assert property (
        f_policy_rsp_seen && !f_policy_legal
        |-> !(|m_axi_awvalid) && !(|m_axi_wvalid) &&
            !(|m_axi_bready) && !(|m_axi_arvalid) &&
            !(|m_axi_rready)
    );

    // Keeps every physical protected subordinate inactive when revocation coincides with an
    // Allow response.
    ast_response_coincident_revoke_never_reaches_subordinate: assert property (
        policy_rsp_hs && policy_rsp_allow && f_policy_legal &&
        policy_revoke_valid
        |=> !(|m_axi_awvalid) && !(|m_axi_wvalid) &&
            !(|m_axi_bready) && !(|m_axi_arvalid) &&
            !(|m_axi_rready)
    );

    // Keeps every physical protected subordinate inactive after policy timeout.
    ast_timeout_never_reaches_subordinate: assert property (
        f_policy_timed_out
        |-> !(|m_axi_awvalid) && !(|m_axi_wvalid) &&
            !(|m_axi_bready) && !(|m_axi_arvalid) &&
            !(|m_axi_rready)
    );

    // Ensures an unimplemented write uses only the local error target and no physical
    // subordinate.
    ast_unimplemented_write_uses_local_target: assert property (
        f_wr_route_valid && !f_wr_route_implemented
        |-> !(|m_axi_awvalid) && !(|m_axi_wvalid) &&
            !(|m_axi_bready)
    );

    // Ensures an unimplemented read uses only the local error target and no physical
    // subordinate.
    ast_unimplemented_read_uses_local_target: assert property (
        f_rd_route_valid && !f_rd_route_implemented
        |-> !(|m_axi_arvalid) && !(|m_axi_rready)
    );

    // Requires the local target to return DECERR with the routed write ID after all
    // expected write beats.
    ast_unimplemented_write_local_b: assert property (
        f_wr_route_valid && !f_wr_route_implemented && fw_m_bvalid
        |-> (fw_m_bid == f_wr_route_id) &&
            (fw_m_bresp == AXI_RESP_DECERR) &&
            (f_fw_w_count == f_fw_w_expected)
    );

    // Requires the local target to return zero-data DECERR read beats with the routed ID
    // and correct RLAST.
    ast_unimplemented_read_local_r: assert property (
        f_rd_route_valid && !f_rd_route_implemented && fw_m_rvalid
        |-> (fw_m_rid == f_rd_route_id) &&
            (fw_m_rdata == '0) &&
            (fw_m_rresp == AXI_RESP_DECERR) &&
            (fw_m_rlast ==
             ((f_fw_r_count + 9'd1) == f_fw_r_expected))
    );

    // Requires an unimplemented read to complete with exactly the ARLEN-derived number of
    // local response beats.
    ast_unimplemented_read_exact_count: assert property (
        f_rd_route_valid && !f_rd_route_implemented &&
        fw_m_r_hs && fw_m_rlast
        |-> (f_fw_r_count + 9'd1) == f_fw_r_expected
    );

    // ------------------------------------------------------------------
    // End-to-end framing, conservation, denial, and revocation association
    // ------------------------------------------------------------------
    // Prevents accepted upstream write beats from exceeding the AWLEN-derived expected
    // count.
    ast_upstream_w_count_bounded: assert property (
        f_aw_seen |-> f_s_w_count <= f_w_expected
    );

    // Prevents firewall-to-subordinate write beats from exceeding the routed write's expected
    // count.
    ast_firewall_w_count_bounded: assert property (
        f_wr_route_valid |-> f_fw_w_count <= f_fw_w_expected
    );

    // Requires firewall-side WLAST to occur exactly on the expected final routed write
    // beat.
    ast_firewall_wlast_framing: assert property (
        fw_m_w_hs
        |-> fw_m_wlast ==
            ((f_fw_w_count + 9'd1) == f_fw_w_expected)
    );

    // Requires each routed write beat to handshake with exactly the selected physical
    // subordinate.
    ast_physical_write_beat_conservation: assert property (
        fw_m_w_hs && f_wr_route_implemented
        |-> $onehot(m_w_hs) &&
            ((m_w_hs & f_wr_route_onehot) != '0)
    );

    // Prevents physical-subordinate write beats for an unmapped subordinate handled locally.
    ast_local_write_has_no_physical_beats: assert property (
        fw_m_w_hs && !f_wr_route_implemented
        |-> !(|m_w_hs)
    );

    // Requires write completion counts to agree across manager, firewall, and
    // routed-subordinate views.
    ast_write_completion_conservation: assert property (
        fw_s_b_hs && f_wr_route_valid
        |-> (f_fw_w_count == f_fw_w_expected) &&
            (f_s_w_count == f_w_expected) &&
            (f_fw_w_expected == f_w_expected)
    );

    // Prevents delivered upstream read beats from exceeding the ARLEN-derived expected
    // count.
    ast_upstream_read_count_bounded: assert property (
        f_ar_seen |-> f_s_r_count <= f_r_expected
    );

    // Prevents firewall-side read beats from exceeding the routed read's expected count.
    ast_firewall_read_count_bounded: assert property (
        f_rd_route_valid |-> f_fw_r_count <= f_fw_r_expected
    );

    // Requires each routed read beat to handshake with exactly the selected physical
    // subordinate.
    ast_physical_read_beat_conservation: assert property (
        fw_m_r_hs && f_rd_route_implemented
        |-> $onehot(m_r_hs) &&
            ((m_r_hs & f_rd_route_onehot) != '0)
    );

    // Prevents physical-subordinate read beats for an unmapped subordinate handled locally.
    ast_local_read_has_no_physical_beats: assert property (
        fw_m_r_hs && !f_rd_route_implemented
        |-> !(|m_r_hs)
    );

    // Requires an upstream read completion to contain exactly the expected number of
    // beats.
    ast_read_completion_conservation: assert property (
        fw_s_r_hs && fw_rlast
        |-> (f_s_r_count + 9'd1) == f_r_expected
    );

    // Requires routed-read completion counts to agree across subordinate, firewall, and
    // manager views.
    ast_routed_read_completion_conservation: assert property (
        fw_s_r_hs && fw_rlast && f_rd_route_valid
        |-> (f_fw_r_count == f_fw_r_expected) &&
            (f_fw_r_expected == f_r_expected) &&
            ((f_s_r_count + 9'd1) == f_r_expected)
    );

    // Returns DECERR with the original write ID to the owner for an initial write denial
    // or timeout.
    ast_initial_denied_write_returns_owner_decerr: assert property (
        fw_bvalid && f_owner_write &&
        ((f_policy_rsp_seen && !f_policy_effective_allow) ||
         f_policy_timed_out)
        |-> (fw_bid == f_awid) && (fw_bresp == AXI_RESP_DECERR)
    );

    // Returns zero-data DECERR beats with the original read ID and correct framing for an
    // initial read denial or timeout.
    ast_initial_denied_read_returns_owner_decerr: assert property (
        fw_rvalid && !f_owner_write &&
        ((f_policy_rsp_seen && !f_policy_effective_allow) ||
         f_policy_timed_out)
        |-> (fw_rid == f_arid) && (fw_rdata == '0) &&
            (fw_rresp == AXI_RESP_DECERR) &&
            (fw_rlast == ((f_s_r_count + 9'd1) == f_r_expected))
    );

    // Returns DECERR with the original write ID when the requested subordinate is
    // unimplemented.
    ast_unimplemented_write_returns_owner_decerr: assert property (
        fw_bvalid && f_wr_route_valid && !f_wr_route_implemented
        |-> (fw_bid == f_awid) && (fw_bresp == AXI_RESP_DECERR)
    );

    // Returns zero-data DECERR with the original read ID when the requested subordinate is
    // unimplemented.
    ast_unimplemented_read_returns_owner_decerr: assert property (
        fw_rvalid && f_rd_route_valid && !f_rd_route_implemented
        |-> (fw_rid == f_arid) && (fw_rdata == '0) &&
            (fw_rresp == AXI_RESP_DECERR)
    );

    // Keeps a late-revoked write bound to the same physical subordinate until completion.
    ast_late_write_revoke_keeps_subordinate: assert property (
        f_wr_route_valid && f_wr_route_implemented &&
        f_policy_effective_allow && policy_revoke_valid &&
        !fw_s_b_hs
        |=> f_wr_route_valid && $stable(f_wr_route_onehot)
    );

    // Keeps a late-revoked read bound to the same physical subordinate until completion.
    ast_late_read_revoke_keeps_subordinate: assert property (
        f_rd_route_valid && f_rd_route_implemented &&
        f_policy_effective_allow && policy_revoke_valid &&
        !(fw_s_r_hs && fw_rlast)
        |=> f_rd_route_valid && $stable(f_rd_route_onehot)
    );

    // After write timeout, accepts remaining write data only from the locked transaction
    // owner.
    ast_timeout_write_drains_only_owner: assert property (
        f_policy_timed_out && f_policy_is_write &&
        f_owner_valid && !f_s_wlast_seen
        |-> s_axi_wready[f_owner_index] &&
            ((s_axi_wready & ~ref_manager_onehot(f_owner_index)) == '0)
    );

    // Requires locally generated timeout-read responses to use the original RID, zero
    // data, DECERR, and correct RLAST.
    ast_timeout_read_framing: assert property (
        f_policy_timed_out && !f_policy_is_write && fw_rvalid
        |-> (fw_rid == f_arid) && (fw_rdata == '0) &&
            (fw_rresp == AXI_RESP_DECERR) &&
            (fw_rlast == ((f_s_r_count + 9'd1) == f_r_expected))
    );

    // ------------------------------------------------------------------
    // Integration reachability
    // ------------------------------------------------------------------
    generate
        for (genvar i = 0; i < NUM_MANAGERS; i++) begin : g_manager_covers
            // Shows that each manager can win arbitration and have a transaction transfer
            // accepted.
            cvr_manager_wins_arbitration: cover property (
                arb_grant[i] &&
                (s_aw_hs[i] || s_w_hs[i] || s_ar_hs[i])
            );

            // Exercises each manager completing a write with AW accepted before W.
            cvr_manager_aw_before_w: cover property (
                s_aw_hs[i] && !s_w_hs[i]
                ##[1:$] s_w_hs[i]
                ##[1:$] s_b_hs[i]
            );

            // Exercises each manager completing a write with W accepted before AW.
            cvr_manager_w_before_aw: cover property (
                s_w_hs[i] && !s_aw_hs[i]
                ##[1:$] s_aw_hs[i]
                ##[1:$] s_b_hs[i]
            );

            // Exercises each manager completing a write with AW and W accepted together.
            cvr_manager_simultaneous_aw_w: cover property (
                s_aw_hs[i] && s_w_hs[i]
                ##[1:$] s_b_hs[i]
            );

            // Exercises policy denial and verifies that DECERR completion returns to the
            // owning manager.
            cvr_manager_policy_deny_returns_here: cover property (
                f_owner_valid && (f_owner_index == i) &&
                policy_rsp_hs && !policy_rsp_allow
                ##[1:$]
                ((s_b_hs[i] &&
                  (s_axi_bresp[i] == AXI_RESP_DECERR)) ||
                 (s_r_hs[i] && s_axi_rlast[i] &&
                  (s_axi_rresp[i] == AXI_RESP_DECERR)))
            );
        end

        for (genvar r = 0; r < NUM_SUBORDINATES; r++) begin : g_subordinate_covers
            // Exercises an allowed write through each protected subordinate and back to a
            // manager response.
            cvr_allowed_write_to_subordinate: cover property (
                m_aw_hs[r]
                ##[1:$] m_b_hs[r]
                ##1 (|s_b_hs)
            );

            // Exercises an allowed read through each protected subordinate and back through
            // the final manager read beat.
            cvr_allowed_read_from_subordinate: cover property (
                m_ar_hs[r]
                ##[1:$] m_r_hs[r] && m_axi_rlast[r]
                ##1 ((|s_r_hs) && (|(s_r_hs & s_axi_rlast)))
            );
        end

        if (NUM_MANAGERS >= 2) begin : g_contention_covers
            // Exercises simultaneous requests from all managers with the highest-priority
            // manager selected.
            cvr_all_managers_request_highest_wins: cover property (
                ((s_axi_awvalid | s_axi_wvalid | s_axi_arvalid) ==
                 {NUM_MANAGERS{1'b1}}) && arb_grant[0] &&
                (s_aw_hs[0] || s_w_hs[0] || s_ar_hs[0])
            );

            // Shows that the lowest-priority manager can win when all higher-priority
            // managers are idle.
            cvr_lower_priority_wins_when_higher_idle: cover property (
                ((s_axi_awvalid | s_axi_wvalid | s_axi_arvalid) ==
                 {1'b1, {(NUM_MANAGERS-1){1'b0}}}) &&
                arb_grant[NUM_MANAGERS-1]
            );

            // Exercises transaction completion followed immediately by admission of a
            // different manager.
            cvr_back_to_back_different_managers: cover property (
                ((|s_b_hs) || (|(s_r_hs & s_axi_rlast)))
                ##1 ((|s_aw_hs) || (|s_w_hs) || (|s_ar_hs)) &&
                    (manager_onehot_index(s_aw_hs | s_w_hs | s_ar_hs) !=
                     f_history_manager)
            );

            // Exercises consecutive transactions from different managers through
            // completion without cross-routing.
            cvr_adjacent_transactions_no_cross_route: cover property (
                f_history_valid && f_owner_valid &&
                (f_history_manager != f_owner_index)
                ##[1:$]
                ((|s_b_hs) || (|(s_r_hs & s_axi_rlast)))
            );
        end
    endgenerate

    // Exercises simultaneous raw write/read contention while the write side is selected.
    cvr_raw_aw_ar_contention_write_selected: cover property (
        !f_owner_valid &&
        (|(s_axi_awvalid | s_axi_wvalid)) &&
        (|s_axi_arvalid) &&
        (fw_s_aw_hs || fw_s_w_hs) && !fw_s_ar_hs
    );

    // Exercises a spoofed manager-supplied identity and shows replacement by the trusted
    // physical-port MANAGER_ID.
    cvr_trusted_id_overwrites_spoof_attempt: cover property (
        fw_s_aw_hs &&
        (s_axi_awuser[f_selected_manager][AXI_USER_W-1 -: MANAGER_ID_W] !=
         ref_manager_id(f_selected_manager)) &&
        (fw_awuser[AXI_USER_W-1 -: MANAGER_ID_W] ==
         ref_manager_id(f_selected_manager))
        ##[1:$] policy_req_hs &&
                  (policy_req_manager_id == ref_manager_id(f_owner_index))
    );

    // Exercises a second AW from the current owner being blocked while the first write
    // address remains active.
    cvr_queued_next_aw_is_blocked: cover property (
        f_owner_valid && f_aw_seen &&
        s_axi_awvalid[f_owner_index] &&
        !s_axi_awready[f_owner_index] && !fw_awvalid
    );

    // Exercises a second AR from the current owner being blocked while the first read
    // address remains active.
    cvr_queued_next_ar_is_blocked: cover property (
        f_owner_valid && f_ar_seen &&
        s_axi_arvalid[f_owner_index] &&
        !s_axi_arready[f_owner_index] && !fw_arvalid
    );

    // Exercises write policy denial and DECERR completion to the transaction owner.
    cvr_policy_deny_write_owner_decerr: cover property (
        policy_rsp_hs && f_policy_is_write && !policy_rsp_allow
        ##[1:$] fw_s_b_hs && (fw_bresp == AXI_RESP_DECERR)
    );

    // Exercises read policy denial and final DECERR completion to the owner.
    cvr_policy_deny_read_owner_decerr: cover property (
        policy_rsp_hs && !f_policy_is_write && !policy_rsp_allow
        ##[1:$] fw_s_r_hs && fw_rlast &&
                  (fw_rresp == AXI_RESP_DECERR)
    );

    // Exercises policy Allow of an illegal write while the architecture still returns
    // DECERR to the owner.
    cvr_illegal_write_owner_decerr: cover property (
        policy_rsp_hs && f_policy_is_write && policy_rsp_allow &&
        !f_policy_legal
        ##[1:$] fw_s_b_hs && (fw_bresp == AXI_RESP_DECERR)
    );

    // Exercises policy Allow of an illegal read while the architecture still returns
    // DECERR to the owner.
    cvr_illegal_read_owner_decerr: cover property (
        policy_rsp_hs && !f_policy_is_write && policy_rsp_allow &&
        !f_policy_legal
        ##[1:$] fw_s_r_hs && fw_rlast &&
                  (fw_rresp == AXI_RESP_DECERR)
    );

    // Exercises write Allow coincident with revocation and DECERR completion to the owner.
    cvr_response_revoke_write_owner_decerr: cover property (
        policy_rsp_hs && f_policy_is_write && policy_rsp_allow &&
        f_policy_legal && policy_revoke_valid
        ##[1:$] fw_s_b_hs && (fw_bresp == AXI_RESP_DECERR)
    );

    // Exercises read Allow coincident with revocation and DECERR completion to the owner.
    cvr_response_revoke_read_owner_decerr: cover property (
        policy_rsp_hs && !f_policy_is_write && policy_rsp_allow &&
        f_policy_legal && policy_revoke_valid
        ##[1:$] fw_s_r_hs && fw_rlast &&
                  (fw_rresp == AXI_RESP_DECERR)
    );

    // Exercises late write revocation while preserving the locked owner/subordinate
    // association through DECERR completion.
    cvr_late_write_revoke_same_owner_subordinate: cover property (
        f_wr_route_valid && f_wr_route_implemented &&
        f_policy_effective_allow && policy_revoke_valid
        ##[1:$] fw_s_b_hs && (fw_bresp == AXI_RESP_DECERR)
    );

    // Exercises late read revocation while preserving the locked owner/subordinate
    // association through final read completion.
    cvr_late_read_revoke_same_owner_subordinate: cover property (
        f_rd_route_valid && f_rd_route_implemented &&
        f_policy_effective_allow && policy_revoke_valid
        ##[1:$] fw_s_r_hs && fw_rlast
    );

    generate
        if (POLICY_TIMEOUT_ENABLE) begin : g_timeout_covers
            // Exercises timeout before policy-request acceptance without entering
            // cancellation quarantine.
            cvr_timeout_before_policy_request_acceptance: cover property (
                policy_timeout_fire && !f_policy_req_seen && !policy_req_hs
                ##1 f_policy_timed_out &&
                    !f_policy_timeout_after_req && !policy_cancel_valid
            );

            // Exercises timeout after policy-request acceptance and entry into
            // cancellation quarantine.
            cvr_timeout_after_policy_request_acceptance: cover property (
                policy_timeout_fire && (f_policy_req_seen || policy_req_hs)
                ##1 f_policy_timed_out &&
                    f_policy_timeout_after_req && policy_cancel_valid
            );

            // Exercises cancellation backpressure followed by cancellation retirement in
            // the integrated architecture.
            cvr_policy_cancellation_backpressure: cover property (
                policy_cancel_valid && !policy_cancel_ready
                ##1 policy_cancel_valid && !policy_cancel_ready
                ##1 policy_cancel_hs
            );

            // Exercises local AXI completion before cancellation retirement for an
            // accepted timed-out policy request.
            cvr_local_completion_before_cancellation: cover property (
                f_policy_timed_out && f_policy_timeout_after_req &&
                policy_axi_complete_hs && !policy_cancel_hs
                ##[1:$] policy_cancel_hs
            );

            // Exercises cancellation retirement before the local AXI completion of a
            // timed-out transaction.
            cvr_cancellation_before_local_completion: cover property (
                policy_cancel_hs && f_policy_timed_out &&
                !f_policy_axi_complete_seen
                ##[1:$] policy_axi_complete_hs
            );

            // Exercises admission of a new manager after cancellation retirement releases
            // the ownership fence.
            cvr_new_manager_after_cancellation_retirement: cover property (
                policy_cancel_hs
                ##[1:$] ((|s_aw_hs) || (|s_w_hs) || (|s_ar_hs))
            );

            // Exercises multi-manager contention followed by an accepted-request timeout
            // and quarantine.
            cvr_contention_with_policy_timeout_quarantine: cover property (
                !f_owner_valid &&
                $countones(s_axi_awvalid | s_axi_wvalid |
                           s_axi_arvalid) > 1
                ##[1:$] policy_timeout_fire &&
                          (f_policy_req_seen || policy_req_hs)
                ##1 policy_cancel_valid
            );
        end
    endgenerate

    // Exercises multi-manager contention together with policy-request backpressure before
    // acceptance.
    cvr_contention_with_policy_request_backpressure: cover property (
        !f_owner_valid &&
        $countones(s_axi_awvalid | s_axi_wvalid | s_axi_arvalid) > 1
        ##[1:$] policy_req_valid && !policy_req_ready
        ##1 policy_req_hs
    );

    // Exercises an authorized write to an unmapped subordinate and local structural DECERR
    // propagation to the manager.
    cvr_unimplemented_write_structural_error: cover property (
        fw_m_aw_hs &&
        !ref_subordinate_implemented(
            fw_m_awuser[SUBORDINATE_ID_W-1:0])
        ##[1:$] fw_m_b_hs && (fw_m_bresp == AXI_RESP_DECERR)
        ##1 fw_s_b_hs && (fw_bresp == AXI_RESP_DECERR)
    );

    // Exercises an authorized read to an unmapped subordinate and local structural DECERR
    // propagation through RLAST.
    cvr_unimplemented_read_structural_error: cover property (
        fw_m_ar_hs &&
        !ref_subordinate_implemented(
            fw_m_aruser[SUBORDINATE_ID_W-1:0])
        ##[1:$] fw_m_r_hs && fw_m_rlast &&
                  (fw_m_rresp == AXI_RESP_DECERR)
        ##1 fw_s_r_hs && fw_rlast &&
              (fw_rresp == AXI_RESP_DECERR)
    );

    // Exercises the same physical manager accessing different protected subordinates across
    // transactions.
    cvr_one_manager_different_subordinates: cover property (
        f_history_valid && policy_req_hs &&
        (f_owner_index == f_history_manager) &&
        (policy_req_subordinate_id != f_history_subordinate)
    );

    // Exercises different physical managers accessing the same protected subordinate across
    // transactions.
    cvr_different_managers_same_subordinate: cover property (
        f_history_valid && policy_req_hs &&
        (f_owner_index != f_history_manager) &&
        (policy_req_subordinate_id == f_history_subordinate)
    );

    // Exercises a 256-beat write while preserving one owner/subordinate route through
    // completion.
    cvr_maximum_length_write_one_owner_subordinate: cover property (
        fw_m_aw_hs && (fw_m_awlen == 8'hff)
        ##[1:$] fw_s_b_hs &&
                  (f_fw_w_count == 9'd256) &&
                  (f_s_w_count == 9'd256)
    );

    // Exercises a 256-beat read while preserving one owner/subordinate route through the
    // final beat.
    cvr_maximum_length_read_one_owner_subordinate: cover property (
        fw_m_ar_hs && (fw_m_arlen == 8'hff)
        ##[1:$] fw_s_r_hs && fw_rlast &&
                  (f_fw_r_count == 9'd256) &&
                  (f_s_r_count == 9'd255)
    );

    // Policy-generation reference history records AW/AR capture, accepted
    // requests/responses, timeout, cancellation, and safe retirement.
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            f_policy_active            <= 1'b0;
            f_policy_is_write          <= 1'b0;
            f_policy_legal             <= 1'b0;
            f_policy_manager_id         <= '0;
            f_policy_subordinate_id       <= '0;
            f_policy_start_addr        <= '0;
            f_policy_end_addr          <= '0;
            f_policy_req_seen          <= 1'b0;
            f_policy_rsp_seen          <= 1'b0;
            f_policy_effective_allow   <= 1'b0;
            f_policy_timed_out         <= 1'b0;
            f_policy_timeout_after_req <= 1'b0;
            f_policy_cancel_seen       <= 1'b0;
            f_policy_axi_complete_seen <= 1'b0;
        end
        else if ((policy_axi_complete_hs &&
                  (!f_policy_timeout_after_req ||
                   f_policy_cancel_seen || policy_cancel_hs)) ||
                 (policy_cancel_hs && f_policy_axi_complete_seen)) begin
            f_policy_active            <= 1'b0;
            f_policy_is_write          <= 1'b0;
            f_policy_legal             <= 1'b0;
            f_policy_manager_id         <= '0;
            f_policy_subordinate_id       <= '0;
            f_policy_start_addr        <= '0;
            f_policy_end_addr          <= '0;
            f_policy_req_seen          <= 1'b0;
            f_policy_rsp_seen          <= 1'b0;
            f_policy_effective_allow   <= 1'b0;
            f_policy_timed_out         <= 1'b0;
            f_policy_timeout_after_req <= 1'b0;
            f_policy_cancel_seen       <= 1'b0;
            f_policy_axi_complete_seen <= 1'b0;
        end
        else begin
            if (policy_axi_complete_hs)
                f_policy_axi_complete_seen <= 1'b1;

            if (fw_s_aw_hs) begin
                f_policy_active            <= 1'b1;
                f_policy_is_write          <= 1'b1;
                f_policy_legal             <= ref_burst_legal(
                    fw_awaddr, fw_awlen, fw_awsize, fw_awburst);
                f_policy_manager_id         <=
                    fw_awuser[AXI_USER_W-1 -: MANAGER_ID_W];
                f_policy_subordinate_id       <=
                    fw_awuser[SUBORDINATE_ID_W-1:0];
                f_policy_start_addr        <= ref_policy_start(
                    fw_awaddr, fw_awlen, fw_awsize, fw_awburst);
                f_policy_end_addr          <= ref_policy_end(
                    fw_awaddr, fw_awlen, fw_awsize, fw_awburst);
                f_policy_req_seen          <= 1'b0;
                f_policy_rsp_seen          <= 1'b0;
                f_policy_effective_allow   <= 1'b0;
                f_policy_timed_out         <= 1'b0;
                f_policy_timeout_after_req <= 1'b0;
                f_policy_cancel_seen       <= 1'b0;
                f_policy_axi_complete_seen <= 1'b0;
            end
            else if (fw_s_ar_hs) begin
                f_policy_active            <= 1'b1;
                f_policy_is_write          <= 1'b0;
                f_policy_legal             <= ref_burst_legal(
                    fw_araddr, fw_arlen, fw_arsize, fw_arburst);
                f_policy_manager_id         <=
                    fw_aruser[AXI_USER_W-1 -: MANAGER_ID_W];
                f_policy_subordinate_id       <=
                    fw_aruser[SUBORDINATE_ID_W-1:0];
                f_policy_start_addr        <= ref_policy_start(
                    fw_araddr, fw_arlen, fw_arsize, fw_arburst);
                f_policy_end_addr          <= ref_policy_end(
                    fw_araddr, fw_arlen, fw_arsize, fw_arburst);
                f_policy_req_seen          <= 1'b0;
                f_policy_rsp_seen          <= 1'b0;
                f_policy_effective_allow   <= 1'b0;
                f_policy_timed_out         <= 1'b0;
                f_policy_timeout_after_req <= 1'b0;
                f_policy_cancel_seen       <= 1'b0;
                f_policy_axi_complete_seen <= 1'b0;
            end

            if (policy_req_hs)
                f_policy_req_seen <= 1'b1;
            if (policy_rsp_hs) begin
                f_policy_rsp_seen        <= 1'b1;
                f_policy_effective_allow <= policy_rsp_effective_allow;
            end
            else if (policy_timeout_fire) begin
                f_policy_timed_out <= 1'b1;
                f_policy_timeout_after_req <=
                    f_policy_req_seen || policy_req_hs;
            end
            if (policy_cancel_hs)
                f_policy_cancel_seen <= 1'b1;
        end
    end

    // Independent inclusive policy-resolution timer begins on address acceptance
    // and gives a valid final-cycle response precedence over timeout.
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            f_policy_timer_active  <= 1'b0;
            f_policy_timeout_count <= '0;
        end
        else if (policy_axi_complete_hs || policy_rsp_hs ||
                 policy_timeout_fire) begin
            f_policy_timer_active  <= 1'b0;
            f_policy_timeout_count <= '0;
        end
        else if (policy_addr_hs && POLICY_TIMEOUT_ENABLE &&
                 (POLICY_TIMEOUT_CYCLES > 1)) begin
            f_policy_timer_active  <= 1'b1;
            f_policy_timeout_count <= POLICY_TIMEOUT_COUNT_ONE;
        end
        else if (f_policy_timer_active) begin
            f_policy_timeout_count <= f_policy_timeout_count +
                                      POLICY_TIMEOUT_COUNT_ONE;
        end
    end

    // Write-route ledger tracks the captured ID, implemented decode, and
    // accepted firewall-side W beats until upstream B completion.
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            f_wr_route_valid       <= 1'b0;
            f_wr_route_implemented <= 1'b0;
            f_wr_route_onehot      <= '0;
            f_wr_route_subordinate_id <= '0;
            f_wr_route_id          <= '0;
            f_fw_w_expected        <= '0;
            f_fw_w_count           <= '0;
        end
        else if (fw_s_b_hs) begin
            f_wr_route_valid       <= 1'b0;
            f_wr_route_implemented <= 1'b0;
            f_wr_route_onehot      <= '0;
            f_wr_route_subordinate_id <= '0;
            f_wr_route_id          <= '0;
            f_fw_w_expected        <= '0;
            f_fw_w_count           <= '0;
        end
        else begin
            if (fw_m_aw_hs) begin
                f_wr_route_valid       <= 1'b1;
                f_wr_route_onehot      <= ref_subordinate_decode(
                    fw_m_awuser[SUBORDINATE_ID_W-1:0]);
                f_wr_route_implemented <= ref_subordinate_implemented(
                    fw_m_awuser[SUBORDINATE_ID_W-1:0]);
                f_wr_route_subordinate_id <=
                    fw_m_awuser[SUBORDINATE_ID_W-1:0];
                f_wr_route_id          <= fw_m_awid;
                f_fw_w_expected        <= {1'b0, fw_m_awlen} + 9'd1;
            end
            if (fw_m_w_hs)
                f_fw_w_count <= f_fw_w_count + 9'd1;
        end
    end

    // Read-route ledger tracks the captured ID, implemented decode, and
    // accepted firewall-side R beats until final upstream read completion.
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            f_rd_route_valid       <= 1'b0;
            f_rd_route_implemented <= 1'b0;
            f_rd_route_onehot      <= '0;
            f_rd_route_subordinate_id <= '0;
            f_rd_route_id          <= '0;
            f_fw_r_expected        <= '0;
            f_fw_r_count           <= '0;
        end
        else if (fw_s_r_hs && fw_rlast) begin
            f_rd_route_valid       <= 1'b0;
            f_rd_route_implemented <= 1'b0;
            f_rd_route_onehot      <= '0;
            f_rd_route_subordinate_id <= '0;
            f_rd_route_id          <= '0;
            f_fw_r_expected        <= '0;
            f_fw_r_count           <= '0;
        end
        else begin
            if (fw_m_ar_hs) begin
                f_rd_route_valid       <= 1'b1;
                f_rd_route_onehot      <= ref_subordinate_decode(
                    fw_m_aruser[SUBORDINATE_ID_W-1:0]);
                f_rd_route_implemented <= ref_subordinate_implemented(
                    fw_m_aruser[SUBORDINATE_ID_W-1:0]);
                f_rd_route_subordinate_id <=
                    fw_m_aruser[SUBORDINATE_ID_W-1:0];
                f_rd_route_id          <= fw_m_arid;
                f_fw_r_expected        <= {1'b0, fw_m_arlen} + 9'd1;
            end
            if (fw_m_r_hs)
                f_fw_r_count <= f_fw_r_count + 9'd1;
        end
    end

    // Per-subordinate peer ledgers independently establish response causality
    // from observed physical-port AW/W/B and AR/R handshakes.
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            f_res_write_active <= '0;
            f_res_awid         <= '0;
            f_res_w_expected   <= '0;
            f_res_w_count      <= '0;
            f_res_read_active  <= '0;
            f_res_arid         <= '0;
            f_res_r_expected   <= '0;
            f_res_r_count      <= '0;
        end
        else begin
            for (int r = 0; r < NUM_SUBORDINATES; r++) begin
                if (m_aw_hs[r]) begin
                    f_res_write_active[r] <= 1'b1;
                    f_res_awid[r]         <= m_axi_awid[r];
                    f_res_w_expected[r]   <=
                        {1'b0, m_axi_awlen[r]} + 9'd1;
                    f_res_w_count[r]      <= '0;
                end
                if (m_w_hs[r])
                    f_res_w_count[r] <= f_res_w_count[r] + 9'd1;
                if (m_b_hs[r]) begin
                    f_res_write_active[r] <= 1'b0;
                    f_res_awid[r]         <= '0;
                    f_res_w_expected[r]   <= '0;
                    f_res_w_count[r]      <= '0;
                end

                if (m_ar_hs[r]) begin
                    f_res_read_active[r] <= 1'b1;
                    f_res_arid[r]        <= m_axi_arid[r];
                    f_res_r_expected[r]  <=
                        {1'b0, m_axi_arlen[r]} + 9'd1;
                    f_res_r_count[r]     <= '0;
                end
                if (m_r_hs[r]) begin
                    if (m_axi_rlast[r]) begin
                        f_res_read_active[r] <= 1'b0;
                        f_res_arid[r]        <= '0;
                        f_res_r_expected[r]  <= '0;
                        f_res_r_count[r]     <= '0;
                    end
                    else begin
                        f_res_r_count[r] <= f_res_r_count[r] + 9'd1;
                    end
                end
            end
        end
    end

endmodule

// Component checkers are already type-bound in arbiter_fp_rtl.sv and
// axi_firewall.sv. This is the only additional integration-checker bind.
bind arbiter_firewall_top arbiter_firewall_top_sva #(
    .NUM_MANAGERS            (NUM_MANAGERS),
    .NUM_SUBORDINATES          (NUM_SUBORDINATES),
    .AXI_ID_W               (AXI_ID_W),
    .AXI_ADDR_W             (AXI_ADDR_W),
    .AXI_DATA_W             (AXI_DATA_W),
    .AXI_STRB_W             (AXI_STRB_W),
    .MANAGER_ID_W            (MANAGER_ID_W),
    .SUBORDINATE_ID_W          (SUBORDINATE_ID_W),
    .AXI_USER_W             (AXI_USER_W),
    .MANAGER_IDX_W           (MANAGER_IDX_W),
    .SUBORDINATE_IDX_W         (SUBORDINATE_IDX_W),
    .POLICY_TIMEOUT_ENABLE  (POLICY_TIMEOUT_ENABLE),
    .POLICY_TIMEOUT_CYCLES  (POLICY_TIMEOUT_CYCLES),
    .MANAGER_ID_MAP          (MANAGER_ID_MAP),
    .SUBORDINATE_ID_MAP        (SUBORDINATE_ID_MAP)
) u_arbiter_firewall_top_sva (.*);


