// =============================================================================
// File   : axi_firewall_sva.sv
// Module : axi_firewall_sva
// Role   : Interface-based formal checker for the transaction-level AXI4 firewall.
//
// Reference ledgers track externally observed handshakes, payloads, and beat
// counts rather than duplicating the RTL control state. Integrated mode makes
// internal AXI4 peer contracts assertions; three external policy contracts
// remain assumptions here. The top-level checker supplies the reported
// manager/subordinate environmental assumptions.
//
// Standalone-only assumptions/covers and one-/two-cycle timeout covers remain
// in this source, but do not elaborate in the reported integrated 32-cycle run.
// Property comments reproduce the approved assertion, assumption, and cover
// catalogs; source labels and SVA expressions are not renamed or rewritten.
// =============================================================================

`timescale 1ns / 1ps

// Black-box formal contract for axi_firewall.
//
// The reference state below is an interface scoreboard: it records accepted
// transactions, beat counts, and one-entry channel ledgers. It deliberately
// does not mirror the RTL control registers or FSM.
//
// System-level contracts outside this checker include trusted sourcing of
// MANAGER_ID, protocol-correct WSTRB lane use, zero-WSTRB side-effect freedom,
// and reset flushing of outstanding subordinate responses plus every policy
// request, response, cancellation, and quarantine record.
// A revocation before the policy-response handshake is ignored. One sampled
// with a legal Allow response vetoes initial authorization; a later revocation
// must identify the one currently authorized transaction.
// Timeout cycle one is the AW/AR acceptance edge. A response handshake on the
// final permitted edge wins; otherwise the transaction is locally denied. An
// accepted timed-out request remains quarantined until cancellation retires its
// untagged response slot.
// Progress/fairness is intentionally not assumed in this safety proof.

module axi_firewall_sva #(
    parameter int AXI_ID_W       = 4,
    parameter int AXI_ADDR_W     = 32,
    parameter int AXI_DATA_W     = 32,
    parameter int AXI_STRB_W     = AXI_DATA_W / 8,
    parameter int MANAGER_ID_W    = 4,
    parameter int SUBORDINATE_ID_W  = 8,
    parameter int AXI_USER_W     = MANAGER_ID_W + SUBORDINATE_ID_W,
    parameter bit POLICY_TIMEOUT_ENABLE = 1'b1,
    parameter int unsigned POLICY_TIMEOUT_CYCLES = 32,
    parameter bit SVA_INTEGRATION_MODE = 1'b0
) (
    input logic                    clk,
    input logic                    rst_n,

    input logic                    policy_req_valid,
    input logic                    policy_req_ready,
    input logic [MANAGER_ID_W-1:0]  policy_req_manager_id,
    input logic [SUBORDINATE_ID_W-1:0] policy_req_subordinate_id,
    input logic                    policy_req_is_write,
    input logic [AXI_ADDR_W-1:0]   policy_req_start_addr,
    input logic [AXI_ADDR_W-1:0]   policy_req_end_addr,

    input logic                    policy_rsp_valid,
    input logic                    policy_rsp_ready,
    input logic                    policy_rsp_allow,

    // A cancel handshake is the responder's permanent-retirement contract for
    // the sole accepted request and every response associated with it.
    input logic                    policy_cancel_valid,
    input logic                    policy_cancel_ready,

    input logic                    policy_revoke_valid,

    input logic [AXI_ID_W-1:0]     s_axi_awid,
    input logic [AXI_ADDR_W-1:0]   s_axi_awaddr,
    input logic [7:0]              s_axi_awlen,
    input logic [2:0]              s_axi_awsize,
    input logic [1:0]              s_axi_awburst,
    input logic [AXI_USER_W-1:0]   s_axi_awuser,
    input logic                    s_axi_awvalid,
    input logic                    s_axi_awready,

    input logic [AXI_DATA_W-1:0]   s_axi_wdata,
    input logic [AXI_STRB_W-1:0]   s_axi_wstrb,
    input logic                    s_axi_wlast,
    input logic                    s_axi_wvalid,
    input logic                    s_axi_wready,

    input logic [AXI_ID_W-1:0]     s_axi_bid,
    input logic [1:0]              s_axi_bresp,
    input logic                    s_axi_bvalid,
    input logic                    s_axi_bready,

    input logic [AXI_ID_W-1:0]     m_axi_awid,
    input logic [AXI_ADDR_W-1:0]   m_axi_awaddr,
    input logic [7:0]              m_axi_awlen,
    input logic [2:0]              m_axi_awsize,
    input logic [1:0]              m_axi_awburst,
    input logic [AXI_USER_W-1:0]   m_axi_awuser,
    input logic                    m_axi_awvalid,
    input logic                    m_axi_awready,

    input logic [AXI_DATA_W-1:0]   m_axi_wdata,
    input logic [AXI_STRB_W-1:0]   m_axi_wstrb,
    input logic                    m_axi_wlast,
    input logic                    m_axi_wvalid,
    input logic                    m_axi_wready,

    input logic [AXI_ID_W-1:0]     m_axi_bid,
    input logic [1:0]              m_axi_bresp,
    input logic                    m_axi_bvalid,
    input logic                    m_axi_bready,

    input logic [AXI_ID_W-1:0]     s_axi_arid,
    input logic [AXI_ADDR_W-1:0]   s_axi_araddr,
    input logic [7:0]              s_axi_arlen,
    input logic [2:0]              s_axi_arsize,
    input logic [1:0]              s_axi_arburst,
    input logic [AXI_USER_W-1:0]   s_axi_aruser,
    input logic                    s_axi_arvalid,
    input logic                    s_axi_arready,

    input logic [AXI_ID_W-1:0]     m_axi_arid,
    input logic [AXI_ADDR_W-1:0]   m_axi_araddr,
    input logic [7:0]              m_axi_arlen,
    input logic [2:0]              m_axi_arsize,
    input logic [1:0]              m_axi_arburst,
    input logic [AXI_USER_W-1:0]   m_axi_aruser,
    input logic                    m_axi_arvalid,
    input logic                    m_axi_arready,

    input logic [AXI_ID_W-1:0]     m_axi_rid,
    input logic [AXI_DATA_W-1:0]   m_axi_rdata,
    input logic [1:0]              m_axi_rresp,
    input logic                    m_axi_rlast,
    input logic                    m_axi_rvalid,
    input logic                    m_axi_rready,

    input logic [AXI_ID_W-1:0]     s_axi_rid,
    input logic [AXI_DATA_W-1:0]   s_axi_rdata,
    input logic [1:0]              s_axi_rresp,
    input logic                    s_axi_rlast,
    input logic                    s_axi_rvalid,
    input logic                    s_axi_rready
);

    localparam logic [1:0] AXI_RESP_DECERR = 2'b11;
    localparam int RANGE_W = AXI_ADDR_W + 16;
    localparam int POLICY_TIMEOUT_CNT_W =
        (POLICY_TIMEOUT_CYCLES <= 1) ? 1 :
        $clog2(POLICY_TIMEOUT_CYCLES);
    localparam logic [POLICY_TIMEOUT_CNT_W-1:0]
        POLICY_TIMEOUT_COUNT_ONE = 1;
    localparam logic [POLICY_TIMEOUT_CNT_W-1:0]
        POLICY_TIMEOUT_LAST_COUNT =
            (POLICY_TIMEOUT_CYCLES > 0) ?
            (POLICY_TIMEOUT_CYCLES - 1) : '0;

    default clocking cb @(posedge clk); endclocking
    default disable iff (!rst_n);

    wire s_aw_hs = s_axi_awvalid && s_axi_awready;
    wire s_w_hs  = s_axi_wvalid  && s_axi_wready;
    wire s_b_hs  = s_axi_bvalid  && s_axi_bready;
    wire m_aw_hs = m_axi_awvalid && m_axi_awready;
    wire m_w_hs  = m_axi_wvalid  && m_axi_wready;
    wire m_b_hs  = m_axi_bvalid  && m_axi_bready;
    wire s_ar_hs = s_axi_arvalid && s_axi_arready;
    wire m_ar_hs = m_axi_arvalid && m_axi_arready;
    wire m_r_hs  = m_axi_rvalid  && m_axi_rready;
    wire s_r_hs  = s_axi_rvalid  && s_axi_rready;
    wire policy_req_hs = policy_req_valid && policy_req_ready;
    wire policy_rsp_hs = policy_rsp_valid && policy_rsp_ready;
    wire policy_cancel_hs = policy_cancel_valid && policy_cancel_ready;
    wire policy_addr_hs = s_aw_hs || s_ar_hs;
    wire policy_txn_complete_hs = s_b_hs || (s_r_hs && s_axi_rlast);

    // Independent address-footprint helpers for FIXED, INCR, and WRAP;
    // illegal encodings produce the reference invalid policy-range sentinel.
    function automatic logic [AXI_ADDR_W-1:0] ref_burst_start(
        input logic [AXI_ADDR_W-1:0] addr,
        input logic [7:0]            len,
        input logic [2:0]            size,
        input logic [1:0]            burst
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
        input logic [7:0]            len,
        input logic [2:0]            size,
        input logic [1:0]            burst
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
        input logic [7:0]            len,
        input logic [2:0]            size,
        input logic [1:0]            burst
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

            if (beat > AXI_STRB_W)
                ref_burst_legal = 1'b0;

            case (burst)
                2'b00: begin
                    last_x = aligned_addr + beat - 1'b1;
                    if (len > 8'd15)
                        ref_burst_legal = 1'b0;
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
        input logic [7:0]            len,
        input logic [2:0]            size,
        input logic [1:0]            burst
    );
        begin
            ref_policy_start = ref_burst_legal(addr, len, size, burst) ?
                               ref_burst_start(addr, len, size, burst) : '0;
        end
    endfunction

    function automatic logic [AXI_ADDR_W-1:0] ref_policy_end(
        input logic [AXI_ADDR_W-1:0] addr,
        input logic [7:0]            len,
        input logic [2:0]            size,
        input logic [1:0]            burst
    );
        begin
            ref_policy_end = ref_burst_legal(addr, len, size, burst) ?
                             ref_burst_end(addr, len, size, burst) :
                             {AXI_ADDR_W{1'b1}};
        end
    endfunction

    // ------------------------------------------------------------------
    // The policy generation and retirement history prevents reuse of an
    // accepted timed-out untagged request until its cancellation retires.
    // Interface-derived policy transaction ledger
    // ------------------------------------------------------------------
    logic                         f_policy_active;
    logic                         f_policy_req_seen;
    logic                         f_policy_rsp_seen;
    logic                         f_policy_raw_allow;
    logic                         f_policy_initial_revoke;
    logic                         f_policy_timed_out;
    logic                         f_policy_timeout_after_req;
    logic                         f_policy_cancel_seen;
    logic                         f_policy_axi_complete_seen;
    logic                         f_policy_timer_active;
    logic [POLICY_TIMEOUT_CNT_W-1:0] f_policy_timeout_count;
    logic                         f_policy_is_write;
    logic                         f_policy_legal;
    logic [MANAGER_ID_W-1:0]       f_policy_manager_id;
    logic [SUBORDINATE_ID_W-1:0]     f_policy_subordinate_id;
    logic [AXI_ADDR_W-1:0]        f_policy_start_addr;
    logic [AXI_ADDR_W-1:0]        f_policy_end_addr;
    logic [1:0]                   f_policy_req_count;
    logic [1:0]                   f_policy_rsp_count;
    logic [1:0]                   f_policy_timeout_event_count;
    logic [1:0]                   f_policy_cancel_count;
    logic [1:0]                   f_policy_resolution_count;

    logic                         f_history_valid;
    logic [MANAGER_ID_W-1:0]       f_history_manager_id;
    logic [SUBORDINATE_ID_W-1:0]     f_history_subordinate_id;
    logic                         f_history_is_write;
    logic                         f_retired_history_valid;
    logic                         f_retired_history_timed_out;
    logic                         f_retired_history_timeout_after_req;
    logic [1:0]                   f_retired_history_req_count;
    logic [1:0]                   f_retired_history_rsp_count;
    logic [1:0]                   f_retired_history_timeout_count;
    logic [1:0]                   f_retired_history_cancel_count;
    logic [1:0]                   f_retired_history_resolution_count;
    logic                         f_policy_generation_retired;

    // ------------------------------------------------------------------
    // Counts and payload snapshots model W-before-AW, downstream forwarding,
    // and draining denied writes without reproducing the RTL FSM.
    // Interface-derived write transaction and one-entry W ledger
    // ------------------------------------------------------------------
    logic                    f_write_owner;
    logic                    f_aw_seen;
    logic                    f_aw_decision_seen;
    logic                    f_aw_allowed;
    logic                    f_aw_legal;
    logic                    f_write_revoked;
    logic [AXI_ID_W-1:0]     f_awid;
    logic [AXI_ADDR_W-1:0]   f_awaddr;
    logic [7:0]              f_awlen;
    logic [2:0]              f_awsize;
    logic [1:0]              f_awburst;
    logic [AXI_USER_W-1:0]   f_awuser;
    logic [8:0]              f_w_expected;
    logic [8:0]              f_s_w_count;
    logic [8:0]              f_m_w_count;
    logic                    f_s_wlast_seen;
    logic                    f_m_aw_seen;
    logic                    f_m_b_captured;
    logic [1:0]              f_expected_bresp;
    logic                    f_w_pending;
    logic [AXI_DATA_W-1:0]   f_w_data;
    logic [AXI_STRB_W-1:0]   f_w_strb;
    logic                    f_w_last;

    // ------------------------------------------------------------------
    // Separate accepted/downstream/upstream beat ledgers cover read framing
    // and preservation of a stalled upstream response during revocation.
    // Interface-derived read transaction ledger and one-entry R ledger
    // ------------------------------------------------------------------
    logic                    f_read_owner;
    logic                    f_ar_seen;
    logic                    f_ar_decision_seen;
    logic                    f_ar_allowed;
    logic                    f_ar_legal;
    logic                    f_read_revoked;
    logic [AXI_ID_W-1:0]     f_arid;
    logic [AXI_ADDR_W-1:0]   f_araddr;
    logic [7:0]              f_arlen;
    logic [2:0]              f_arsize;
    logic [1:0]              f_arburst;
    logic [AXI_USER_W-1:0]   f_aruser;
    logic [8:0]              f_r_expected;
    logic [8:0]              f_m_r_count;
    logic [8:0]              f_s_r_count;
    logic                    f_m_ar_seen;
    logic                    f_r_fifo_valid;
    logic [AXI_ID_W-1:0]     f_r_fifo_id;
    logic [AXI_DATA_W-1:0]   f_r_fifo_data;
    logic [1:0]              f_r_fifo_resp;
    logic                    f_r_fifo_last;

    wire policy_rsp_effective_allow = policy_rsp_allow &&
                                      f_policy_legal &&
                                      !policy_revoke_valid;
    wire policy_initial_revoke_hs = policy_rsp_hs &&
                                    policy_rsp_allow &&
                                    f_policy_legal &&
                                    policy_revoke_valid;
    wire policy_timeout_final_cycle = POLICY_TIMEOUT_ENABLE &&
        ((policy_addr_hs && (POLICY_TIMEOUT_CYCLES == 1)) ||
         (f_policy_timer_active &&
          (f_policy_timeout_count == POLICY_TIMEOUT_LAST_COUNT)));
    wire policy_timeout_fire = policy_timeout_final_cycle &&
                               !policy_rsp_hs;
    wire policy_timeout_is_write = f_policy_timer_active ?
                                   f_policy_is_write : s_aw_hs;
    wire policy_timeout_request_accepted =
        f_policy_req_seen || policy_req_hs;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            f_policy_active      <= 1'b0;
            f_policy_req_seen    <= 1'b0;
            f_policy_rsp_seen    <= 1'b0;
            f_policy_raw_allow   <= 1'b0;
            f_policy_initial_revoke <= 1'b0;
            f_policy_timed_out   <= 1'b0;
            f_policy_timeout_after_req <= 1'b0;
            f_policy_cancel_seen <= 1'b0;
            f_policy_axi_complete_seen <= 1'b0;
            f_policy_is_write    <= 1'b0;
            f_policy_legal       <= 1'b0;
            f_policy_manager_id   <= '0;
            f_policy_subordinate_id <= '0;
            f_policy_start_addr  <= '0;
            f_policy_end_addr    <= '0;
            f_policy_req_count   <= '0;
            f_policy_rsp_count   <= '0;
            f_policy_timeout_event_count <= '0;
            f_policy_cancel_count <= '0;
            f_policy_resolution_count <= '0;
            f_history_valid      <= 1'b0;
            f_history_manager_id  <= '0;
            f_history_subordinate_id <= '0;
            f_history_is_write   <= 1'b0;
            f_retired_history_valid <= 1'b0;
            f_retired_history_timed_out <= 1'b0;
            f_retired_history_timeout_after_req <= 1'b0;
            f_retired_history_req_count <= '0;
            f_retired_history_rsp_count <= '0;
            f_retired_history_timeout_count <= '0;
            f_retired_history_cancel_count <= '0;
            f_retired_history_resolution_count <= '0;
        end
        else if ((policy_txn_complete_hs &&
                  (!f_policy_timeout_after_req ||
                   f_policy_cancel_seen || policy_cancel_hs)) ||
                 (policy_cancel_hs && f_policy_axi_complete_seen)) begin
            if (policy_txn_complete_hs) begin
                f_history_valid       <= f_policy_active;
                f_history_manager_id   <= f_policy_manager_id;
                f_history_subordinate_id <= f_policy_subordinate_id;
                f_history_is_write    <= f_policy_is_write;
            end
            f_retired_history_valid <= f_policy_active;
            f_retired_history_timed_out <= f_policy_timed_out;
            f_retired_history_timeout_after_req <=
                f_policy_timeout_after_req;
            f_retired_history_req_count <= f_policy_req_count;
            f_retired_history_rsp_count <= f_policy_rsp_count;
            f_retired_history_timeout_count <=
                f_policy_timeout_event_count;
            f_retired_history_cancel_count <= f_policy_cancel_count +
                (policy_cancel_hs ? 2'd1 : 2'd0);
            f_retired_history_resolution_count <=
                f_policy_resolution_count;
            f_policy_active      <= 1'b0;
            f_policy_req_seen    <= 1'b0;
            f_policy_rsp_seen    <= 1'b0;
            f_policy_raw_allow   <= 1'b0;
            f_policy_initial_revoke <= 1'b0;
            f_policy_timed_out   <= 1'b0;
            f_policy_timeout_after_req <= 1'b0;
            f_policy_cancel_seen <= 1'b0;
            f_policy_axi_complete_seen <= 1'b0;
            f_policy_is_write    <= 1'b0;
            f_policy_legal       <= 1'b0;
            f_policy_manager_id   <= '0;
            f_policy_subordinate_id <= '0;
            f_policy_start_addr  <= '0;
            f_policy_end_addr    <= '0;
            f_policy_req_count   <= '0;
            f_policy_rsp_count   <= '0;
            f_policy_timeout_event_count <= '0;
            f_policy_cancel_count <= '0;
            f_policy_resolution_count <= '0;
        end
        else begin
            if (policy_txn_complete_hs) begin
                f_history_valid       <= f_policy_active;
                f_history_manager_id   <= f_policy_manager_id;
                f_history_subordinate_id <= f_policy_subordinate_id;
                f_history_is_write    <= f_policy_is_write;
                f_policy_axi_complete_seen <= 1'b1;
            end

            if (s_aw_hs) begin
                f_policy_active      <= 1'b1;
                f_policy_req_seen    <= 1'b0;
                f_policy_rsp_seen    <= 1'b0;
                f_policy_raw_allow   <= 1'b0;
                f_policy_initial_revoke <= 1'b0;
                f_policy_timed_out   <= 1'b0;
                f_policy_timeout_after_req <= 1'b0;
                f_policy_cancel_seen <= 1'b0;
                f_policy_axi_complete_seen <= 1'b0;
                f_policy_is_write    <= 1'b1;
                f_policy_legal       <= ref_burst_legal(
                                         s_axi_awaddr, s_axi_awlen,
                                         s_axi_awsize, s_axi_awburst);
                f_policy_manager_id   <=
                    s_axi_awuser[AXI_USER_W-1 -: MANAGER_ID_W];
                f_policy_subordinate_id <=
                    s_axi_awuser[SUBORDINATE_ID_W-1:0];
                f_policy_start_addr  <= ref_policy_start(
                                         s_axi_awaddr, s_axi_awlen,
                                         s_axi_awsize, s_axi_awburst);
                f_policy_end_addr    <= ref_policy_end(
                                         s_axi_awaddr, s_axi_awlen,
                                         s_axi_awsize, s_axi_awburst);
                f_policy_req_count   <= '0;
                f_policy_rsp_count   <= '0;
                f_policy_timeout_event_count <= '0;
                f_policy_cancel_count <= '0;
                f_policy_resolution_count <= '0;
            end
            else if (s_ar_hs) begin
                f_policy_active      <= 1'b1;
                f_policy_req_seen    <= 1'b0;
                f_policy_rsp_seen    <= 1'b0;
                f_policy_raw_allow   <= 1'b0;
                f_policy_initial_revoke <= 1'b0;
                f_policy_timed_out   <= 1'b0;
                f_policy_timeout_after_req <= 1'b0;
                f_policy_cancel_seen <= 1'b0;
                f_policy_axi_complete_seen <= 1'b0;
                f_policy_is_write    <= 1'b0;
                f_policy_legal       <= ref_burst_legal(
                                         s_axi_araddr, s_axi_arlen,
                                         s_axi_arsize, s_axi_arburst);
                f_policy_manager_id   <=
                    s_axi_aruser[AXI_USER_W-1 -: MANAGER_ID_W];
                f_policy_subordinate_id <=
                    s_axi_aruser[SUBORDINATE_ID_W-1:0];
                f_policy_start_addr  <= ref_policy_start(
                                         s_axi_araddr, s_axi_arlen,
                                         s_axi_arsize, s_axi_arburst);
                f_policy_end_addr    <= ref_policy_end(
                                         s_axi_araddr, s_axi_arlen,
                                         s_axi_arsize, s_axi_arburst);
                f_policy_req_count   <= '0;
                f_policy_rsp_count   <= '0;
                f_policy_timeout_event_count <= '0;
                f_policy_cancel_count <= '0;
                f_policy_resolution_count <= '0;
            end

            if (policy_req_hs) begin
                f_policy_req_seen  <= 1'b1;
                f_policy_req_count <= f_policy_req_count + 2'd1;
            end

            if (policy_rsp_hs) begin
                f_policy_rsp_seen  <= 1'b1;
                f_policy_raw_allow <= policy_rsp_allow;
                f_policy_initial_revoke <= policy_rsp_allow &&
                                           f_policy_legal &&
                                           policy_revoke_valid;
                f_policy_rsp_count <= f_policy_rsp_count + 2'd1;
                f_policy_resolution_count <=
                    f_policy_resolution_count + 2'd1;
            end
            else if (policy_timeout_fire) begin
                f_policy_timed_out <= 1'b1;
                f_policy_timeout_after_req <=
                    policy_timeout_request_accepted;
                f_policy_timeout_event_count <=
                    f_policy_timeout_event_count + 2'd1;
                f_policy_resolution_count <=
                    f_policy_resolution_count + 2'd1;
            end

            if (policy_cancel_hs) begin
                f_policy_cancel_seen <= 1'b1;
                f_policy_cancel_count <= f_policy_cancel_count + 2'd1;
            end
        end
    end

    // Environment-protocol epoch fence. Cancellation acknowledgement closes
    // the old untagged generation permanently; the fence remains until the
    // firewall actually transfers a later request.
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            f_policy_generation_retired <= 1'b0;
        else if (policy_cancel_hs)
            f_policy_generation_retired <= 1'b1;
        else if (policy_req_hs)
            f_policy_generation_retired <= 1'b0;
    end

    // Interface-derived reference timer. It starts only on AW/AR acceptance,
    // never on W alone, and stops on response, timeout, or transaction clear.
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            f_policy_timer_active  <= 1'b0;
            f_policy_timeout_count <= '0;
        end
        else if (policy_txn_complete_hs || policy_rsp_hs ||
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

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            f_write_owner     <= 1'b0;
            f_aw_seen         <= 1'b0;
            f_aw_decision_seen <= 1'b0;
            f_aw_allowed      <= 1'b0;
            f_aw_legal        <= 1'b0;
            f_write_revoked   <= 1'b0;
            f_awid            <= '0;
            f_awaddr          <= '0;
            f_awlen           <= '0;
            f_awsize          <= '0;
            f_awburst         <= '0;
            f_awuser          <= '0;
            f_w_expected      <= '0;
            f_s_w_count       <= '0;
            f_m_w_count       <= '0;
            f_s_wlast_seen    <= 1'b0;
            f_m_aw_seen       <= 1'b0;
            f_m_b_captured    <= 1'b0;
            f_expected_bresp  <= '0;
            f_w_pending       <= 1'b0;
            f_w_data          <= '0;
            f_w_strb          <= '0;
            f_w_last          <= 1'b0;
        end
        else if (s_b_hs) begin
            f_write_owner     <= 1'b0;
            f_aw_seen         <= 1'b0;
            f_aw_decision_seen <= 1'b0;
            f_aw_allowed      <= 1'b0;
            f_aw_legal        <= 1'b0;
            f_write_revoked   <= 1'b0;
            f_awid            <= '0;
            f_awaddr          <= '0;
            f_awlen           <= '0;
            f_awsize          <= '0;
            f_awburst         <= '0;
            f_awuser          <= '0;
            f_w_expected      <= '0;
            f_s_w_count       <= '0;
            f_m_w_count       <= '0;
            f_s_wlast_seen    <= 1'b0;
            f_m_aw_seen       <= 1'b0;
            f_m_b_captured    <= 1'b0;
            f_expected_bresp  <= '0;
            f_w_pending       <= 1'b0;
            f_w_data          <= '0;
            f_w_strb          <= '0;
            f_w_last          <= 1'b0;
        end
        else begin
            if (!f_write_owner && !f_read_owner && (s_aw_hs || s_w_hs))
                f_write_owner <= 1'b1;

            if (s_aw_hs) begin
                f_write_owner      <= 1'b1;
                f_aw_seen          <= 1'b1;
                f_aw_decision_seen <= 1'b0;
                f_aw_allowed       <= 1'b0;
                f_aw_legal         <= ref_burst_legal(
                                      s_axi_awaddr, s_axi_awlen,
                                      s_axi_awsize, s_axi_awburst);
                f_write_revoked    <= 1'b0;
                f_awid             <= s_axi_awid;
                f_awaddr           <= s_axi_awaddr;
                f_awlen            <= s_axi_awlen;
                f_awsize           <= s_axi_awsize;
                f_awburst          <= s_axi_awburst;
                f_awuser           <= s_axi_awuser;
                f_w_expected       <= {1'b0, s_axi_awlen} + 9'd1;
            end

            if (s_w_hs) begin
                f_s_w_count <= f_s_w_count + 9'd1;
                if (s_axi_wlast)
                    f_s_wlast_seen <= 1'b1;
                if (!f_aw_seen || !f_aw_decision_seen || f_aw_allowed) begin
                    f_w_pending <= 1'b1;
                    f_w_data    <= s_axi_wdata;
                    f_w_strb    <= s_axi_wstrb;
                    f_w_last    <= s_axi_wlast;
                end
            end

            if (policy_rsp_hs && f_policy_is_write) begin
                f_aw_decision_seen <= 1'b1;
                f_aw_allowed       <= policy_rsp_effective_allow;
                f_write_revoked    <= 1'b0;
                if (!policy_rsp_effective_allow)
                    f_w_pending <= 1'b0;
            end
            else if (policy_timeout_fire && policy_timeout_is_write) begin
                f_aw_decision_seen <= 1'b1;
                f_aw_allowed       <= 1'b0;
                f_write_revoked    <= 1'b0;
                f_w_pending        <= 1'b0;
            end

            if (m_aw_hs)
                f_m_aw_seen <= 1'b1;

            if (m_w_hs) begin
                f_m_w_count <= f_m_w_count + 9'd1;
                f_w_pending <= 1'b0;
            end

            if (f_aw_seen && f_aw_decision_seen && f_aw_allowed &&
                policy_revoke_valid)
                f_write_revoked <= 1'b1;

            if (m_b_hs) begin
                f_m_b_captured   <= 1'b1;
                f_expected_bresp <= (f_write_revoked ||
                                     policy_revoke_valid) ?
                                    AXI_RESP_DECERR : m_axi_bresp;
            end
        end
    end

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            f_read_owner      <= 1'b0;
            f_ar_seen         <= 1'b0;
            f_ar_decision_seen <= 1'b0;
            f_ar_allowed      <= 1'b0;
            f_ar_legal        <= 1'b0;
            f_read_revoked    <= 1'b0;
            f_arid            <= '0;
            f_araddr          <= '0;
            f_arlen           <= '0;
            f_arsize          <= '0;
            f_arburst         <= '0;
            f_aruser          <= '0;
            f_r_expected      <= '0;
            f_m_r_count       <= '0;
            f_s_r_count       <= '0;
            f_m_ar_seen       <= 1'b0;
            f_r_fifo_valid    <= 1'b0;
            f_r_fifo_id       <= '0;
            f_r_fifo_data     <= '0;
            f_r_fifo_resp     <= '0;
            f_r_fifo_last     <= 1'b0;
        end
        else begin
            if (s_ar_hs) begin
                f_read_owner      <= 1'b1;
                f_ar_seen         <= 1'b1;
                f_ar_decision_seen <= 1'b0;
                f_ar_allowed      <= 1'b0;
                f_ar_legal        <= ref_burst_legal(
                                      s_axi_araddr, s_axi_arlen,
                                      s_axi_arsize, s_axi_arburst);
                f_read_revoked    <= 1'b0;
                f_arid            <= s_axi_arid;
                f_araddr          <= s_axi_araddr;
                f_arlen           <= s_axi_arlen;
                f_arsize          <= s_axi_arsize;
                f_arburst         <= s_axi_arburst;
                f_aruser          <= s_axi_aruser;
                f_r_expected      <= {1'b0, s_axi_arlen} + 9'd1;
            end

            if (policy_rsp_hs && !f_policy_is_write) begin
                f_ar_decision_seen <= 1'b1;
                f_ar_allowed       <= policy_rsp_effective_allow;
                f_read_revoked     <= 1'b0;
            end
            else if (policy_timeout_fire && !policy_timeout_is_write) begin
                f_ar_decision_seen <= 1'b1;
                f_ar_allowed       <= 1'b0;
                f_read_revoked     <= 1'b0;
            end

            if (m_ar_hs)
                f_m_ar_seen <= 1'b1;

            if (f_ar_seen && f_ar_decision_seen && f_ar_allowed &&
                policy_revoke_valid)
                f_read_revoked <= 1'b1;

            if (m_r_hs) begin
                f_m_r_count    <= f_m_r_count + 9'd1;
                f_r_fifo_valid <= 1'b1;
                f_r_fifo_id    <= f_arid;
                f_r_fifo_data  <= (f_read_revoked ||
                                   policy_revoke_valid) ?
                                  '0 : m_axi_rdata;
                f_r_fifo_resp  <= (f_read_revoked ||
                                   policy_revoke_valid) ?
                                  AXI_RESP_DECERR : m_axi_rresp;
                f_r_fifo_last  <= ((f_m_r_count + 9'd1) == f_r_expected);
            end

            if (s_r_hs) begin
                f_s_r_count <= f_s_r_count + 9'd1;
                if (f_ar_allowed)
                    f_r_fifo_valid <= 1'b0;
            end

            if (s_r_hs && s_axi_rlast) begin
                f_read_owner      <= 1'b0;
                f_ar_seen         <= 1'b0;
                f_ar_decision_seen <= 1'b0;
                f_ar_allowed      <= 1'b0;
                f_ar_legal        <= 1'b0;
                f_read_revoked    <= 1'b0;
                f_arid            <= '0;
                f_araddr          <= '0;
                f_arlen           <= '0;
                f_arsize          <= '0;
                f_arburst         <= '0;
                f_aruser          <= '0;
                f_r_expected      <= '0;
                f_m_r_count       <= '0;
                f_s_r_count       <= '0;
                f_m_ar_seen       <= 1'b0;
                f_r_fifo_valid    <= 1'b0;
                f_r_fifo_id       <= '0;
                f_r_fifo_data     <= '0;
                f_r_fifo_resp     <= '0;
                f_r_fifo_last     <= 1'b0;
            end
        end
    end

    // ------------------------------------------------------------------
    // Environment assumptions: peer protocol behavior only
    // ------------------------------------------------------------------
    property p_s_aw_stable;
        s_axi_awvalid && !s_axi_awready
        |=> s_axi_awvalid &&
            $stable({s_axi_awid, s_axi_awaddr, s_axi_awlen,
                     s_axi_awsize, s_axi_awburst, s_axi_awuser});
    endproperty

    property p_s_w_stable;
        s_axi_wvalid && !s_axi_wready
        |=> s_axi_wvalid &&
            $stable({s_axi_wdata, s_axi_wstrb, s_axi_wlast});
    endproperty

    property p_s_ar_stable;
        s_axi_arvalid && !s_axi_arready
        |=> s_axi_arvalid &&
            $stable({s_axi_arid, s_axi_araddr, s_axi_arlen,
                     s_axi_arsize, s_axi_arburst, s_axi_aruser});
    endproperty

    property p_m_r_stable;
        m_axi_rvalid && !m_axi_rready
        |=> m_axi_rvalid &&
            $stable({m_axi_rid, m_axi_rdata, m_axi_rresp, m_axi_rlast});
    endproperty

    // WLAST framing, including simultaneous AW/W and W-before-AW.
    property p_wlast_after_aw;
        f_aw_seen && s_w_hs
        |-> (s_axi_wlast == ((f_s_w_count + 9'd1) == f_w_expected));
    endproperty

    property p_wlast_with_aw;
        s_aw_hs && s_w_hs
        |-> (s_axi_wlast ==
             ((f_s_w_count + 9'd1) == ({1'b0, s_axi_awlen} + 9'd1)));
    endproperty

    property p_w_before_aw_framing;
        s_aw_hs && (f_s_w_count != 0)
        |-> (f_s_w_count <= ({1'b0, s_axi_awlen} + 9'd1)) &&
            (f_s_wlast_seen ==
             (f_s_w_count == ({1'b0, s_axi_awlen} + 9'd1)));
    endproperty

    // A downstream slave may respond only to the one request accepted from the
    // firewall, with legal ID and burst framing.
    property p_m_b_causal;
        m_axi_bvalid
        |-> f_aw_seen && f_aw_decision_seen && f_aw_allowed &&
            f_m_aw_seen &&
            (f_m_w_count == f_w_expected) && !f_m_b_captured &&
            (m_axi_bid == f_awid);
    endproperty

    property p_m_r_causal;
        m_axi_rvalid
        |-> f_ar_seen && f_ar_decision_seen && f_ar_allowed &&
            f_m_ar_seen &&
            (f_m_r_count < f_r_expected) &&
            (m_axi_rid == f_arid) &&
            (m_axi_rlast ==
             ((f_m_r_count + 9'd1) == f_r_expected));
    endproperty

    // In a standalone firewall proof these are legal peer-protocol
    // assumptions. In the integrated proof the wrapper and subordinate router are
    // part of the DUT, so the same contracts become proof obligations. This
    // prevents component assumptions from masking integration defects.
    generate
        if (!SVA_INTEGRATION_MODE) begin : g_standalone_axi_contracts
            // Holds AWVALID and the write-address payload stable while the manager is stalled by
            // backpressure.
            asm_s_aw_stable: assume property (p_s_aw_stable);
            // Holds WVALID, WDATA, WSTRB, and WLAST stable while the write-data channel is
            // stalled.
            asm_s_w_stable: assume property (p_s_w_stable);
            // Holds ARVALID and the read-address payload stable while the manager is stalled by
            // backpressure.
            asm_s_ar_stable: assume property (p_s_ar_stable);
            // Holds RVALID and the read-response payload stable while the read response is stalled
            // by backpressure.
            asm_m_r_stable: assume property (p_m_r_stable);
            // Requires WLAST to identify exactly the expected final write-data beat after the
            // corresponding write address has been accepted.
            asm_wlast_after_aw: assume property (p_wlast_after_aw);
            // Requires correct WLAST framing when the write address and a write-data beat are
            // accepted in the same cycle.
            asm_wlast_with_aw: assume property (p_wlast_with_aw);
            // Constrains write-data accepted before the write address so that the buffered beat
            // count and observed WLAST remain consistent with the subsequently accepted AWLEN.
            asm_w_before_aw_framing: assume property (p_w_before_aw_framing);
            // Allows a write response only for an active write after the expected number of
            // write-data beats has been accepted, with BID matching the accepted AWID.
            asm_m_b_causal: assume property (p_m_b_causal);
            // Allows read data only for an active read, requires RID to match the accepted ARID,
            // and requires RLAST only on the expected final beat.
            asm_m_r_causal: assume property (p_m_r_causal);
        end
        else begin : g_integrated_axi_contracts
            // Requires an integrated write address to be captured without stalling.
            ast_int_s_aw_capture_first: assert property (
                !(s_axi_awvalid && !s_axi_awready)
            );
            // Keeps write-data payload stable while the integrated input is backpressured.
            ast_int_s_w_stable: assert property (p_s_w_stable);
            // Requires an integrated read address to be captured without stalling.
            ast_int_s_ar_capture_first: assert property (
                !(s_axi_arvalid && !s_axi_arready)
            );
            //ast_int_m_r_stable: assert property (p_m_r_stable);
            // Checks WLAST against the expected write-beat count after AW acceptance.
            ast_int_wlast_after_aw: assert property (p_wlast_after_aw);
            // Checks WLAST framing when AW and W are accepted together.
            ast_int_wlast_with_aw: assert property (p_wlast_with_aw);
            // Checks that W-before-AW beats are consistent with the later AWLEN.
            ast_int_w_before_aw_framing: assert property (p_w_before_aw_framing);
            // Allows a downstream B response only after the corresponding allowed write completes,
            // with the correct BID.
            ast_int_m_b_causal: assert property (p_m_b_causal);
            //ast_int_m_r_causal: assert property (p_m_r_causal);
        end
    endgenerate

    // The untagged responder may assert VALID on the request-acceptance cycle,
    // but not before it. No latency or eventual-progress constraint is used.
    // Allows a policy response only for the active request after that request has been accepted or
    // on the same cycle in which the request is accepted, and prevents responses after safe
    // retirement.
    asm_policy_rsp_causal: assume property (
        policy_rsp_valid
        |-> f_policy_active &&
            (f_policy_req_seen || policy_req_hs) &&
            !f_policy_rsp_seen &&
            (!f_policy_timed_out ||
             (f_policy_timeout_after_req && !f_policy_cancel_seen))
    );

    // Holds a presented policy response and its Allow decision stable while the response is
    // backpressured, unless cancellation retires the request.
    asm_policy_rsp_stable: assume property (
        policy_rsp_valid && !policy_rsp_ready && !policy_cancel_hs
        |=> policy_rsp_valid && $stable(policy_rsp_allow)
    );

    // Cancellation acknowledgement retires the sole accepted untagged request
    // and permits an already asserted stale response to be withdrawn.
    // Prevents a stale policy response from remaining valid after the timed-out policy generation
    // has been permanently retired.
    asm_policy_cancel_retires_stale_response: assume property (
        f_policy_generation_retired && !policy_req_hs
        |-> !policy_rsp_valid
    );

    // ------------------------------------------------------------------
    // Registered-channel stability
    // ------------------------------------------------------------------
    // Keeps the policy request and all request fields stable while backpressured.
    ast_policy_req_stable: assert property (
        policy_req_valid && !policy_req_ready && !policy_timeout_fire
        |=> policy_req_valid &&
            $stable({policy_req_manager_id, policy_req_subordinate_id,
                     policy_req_is_write, policy_req_start_addr,
                     policy_req_end_addr})
    );

    // Keeps POLICY\_CANCEL\_VALID asserted while cancellation is backpressured.
    ast_policy_cancel_stable: assert property (
        policy_cancel_valid && !policy_cancel_ready
        |=> policy_cancel_valid
    );


    // Keeps forwarded AWVALID and its payload stable under backpressure.
    ast_m_aw_stable: assert property (
        m_axi_awvalid && !m_axi_awready
        |=> m_axi_awvalid &&
            $stable({m_axi_awid, m_axi_awaddr, m_axi_awlen,
                     m_axi_awsize, m_axi_awburst, m_axi_awuser})
    );

    // Keeps forwarded WVALID, WDATA, WSTRB, and WLAST stable under backpressure.
    ast_m_w_stable: assert property (
        m_axi_wvalid && !m_axi_wready
        |=> m_axi_wvalid &&
            $stable({m_axi_wdata, m_axi_wstrb, m_axi_wlast})
    );

    // Keeps the returned B response and BID stable under manager backpressure.
    ast_s_b_stable: assert property (
        s_axi_bvalid && !s_axi_bready
        |=> s_axi_bvalid && $stable({s_axi_bid, s_axi_bresp})
    );

    // Keeps forwarded ARVALID and its payload stable under backpressure.
    ast_m_ar_stable: assert property (
        m_axi_arvalid && !m_axi_arready
        |=> m_axi_arvalid &&
            $stable({m_axi_arid, m_axi_araddr, m_axi_arlen,
                     m_axi_arsize, m_axi_arburst, m_axi_aruser})
    );

    // Keeps the returned R payload stable under manager backpressure.
    ast_s_r_stable: assert property (
        s_axi_rvalid && !s_axi_rready
        |=> s_axi_rvalid &&
            $stable({s_axi_rid, s_axi_rdata,
                     s_axi_rresp, s_axi_rlast})
    );

    // The causal B assumption makes the firewall ready for every legal BVALID,
    // so a separate downstream B stability assumption would be redundant.
    // Requires every legal downstream BVALID to be accepted immediately.
    ast_m_b_immediate_capture: assert property (
        m_axi_bvalid |-> m_axi_bready
    );

    // Exercises capture of a protected-side write response by the firewall.
    cvr_m_b_capture: cover property (m_b_hs);

    // ------------------------------------------------------------------
    // Global policy ownership and arbitration
    // ------------------------------------------------------------------
    // Prevents simultaneous write and read transaction ownership.
    ast_owner_mutex: assert property (!(f_write_owner && f_read_owner));
    // Prevents simultaneous acceptance of write and read addresses.
    ast_no_aw_ar_same_cycle: assert property (!(s_aw_hs && s_ar_hs));
    // Prevents simultaneous acceptance of write data and a read address.
    ast_no_w_ar_same_cycle: assert property (!(s_w_hs && s_ar_hs));

    // Blocks read-channel activity while a write transaction owns the firewall.
    ast_write_blocks_read: assert property (
        f_write_owner |-> !s_axi_arready && !m_axi_arvalid && !m_axi_rready
    );

    // Blocks write-channel activity while a read transaction owns the firewall.
    ast_read_blocks_write: assert property (
        f_read_owner |->
        !s_axi_awready && !s_axi_wready &&
        !m_axi_awvalid && !m_axi_wvalid && !m_axi_bready
    );

    // Prevents acceptance of a second write address while one is active.
    ast_no_second_aw_accept: assert property (
        f_aw_seen |-> !s_axi_awready
    );

    // Prevents acceptance of a second read address while one is active.
    ast_no_second_ar_accept: assert property (
        f_ar_seen |-> !s_axi_arready
    );

    generate
        if (!SVA_INTEGRATION_MODE) begin : g_standalone_write_priority
            // In standalone firewall mode, gives a pending write precedence over a simultaneous
            // read when the firewall is idle.
            ast_write_priority: assert property (
                !f_write_owner && !f_read_owner && s_axi_arvalid &&
                (s_axi_awvalid || s_axi_wvalid)
                |-> !s_axi_arready
            );
        end
    endgenerate

    // ------------------------------------------------------------------
    // Policy request/response protocol, context, and enforcement
    // ------------------------------------------------------------------
    // Checks that AXI USER metadata width exactly accommodates MANAGER\_ID and SUBORDINATE\_ID.
    ast_user_width: assert property (
        AXI_USER_W == (MANAGER_ID_W + SUBORDINATE_ID_W)
    );

    // Requires a positive timeout length whenever policy timeout is enabled.
    ast_policy_timeout_configuration: assert property (
        !POLICY_TIMEOUT_ENABLE || (POLICY_TIMEOUT_CYCLES > 0)
    );

    // When VALID is low, every request payload has a deterministic neutral
    // value. This replaces the old continuously driven live-footprint outputs.
    // Drives neutral policy-request fields whenever POLICY\_REQ\_VALID is low.
    ast_idle_policy_neutral: assert property (
        !policy_req_valid
        |-> policy_req_manager_id == '0 &&
            policy_req_subordinate_id == '0 &&
            !policy_req_is_write &&
            policy_req_start_addr == '0 &&
            policy_req_end_addr == '0
    );

    // Allows a policy request only while one unresolved transaction owns the policy interface.
    ast_policy_req_has_owner: assert property (
        policy_req_valid
        |-> f_policy_active && !f_policy_req_seen &&
            !f_policy_rsp_seen && !f_policy_timed_out
    );

    // Presents a policy request for an unresolved transaction with a captured AW or AR, unless the
    // transaction has timed out.
    ast_policy_req_is_presented: assert property (
        f_policy_active && !f_policy_req_seen && !f_policy_timed_out
        |-> policy_req_valid
    );

    // Allows at most one accepted policy request per transaction.
    ast_one_policy_req: assert property (
        policy_req_hs |-> !f_policy_req_seen &&
                          (f_policy_req_count == 0)
    );

    // Deasserts the policy request after its handshake.
    ast_policy_req_drops_after_handshake: assert property (
        f_policy_req_seen |-> !policy_req_valid
    );

    // Requires the policy request fields to match the captured transaction context.
    ast_policy_req_payload: assert property (
        policy_req_valid
        |-> policy_req_manager_id == f_policy_manager_id &&
            policy_req_subordinate_id == f_policy_subordinate_id &&
            policy_req_is_write == f_policy_is_write &&
            policy_req_start_addr == f_policy_start_addr &&
            policy_req_end_addr == f_policy_end_addr
    );

    // Requires an accepted write address to produce the corresponding write policy address range
    // unless it times out.
    ast_live_write_footprint: assert property (
        s_aw_hs
        |=> f_policy_timed_out ||
            (policy_req_valid && policy_req_is_write &&
             policy_req_manager_id == f_policy_manager_id &&
             policy_req_subordinate_id == f_policy_subordinate_id &&
             policy_req_start_addr == ref_policy_start(
                 f_awaddr, f_awlen, f_awsize, f_awburst) &&
             policy_req_end_addr == ref_policy_end(
                 f_awaddr, f_awlen, f_awsize, f_awburst))
    );

    // Requires an accepted read address to produce the corresponding read policy address range
    // unless it times out.
    ast_live_read_footprint: assert property (
        s_ar_hs
        |=> f_policy_timed_out ||
            (policy_req_valid && !policy_req_is_write &&
             policy_req_manager_id == f_policy_manager_id &&
             policy_req_subordinate_id == f_policy_subordinate_id &&
             policy_req_start_addr == ref_policy_start(
                 f_araddr, f_arlen, f_arsize, f_arburst) &&
             policy_req_end_addr == ref_policy_end(
                 f_araddr, f_arlen, f_arsize, f_arburst))
    );

    // Requires a write policy request to match the captured write address, IDs, and computed
    // address range.
    ast_captured_write_footprint: assert property (
        policy_req_valid && f_policy_is_write
        |-> f_aw_seen &&
            policy_req_manager_id ==
                f_awuser[AXI_USER_W-1 -: MANAGER_ID_W] &&
            policy_req_subordinate_id ==
                f_awuser[SUBORDINATE_ID_W-1:0] &&
            policy_req_start_addr == ref_policy_start(
                f_awaddr, f_awlen, f_awsize, f_awburst) &&
            policy_req_end_addr == ref_policy_end(
                f_awaddr, f_awlen, f_awsize, f_awburst)
    );

    // Prevents policy evaluation before the write address is captured.
    ast_waiting_aw_live_footprint: assert property (
        f_write_owner && !f_aw_seen && s_axi_awvalid
        |-> !policy_req_valid
    );

    // Requires a read policy request to match the captured read address, IDs, and computed address
    // range.
    ast_captured_read_footprint: assert property (
        policy_req_valid && !f_policy_is_write
        |-> f_ar_seen &&
            policy_req_manager_id ==
                f_aruser[AXI_USER_W-1 -: MANAGER_ID_W] &&
            policy_req_subordinate_id ==
                f_aruser[SUBORDINATE_ID_W-1:0] &&
            policy_req_start_addr == ref_policy_start(
                f_araddr, f_arlen, f_arsize, f_arburst) &&
            policy_req_end_addr == ref_policy_end(
                f_araddr, f_arlen, f_arsize, f_arburst)
    );

    // Prevents write data alone from creating a policy request.
    ast_no_policy_req_from_w_alone: assert property (
        f_write_owner && !f_aw_seen |-> !policy_req_valid
    );

    // Asserts policy-response readiness only for an outstanding accepted request.
    ast_policy_rsp_ready_only_when_expected: assert property (
        policy_rsp_ready
        |-> f_policy_active && f_policy_req_seen &&
            !f_policy_rsp_seen && !f_policy_timed_out
    );

    // Prevents acceptance of a policy response before its request has been accepted.
    ast_no_policy_rsp_before_req: assert property (
        policy_rsp_hs |-> f_policy_req_seen &&
                          !f_policy_rsp_seen && !f_policy_timed_out
    );

    // Allows at most one accepted policy response per transaction.
    ast_one_policy_rsp: assert property (
        policy_rsp_hs |-> (f_policy_rsp_count == 0)
    );

    // Registers policy-response readiness after request acceptance unless the transaction times
    // out.
    ast_policy_rsp_registered_ready: assert property (
        policy_req_hs && !policy_timeout_fire
        |=> !policy_rsp_ready ##1
            (policy_rsp_ready || f_policy_timed_out)
    );

    // Keeps policy-response readiness asserted while waiting for a response.
    ast_policy_rsp_ready_sticky: assert property (
        policy_rsp_ready && !policy_rsp_valid && !policy_timeout_fire
        |=> policy_rsp_ready
    );

    // Deasserts policy-response readiness after a response handshake.
    ast_policy_rsp_ready_drops: assert property (
        policy_rsp_hs |=> !policy_rsp_ready
    );

    // Bounds policy request, response, timeout, cancellation, and resolution counts and enforces
    // their consistency.
    ast_policy_count_bounds: assert property (
        f_policy_active
        |-> (f_policy_req_count <= 2'd1) &&
            (f_policy_rsp_count <= 2'd1) &&
            (f_policy_timeout_event_count <= 2'd1) &&
            (f_policy_cancel_count <= 2'd1) &&
            (f_policy_resolution_count <= 2'd1) &&
            (f_policy_rsp_count <= f_policy_req_count) &&
            (f_policy_cancel_count <= f_policy_req_count) &&
            (f_policy_resolution_count ==
             (f_policy_rsp_count + f_policy_timeout_event_count))
    );

    // Requires policy accounting to be balanced when the AXI transaction completes.
    ast_policy_completion_balanced: assert property (
        policy_txn_complete_hs
        |-> f_policy_active &&
            (f_policy_resolution_count == 2'd1) &&
            (((f_policy_req_count == 2'd1) &&
              (f_policy_rsp_count == 2'd1) &&
              (f_policy_timeout_event_count == 2'd0)) ||
             ((f_policy_rsp_count == 2'd0) &&
              (f_policy_timeout_event_count == 2'd1) &&
              (f_policy_req_count ==
               (f_policy_timeout_after_req ? 2'd1 : 2'd0))))
    );

    // Requires every retired policy generation to have a consistent request, response, timeout,
    // and cancellation history.
    ast_retired_policy_history_balanced: assert property (
        f_retired_history_valid
        |-> (f_retired_history_resolution_count == 2'd1) &&
            ((!f_retired_history_timed_out &&
              (f_retired_history_req_count == 2'd1) &&
              (f_retired_history_rsp_count == 2'd1) &&
              (f_retired_history_timeout_count == 2'd0) &&
              (f_retired_history_cancel_count == 2'd0)) ||
             (f_retired_history_timed_out &&
              !f_retired_history_timeout_after_req &&
              (f_retired_history_req_count == 2'd0) &&
              (f_retired_history_rsp_count == 2'd0) &&
              (f_retired_history_timeout_count == 2'd1) &&
              (f_retired_history_cancel_count == 2'd0)) ||
             (f_retired_history_timed_out &&
              f_retired_history_timeout_after_req &&
              (f_retired_history_req_count == 2'd1) &&
              (f_retired_history_rsp_count == 2'd0) &&
              (f_retired_history_timeout_count == 2'd1) &&
              (f_retired_history_cancel_count == 2'd1)))
    );

    // ------------------------------------------------------------------
    // Initial-policy timeout and untagged-response quarantine
    // ------------------------------------------------------------------
    generate
        if (POLICY_TIMEOUT_ENABLE &&
            (POLICY_TIMEOUT_CYCLES == 1)) begin : g_timeout_one_cycle
            // For a one-cycle timeout, times out a write immediately after address acceptance
            // without issuing a policy request.
            ast_one_cycle_write_times_out_on_accept: assert property (
                s_aw_hs |=> f_policy_timed_out &&
                            f_policy_is_write &&
                            (f_policy_req_count == 0)
            );

            // For a one-cycle timeout, times out a read immediately after address acceptance
            // without issuing a policy request.
            ast_one_cycle_read_times_out_on_accept: assert property (
                s_ar_hs |=> f_policy_timed_out &&
                            !f_policy_is_write &&
                            (f_policy_req_count == 0)
            );
        end
        else if (POLICY_TIMEOUT_ENABLE) begin : g_timeout_multicycle
            // Starts the policy timeout timer when a write address is accepted.
            ast_write_starts_policy_timer: assert property (
                s_aw_hs |=> f_policy_timer_active &&
                            (f_policy_timeout_count ==
                             POLICY_TIMEOUT_COUNT_ONE)
            );

            // Starts the policy timeout timer when a read address is accepted.
            ast_read_starts_policy_timer: assert property (
                s_ar_hs |=> f_policy_timer_active &&
                            (f_policy_timeout_count ==
                             POLICY_TIMEOUT_COUNT_ONE)
            );

            if (POLICY_TIMEOUT_CYCLES == 2) begin : g_two_cycle_deadline
                // For a two-cycle timeout, places the timeout event on the edge after address
                // acceptance.
                ast_two_cycle_deadline_is_next_edge: assert property (
                    policy_addr_hs |=> policy_timeout_fire
                );
            end
        end
        else begin : g_timeout_disabled
            // Keeps timeout and cancellation state inactive when policy timeout is disabled.
            ast_disabled_timeout_never_runs: assert property (
                !f_policy_timer_active && !f_policy_timed_out &&
                !policy_cancel_valid
            );
        end
    endgenerate

    // Prevents W-before-AW data from starting the policy timer before address acceptance.
    ast_w_before_aw_does_not_start_policy_timer: assert property (
        s_w_hs && !s_aw_hs && !f_aw_seen && !f_policy_active
        |=> !f_policy_timer_active && !f_policy_timed_out
    );

    // Keeps the active timeout counter within its configured legal range.
    ast_policy_timeout_counter_range: assert property (
        f_policy_timer_active
        |-> (f_policy_timeout_count >= POLICY_TIMEOUT_COUNT_ONE) &&
            (f_policy_timeout_count <= POLICY_TIMEOUT_LAST_COUNT)
    );

    // Advances the timeout counter by one cycle while awaiting policy resolution.
    ast_policy_timeout_counter_advances: assert property (
        f_policy_timer_active && !policy_timeout_final_cycle &&
        !policy_rsp_hs
        |=> f_policy_timer_active &&
            (f_policy_timeout_count ==
             ($past(f_policy_timeout_count) + POLICY_TIMEOUT_COUNT_ONE))
    );

    // Stops the timer and records a response when policy resolution arrives before timeout.
    ast_timely_policy_response_stops_timeout: assert property (
        policy_rsp_hs
        |=> f_policy_rsp_seen && !f_policy_timed_out &&
            !f_policy_timer_active
    );

    // Gives a valid policy response precedence when it handshakes on the final permitted cycle.
    ast_final_cycle_response_wins: assert property (
        policy_timeout_final_cycle && policy_rsp_hs
        |=> f_policy_rsp_seen && !f_policy_timed_out &&
            !f_policy_timer_active &&
            (f_policy_resolution_count == 2'd1)
    );

    // Generates exactly one timeout resolution when the final permitted cycle ends without a
    // response.
    ast_final_cycle_without_response_times_out: assert property (
        policy_timeout_fire
        |=> f_policy_timed_out && !f_policy_rsp_seen &&
            !f_policy_timer_active &&
            (f_policy_timeout_event_count == 2'd1) &&
            (f_policy_resolution_count == 2'd1)
    );

    // Prevents a transaction from being resolved both by response and by timeout.
    ast_policy_resolution_is_exclusive: assert property (
        f_policy_active
        |-> !(f_policy_rsp_seen && f_policy_timed_out) &&
            (f_policy_resolution_count <= 2'd1)
    );

    // Prevents more than one timeout event or resolution for the same transaction.
    ast_policy_timeout_cannot_repeat: assert property (
        f_policy_timed_out
        |-> !f_policy_timer_active &&
            (f_policy_timeout_event_count == 2'd1) &&
            (f_policy_resolution_count == 2'd1)
    );

    // Keeps timeout state asserted until local completion and any required cancellation make
    // clearing safe.
    ast_policy_timeout_sticky_until_safe_clear: assert property (
        f_policy_timed_out && !policy_txn_complete_hs &&
        !(policy_cancel_hs && f_policy_axi_complete_seen)
        |=> f_policy_timed_out
    );

    // Keeps an accepted timed-out transaction quarantined after AXI completion until cancellation
    // retires it.
    ast_completed_quarantine_remains_sticky: assert property (
        f_policy_timed_out && f_policy_timeout_after_req &&
        policy_txn_complete_hs && !f_policy_cancel_seen &&
        !policy_cancel_hs
        |=> f_policy_timed_out && f_policy_axi_complete_seen &&
            policy_cancel_valid
    );

    // Requires no cancellation when timeout occurs before the policy request is accepted.
    ast_timeout_before_request_needs_no_cancel: assert property (
        policy_timeout_fire && !policy_timeout_request_accepted
        |=> f_policy_timed_out &&
            !f_policy_timeout_after_req && !policy_cancel_valid
    );

    // Requires cancellation and response quarantine when timeout follows policy-request
    // acceptance.
    ast_timeout_after_request_enters_quarantine: assert property (
        policy_timeout_fire && policy_timeout_request_accepted
        |=> f_policy_timed_out && f_policy_timeout_after_req &&
            policy_cancel_valid && !policy_rsp_ready
    );

    // Allows cancellation only for one accepted, unanswered policy request that has timed out.
    ast_policy_cancel_only_for_quarantine: assert property (
        policy_cancel_valid
        |-> f_policy_active && f_policy_timed_out &&
            f_policy_timeout_after_req && !f_policy_cancel_seen &&
            (f_policy_req_count == 2'd1) &&
            (f_policy_rsp_count == 2'd0)
    );

    // Prevents policy-response readiness while cancellation is active.
    ast_policy_cancel_excludes_response_ready: assert property (
        policy_cancel_valid |-> !policy_rsp_ready
    );

    // Prevents a policy-response handshake on the cancellation-retirement cycle.
    ast_policy_cancel_excludes_response_handshake: assert property (
        policy_cancel_hs |-> !policy_rsp_hs
    );

    // Allows at most one cancellation handshake for a timed-out accepted request.
    ast_one_policy_cancel: assert property (
        policy_cancel_hs
        |-> f_policy_timed_out && f_policy_timeout_after_req &&
            !f_policy_cancel_seen && (f_policy_cancel_count == 0)
    );

    // Deasserts cancellation after the cancellation handshake.
    ast_policy_cancel_drops_after_handshake: assert property (
        policy_cancel_hs |=> !policy_cancel_valid
    );

    // Keeps a retired policy-generation fence active until a new request is accepted.
    ast_policy_generation_fence_sticky: assert property (
        f_policy_generation_retired && !policy_req_hs
        |=> f_policy_generation_retired
    );

    // Rejects late policy responses while an accepted timed-out request remains quarantined.
    ast_quarantine_rejects_late_response: assert property (
        f_policy_timed_out && f_policy_timeout_after_req &&
        !f_policy_cancel_seen
        |-> !policy_rsp_ready && !policy_rsp_hs
    );

    // Blocks new policy requests and new address admission until quarantine retirement.
    ast_quarantine_blocks_policy_reuse: assert property (
        f_policy_timed_out && f_policy_timeout_after_req &&
        !f_policy_cancel_seen
        |-> !policy_req_valid && !s_axi_awready && !s_axi_arready
    );

    // Blocks new write-data ownership after local completion while quarantine remains active.
    ast_completed_quarantine_blocks_new_w_owner: assert property (
        f_policy_timed_out && f_policy_timeout_after_req &&
        f_policy_axi_complete_seen && !f_policy_cancel_seen
        |-> !s_axi_wready
    );

    // Prevents acceptance of any policy response after timeout has been recorded.
    ast_policy_response_never_accepted_after_timeout: assert property (
        f_policy_timed_out |-> !policy_rsp_hs
    );

    // Ignores revocation presented before an authorization decision as a late-revocation event.
    ast_pre_timeout_revocation_is_not_late_revocation: assert property (
        f_policy_active && !f_policy_rsp_seen && !f_policy_timed_out &&
        !policy_rsp_hs && policy_revoke_valid
        |=> !f_write_revoked && !f_read_revoked
    );

    // Converts a timed-out write into an initial denial and blocks protected-side write activity.
    ast_write_timeout_causes_initial_denial: assert property (
        policy_timeout_fire && policy_timeout_is_write
        |=> f_policy_timed_out && f_policy_is_write &&
            f_aw_decision_seen && !f_aw_allowed &&
            !f_write_revoked &&
            !m_axi_awvalid && !m_axi_wvalid && !m_axi_bready
    );

    // Converts a timed-out read into an initial denial and blocks protected-side read activity.
    ast_read_timeout_causes_initial_denial: assert property (
        policy_timeout_fire && !policy_timeout_is_write
        |=> f_policy_timed_out && !f_policy_is_write &&
            f_ar_decision_seen && !f_ar_allowed &&
            !f_read_revoked && !m_axi_arvalid && !m_axi_rready
    );

    // Prevents all protected-side AXI activity after policy timeout.
    ast_timeout_downstream_isolated: assert property (
        f_policy_timed_out
        |-> !m_axi_awvalid && !m_axi_wvalid && !m_axi_bready &&
            !m_axi_arvalid && !m_axi_rready
    );

    // Discards a buffered write beat when the corresponding write times out.
    ast_write_timeout_discards_buffered_w: assert property (
        policy_timeout_fire && policy_timeout_is_write && f_w_pending
        |=> !f_w_pending && !m_axi_awvalid &&
            !m_axi_wvalid && !m_axi_bready
    );

    // Discards a write beat accepted on the timeout boundary.
    ast_write_timeout_discards_boundary_w: assert property (
        policy_timeout_fire && policy_timeout_is_write && s_w_hs
        |=> !f_w_pending && !m_axi_awvalid &&
            !m_axi_wvalid && !m_axi_bready
    );

    // Continues accepting owner write data after timeout until WLAST is drained.
    ast_timed_out_write_drains_to_wlast: assert property (
        f_policy_timed_out && f_policy_is_write &&
        f_write_owner && !f_s_wlast_seen
        |-> s_axi_wready
    );

    // Returns DECERR promptly when timeout occurs after WLAST is already available.
    ast_write_timeout_existing_wlast_completion: assert property (
        policy_timeout_fire && policy_timeout_is_write &&
        (f_s_wlast_seen || (s_w_hs && s_axi_wlast))
        |-> ##2 s_axi_bvalid &&
                 (s_axi_bid == f_awid) &&
                 (s_axi_bresp == AXI_RESP_DECERR)
    );

    // Returns DECERR promptly after the final drained write beat of a timed-out write.
    ast_write_timeout_final_w_completion: assert property (
        f_policy_timed_out && f_policy_is_write &&
        s_w_hs && s_axi_wlast
        |-> ##2 s_axi_bvalid &&
                 (s_axi_bid == f_awid) &&
                 (s_axi_bresp == AXI_RESP_DECERR)
    );

    // Requires the local response for a timed-out write to be DECERR with the original BID and no
    // downstream write activity.
    ast_write_timeout_local_b: assert property (
        s_axi_bvalid && f_policy_timed_out && f_policy_is_write
        |-> (s_axi_bid == f_awid) &&
            (s_axi_bresp == AXI_RESP_DECERR) &&
            (f_s_w_count == f_w_expected) &&
            !f_m_aw_seen && (f_m_w_count == 0) &&
            !f_m_b_captured
    );

    // Generates a zero-data DECERR read beat after a read timeout.
    ast_read_timeout_first_local_beat: assert property (
        policy_timeout_fire && !policy_timeout_is_write
        |-> ##2 s_axi_rvalid &&
                 (s_axi_rid == f_arid) &&
                 (s_axi_rdata == '0) &&
                 (s_axi_rresp == AXI_RESP_DECERR)
    );

    // Requires every local read-timeout beat to carry the original RID, zero data, DECERR, and
    // correct RLAST.
    ast_read_timeout_local_r: assert property (
        s_axi_rvalid && f_policy_timed_out && !f_policy_is_write
        |-> (s_axi_rid == f_arid) &&
            (s_axi_rdata == '0) &&
            (s_axi_rresp == AXI_RESP_DECERR) &&
            (s_axi_rlast ==
             ((f_s_r_count + 9'd1) == f_r_expected)) &&
            (f_m_r_count == 0) && !f_m_ar_seen
    );

    // Requires a timed-out read to complete with exactly the expected local beat count and no
    // downstream read.
    ast_read_timeout_final_conservation: assert property (
        s_r_hs && s_axi_rlast && f_policy_timed_out &&
        !f_policy_is_write
        |-> (f_s_r_count + 9'd1) == f_r_expected &&
            (f_m_r_count == 0) && !f_m_ar_seen
    );

    // Live policy_rsp_allow is irrelevant until a response handshake. These
    // isolation properties hold for all values and changes of that input.
    // Prevents an unhandshaken policy Allow value from enabling downstream or local completion
    // activity.
    ast_policy_allow_ignored_without_handshake: assert property (
        f_policy_active && !f_policy_rsp_seen &&
        !f_policy_timed_out && !policy_rsp_hs
        |-> !m_axi_awvalid && !m_axi_wvalid && !m_axi_bready &&
            !m_axi_arvalid && !m_axi_rready &&
            !s_axi_bvalid && !s_axi_rvalid
    );

    // Blocks write forwarding and completion before a write authorization decision exists.
    ast_write_blocked_before_policy_resolution: assert property (
        f_write_owner && (!f_aw_seen || !f_aw_decision_seen)
        |-> !m_axi_awvalid && !m_axi_wvalid && !m_axi_bready &&
            !s_axi_bvalid
    );

    // Blocks read forwarding and completion before a read authorization decision exists.
    ast_read_blocked_before_policy_resolution: assert property (
        f_read_owner && !f_ar_decision_seen
        |-> !m_axi_arvalid && !m_axi_rready && !s_axi_rvalid
    );

    // Overrides an external Allow for an illegal write and keeps the protected side isolated.
    ast_illegal_write_allow_isolated: assert property (
        policy_rsp_hs && f_policy_is_write && policy_rsp_allow &&
        !f_policy_legal
        |=> f_aw_decision_seen && !f_aw_allowed &&
            !m_axi_awvalid && !m_axi_wvalid && !m_axi_bready
    );

    // Overrides an external Allow for an illegal read and keeps the protected side isolated.
    ast_illegal_read_allow_isolated: assert property (
        policy_rsp_hs && !f_policy_is_write && policy_rsp_allow &&
        !f_policy_legal
        |=> f_ar_decision_seen && !f_ar_allowed &&
            !m_axi_arvalid && !m_axi_rready
    );

    // Treats Allow coincident with revocation as an initial write denial.
    ast_simultaneous_write_allow_revoke_denied: assert property (
        policy_initial_revoke_hs && f_policy_is_write
        |=> f_policy_initial_revoke &&
            f_aw_decision_seen && !f_aw_allowed &&
            !f_write_revoked &&
            !m_axi_awvalid && !m_axi_wvalid && !m_axi_bready
    );

    // Treats Allow coincident with revocation as an initial read denial.
    ast_simultaneous_read_allow_revoke_denied: assert property (
        policy_initial_revoke_hs && !f_policy_is_write
        |=> f_policy_initial_revoke &&
            f_ar_decision_seen && !f_ar_allowed &&
            !f_read_revoked &&
            !m_axi_arvalid && !m_axi_rready
    );

    // Prevents protected-side activity after an Allow decision that is vetoed by coincident
    // revocation.
    ast_simultaneous_allow_revoke_downstream_isolated: assert property (
        f_policy_initial_revoke
        |-> !m_axi_awvalid && !m_axi_wvalid && !m_axi_bready &&
            !m_axi_arvalid && !m_axi_rready
    );

    // Discards buffered write data when coincident revocation vetoes initial write authorization.
    ast_simultaneous_write_revoke_discards_buffered_w: assert property (
        policy_initial_revoke_hs && f_policy_is_write && f_w_pending
        |=> f_policy_initial_revoke && !f_w_pending &&
            !m_axi_awvalid && !m_axi_wvalid && !m_axi_bready
    );

    // Discards write data accepted on the coincident-revocation decision edge.
    ast_simultaneous_write_revoke_discards_response_edge_w: assert property (
        policy_initial_revoke_hs && f_policy_is_write && s_w_hs
        |=> f_policy_initial_revoke && !f_w_pending &&
            !m_axi_awvalid && !m_axi_wvalid && !m_axi_bready
    );

    // Drains the denied write to WLAST after coincident revocation.
    ast_simultaneous_write_revoke_drains_to_wlast: assert property (
        f_policy_initial_revoke && f_policy_is_write &&
        !f_s_wlast_seen
        |-> s_axi_wready
    );

    // Returns DECERR promptly when coincident revocation occurs with WLAST already available.
    ast_simultaneous_write_revoke_existing_wlast_completion: assert property (
        policy_initial_revoke_hs && f_policy_is_write &&
        (f_s_wlast_seen || (s_w_hs && s_axi_wlast))
        |-> ##2 s_axi_bvalid &&
                 (s_axi_bid == f_awid) &&
                 (s_axi_bresp == AXI_RESP_DECERR)
    );

    // Returns DECERR promptly after the final drained beat of a write denied by coincident
    // revocation.
    ast_simultaneous_write_revoke_final_w_completion: assert property (
        f_policy_initial_revoke && f_policy_is_write &&
        s_w_hs && s_axi_wlast
        |-> ##2 s_axi_bvalid &&
                 (s_axi_bid == f_awid) &&
                 (s_axi_bresp == AXI_RESP_DECERR)
    );

    // Requires the local response for a coincidently revoked write to be DECERR with no downstream
    // write activity.
    ast_simultaneous_write_revoke_local_b: assert property (
        s_axi_bvalid && f_policy_initial_revoke &&
        f_policy_is_write
        |-> (s_axi_bid == f_awid) &&
            (s_axi_bresp == AXI_RESP_DECERR) &&
            (f_s_w_count == f_w_expected) &&
            !f_m_aw_seen && (f_m_w_count == 0) &&
            !f_m_b_captured
    );

    // Generates a zero-data DECERR read beat when coincident revocation vetoes initial read
    // authorization.
    ast_simultaneous_read_revoke_first_local_beat: assert property (
        policy_initial_revoke_hs && !f_policy_is_write
        |-> ##2 s_axi_rvalid &&
                 (s_axi_rid == f_arid) &&
                 (s_axi_rdata == '0) &&
                 (s_axi_rresp == AXI_RESP_DECERR)
    );

    // Requires each locally generated read beat after coincident revocation to carry zero data,
    // DECERR, and correct framing.
    ast_simultaneous_read_revoke_local_r: assert property (
        s_axi_rvalid && f_policy_initial_revoke &&
        !f_policy_is_write
        |-> (s_axi_rid == f_arid) &&
            (s_axi_rdata == '0) &&
            (s_axi_rresp == AXI_RESP_DECERR) &&
            (s_axi_rlast ==
             ((f_s_r_count + 9'd1) == f_r_expected)) &&
            (f_m_r_count == 0) && !f_m_ar_seen
    );

    // Requires a coincidently revoked read to complete with exactly the expected local beat count
    // and no downstream read.
    ast_simultaneous_read_revoke_final_conservation: assert property (
        s_r_hs && s_axi_rlast && f_policy_initial_revoke &&
        !f_policy_is_write
        |-> (f_s_r_count + 9'd1) == f_r_expected &&
            (f_m_r_count == 0) && !f_m_ar_seen
    );

    // Independent directed vectors guard against a common-mode error in the
    // general reference arithmetic. They now check the registered request.
    generate
        if ((AXI_ADDR_W >= 12) && (AXI_STRB_W >= 4)) begin : g_direct_footprint_checks
            localparam logic [AXI_ADDR_W-1:0] V_0100 = 12'h100;
            localparam logic [AXI_ADDR_W-1:0] V_0102 = 12'h102;
            localparam logic [AXI_ADDR_W-1:0] V_0103 = 12'h103;
            localparam logic [AXI_ADDR_W-1:0] V_010C = 12'h10c;
            localparam logic [AXI_ADDR_W-1:0] V_010F = 12'h10f;
            localparam logic [AXI_ADDR_W-1:0] V_0FFC = 12'hffc;

            if (!POLICY_TIMEOUT_ENABLE ||
                (POLICY_TIMEOUT_CYCLES > 1)) begin : g_request_survives_accept
            // Checks the computed address range for a representative FIXED burst.
            ast_direct_fixed_footprint: assert property (
                s_aw_hs && (s_axi_awaddr == V_0100) &&
                (s_axi_awlen == 8'd15) && (s_axi_awsize == 3'd2) &&
                (s_axi_awburst == 2'b00)
                |=> policy_req_valid && policy_req_is_write &&
                    (policy_req_start_addr == V_0100) &&
                    (policy_req_end_addr == V_0103)
            );

            // Checks the computed address range for a representative unaligned INCR burst.
            ast_direct_unaligned_incr_footprint: assert property (
                s_aw_hs && (s_axi_awaddr == V_0103) &&
                (s_axi_awlen == 8'd3) && (s_axi_awsize == 3'd2) &&
                (s_axi_awburst == 2'b01)
                |=> policy_req_valid &&
                    (policy_req_start_addr == V_0103) &&
                    (policy_req_end_addr == V_010F)
            );

            // Checks the computed address range for a representative WRAP burst.
            ast_direct_wrap_footprint: assert property (
                s_aw_hs && (s_axi_awaddr == V_010C) &&
                (s_axi_awlen == 8'd3) && (s_axi_awsize == 3'd2) &&
                (s_axi_awburst == 2'b10)
                |=> policy_req_valid &&
                    (policy_req_start_addr == V_0100) &&
                    (policy_req_end_addr == V_010F)
            );

            // Marks a representative 4-KiB-crossing burst as illegal in the policy range.
            ast_direct_4k_crossing_denied: assert property (
                s_aw_hs && (s_axi_awaddr == V_0FFC) &&
                (s_axi_awlen == 8'd1) && (s_axi_awsize == 3'd2) &&
                (s_axi_awburst == 2'b01)
                |=> policy_req_valid &&
                    (policy_req_start_addr == '0) &&
                    (policy_req_end_addr == {AXI_ADDR_W{1'b1}})
            );

            // Marks a reserved AXI burst type as illegal in the policy range.
            ast_direct_reserved_burst_denied: assert property (
                s_aw_hs && (s_axi_awaddr == V_0100) &&
                (s_axi_awlen == 8'd0) && (s_axi_awsize == 3'd0) &&
                (s_axi_awburst == 2'b11)
                |=> policy_req_valid &&
                    (policy_req_start_addr == '0) &&
                    (policy_req_end_addr == {AXI_ADDR_W{1'b1}})
            );

            // Marks an unsupported FIXED-burst length as illegal in the policy range.
            ast_direct_fixed_length_denied: assert property (
                s_aw_hs && (s_axi_awaddr == V_0100) &&
                (s_axi_awlen == 8'd16) && (s_axi_awsize == 3'd2) &&
                (s_axi_awburst == 2'b00)
                |=> policy_req_valid &&
                    (policy_req_start_addr == '0) &&
                    (policy_req_end_addr == {AXI_ADDR_W{1'b1}})
            );

            // Marks an invalid WRAP-burst length as illegal in the policy range.
            ast_direct_wrap_length_denied: assert property (
                s_aw_hs && (s_axi_awaddr == V_0100) &&
                (s_axi_awlen == 8'd2) && (s_axi_awsize == 3'd2) &&
                (s_axi_awburst == 2'b10)
                |=> policy_req_valid &&
                    (policy_req_start_addr == '0) &&
                    (policy_req_end_addr == {AXI_ADDR_W{1'b1}})
            );

            // Marks a misaligned WRAP burst as illegal in the policy range.
            ast_direct_wrap_alignment_denied: assert property (
                s_aw_hs && (s_axi_awaddr == V_0102) &&
                (s_axi_awlen == 8'd3) && (s_axi_awsize == 3'd2) &&
                (s_axi_awburst == 2'b10)
                |=> policy_req_valid &&
                    (policy_req_start_addr == '0) &&
                    (policy_req_end_addr == {AXI_ADDR_W{1'b1}})
            );

            // Marks a representative illegal read burst as illegal in the policy range.
            ast_direct_illegal_read_denied: assert property (
                s_ar_hs && (s_axi_araddr == V_0FFC) &&
                (s_axi_arlen == 8'd1) && (s_axi_arsize == 3'd2) &&
                (s_axi_arburst == 2'b01)
                |=> policy_req_valid && !policy_req_is_write &&
                    (policy_req_start_addr == '0) &&
                    (policy_req_end_addr == {AXI_ADDR_W{1'b1}})
            );

            if (AXI_STRB_W < 128) begin : g_direct_oversize_check
                // Marks a transfer size wider than the data bus as illegal in the policy range.
                ast_direct_oversize_denied: assert property (
                    s_aw_hs && (s_axi_awaddr == V_0100) &&
                    (s_axi_awlen == 8'd0) && (s_axi_awsize == 3'd7) &&
                    (s_axi_awburst == 2'b01)
                    |=> policy_req_valid &&
                        (policy_req_start_addr == '0) &&
                        (policy_req_end_addr == {AXI_ADDR_W{1'b1}})
                );
            end

            if (AXI_ADDR_W == 32) begin : g_direct_overflow_check
                // Marks a burst whose computed address range overflows the address space as
                // illegal.
                ast_direct_address_overflow_denied: assert property (
                    s_aw_hs && (s_axi_awaddr == 32'hffff_fffc) &&
                    (s_axi_awlen == 8'd1) && (s_axi_awsize == 3'd2) &&
                    (s_axi_awburst == 2'b01)
                    |=> policy_req_valid &&
                        (policy_req_start_addr == '0) &&
                        (policy_req_end_addr == {AXI_ADDR_W{1'b1}})
                );
            end
            end
        end
    endgenerate

    // ------------------------------------------------------------------
    // Write address, data, and response conservation
    // ------------------------------------------------------------------
    // Allows a downstream AW only for a captured, legal, policy-authorized write that has not
    // already been forwarded.
    ast_m_aw_only_if_allowed: assert property (
        m_axi_awvalid
        |-> f_aw_seen && f_aw_decision_seen && f_aw_allowed &&
            f_policy_rsp_seen && f_policy_raw_allow && f_aw_legal &&
            !f_m_aw_seen
    );

    // Requires the forwarded AW payload to match the captured write-address transaction.
    ast_m_aw_payload: assert property (
        m_axi_awvalid
        |-> m_axi_awid == f_awid &&
            m_axi_awaddr == f_awaddr &&
            m_axi_awlen == f_awlen &&
            m_axi_awsize == f_awsize &&
            m_axi_awburst == f_awburst &&
            m_axi_awuser == f_awuser
    );

    // Issues the downstream write address after an effective write Allow decision.
    ast_allowed_aw_is_issued: assert property (
        policy_rsp_hs && f_policy_is_write &&
        policy_rsp_effective_allow
        |=> m_axi_awvalid
    );

    // Allows at most one downstream AW handshake per write transaction.
    ast_one_m_aw: assert property (m_aw_hs |-> !f_m_aw_seen);
    // Deasserts downstream AWVALID after the write-address handshake.
    ast_m_aw_drops_after_handshake: assert property (
        f_m_aw_seen |-> !m_axi_awvalid
    );

    // Prevents downstream write activity for a denied write.
    ast_denied_write_isolated: assert property (
        f_aw_seen && f_aw_decision_seen && !f_aw_allowed
        |-> !m_axi_awvalid && !m_axi_wvalid && !m_axi_bready
    );

    // Allows downstream WVALID only after an authorized write address has been forwarded and write
    // data is pending.
    ast_m_w_after_aw: assert property (
        m_axi_wvalid
        |-> f_aw_seen && f_aw_decision_seen && f_aw_allowed &&
            f_m_aw_seen && f_w_pending
    );

    // Requires forwarded WDATA and WLAST to match the buffered upstream write beat.
    ast_m_w_payload: assert property (
        m_axi_wvalid
        |-> m_axi_wdata == f_w_data &&
            m_axi_wlast == f_w_last
    );

    // The strobe decision is checked when a new registered beat is presented.
    // Stability, rather than mutation, governs a beat already under stall.
    // Preserves WSTRB on newly presented write beats before late revocation.
    ast_new_clean_w_strb: assert property (
        $rose(m_axi_wvalid) && !f_write_revoked
        |-> m_axi_wstrb == f_w_strb
    );

    // Forces WSTRB to zero on newly presented write beats after late revocation.
    ast_new_revoked_w_poisoned: assert property (
        $rose(m_axi_wvalid) && f_write_revoked
        |-> m_axi_wstrb == '0
    );

    // Prevents the number of forwarded write beats from exceeding the number accepted upstream.
    ast_m_w_count_conserved: assert property (
        f_aw_seen && f_aw_decision_seen && f_aw_allowed
        |-> f_m_w_count <= f_s_w_count
    );

    // Keeps the write skid-buffer occupancy consistent with accepted and forwarded beat counts.
    ast_allowed_w_stage_occupancy: assert property (
        f_aw_seen && f_aw_decision_seen && f_aw_allowed
        |-> (f_s_w_count - f_m_w_count) ==
            (f_w_pending ? 9'd1 : 9'd0)
    );

    // Accounts correctly for buffered W-before-AW data before the write address arrives.
    ast_w_before_aw_stage_occupancy: assert property (
        f_write_owner && !f_aw_seen
        |-> f_m_w_count == 0 &&
            f_s_w_count == (f_w_pending ? 9'd1 : 9'd0)
    );

    // Accounts correctly for buffered write data while authorization is pending.
    ast_policy_wait_w_stage_occupancy: assert property (
        f_aw_seen && !f_aw_decision_seen
        |-> f_m_w_count == 0 &&
            f_s_w_count == (f_w_pending ? 9'd1 : 9'd0)
    );

    // Prevents acceptance of a new upstream write beat while the one-entry write buffer is
    // occupied.
    ast_no_w_stage_overwrite: assert property (
        s_w_hs |-> !f_w_pending
    );

    // Requires forwarded WLAST to occur exactly on the expected final write beat.
    ast_m_w_framing: assert property (
        m_w_hs
        |-> f_m_w_count < f_w_expected &&
            (m_axi_wlast ==
             ((f_m_w_count + 9'd1) == f_w_expected))
    );

    // Forwards a buffered write beat after the downstream write address is accepted.
    ast_buffered_w_is_issued_after_aw: assert property (
        m_aw_hs && f_w_pending
        |-> ##2 m_axi_wvalid
    );

    // Forwards an accepted post-AW write beat once the authorized write path is ready.
    ast_post_aw_w_is_issued: assert property (
        s_w_hs && f_aw_seen && f_aw_decision_seen && f_aw_allowed &&
        (f_m_aw_seen || m_aw_hs)
        |-> ##2 m_axi_wvalid
    );

    // Stops accepting upstream write data after WLAST has been accepted.
    ast_no_s_w_after_wlast: assert property (
        f_s_wlast_seen |-> !s_axi_wready
    );

    // Accepts a downstream B response only after the authorized write address and all expected
    // data beats complete.
    ast_m_bready_only_when_expected: assert property (
        m_axi_bready
        |-> f_aw_seen && f_aw_decision_seen && f_aw_allowed &&
            f_m_aw_seen &&
            (f_m_w_count == f_w_expected) && !f_m_b_captured
    );

    // Captures at most one downstream B response per write transaction.
    ast_one_m_b_capture: assert property (
        m_b_hs |-> !f_m_b_captured
    );

    // Enables downstream B-response capture after the final forwarded write beat.
    ast_final_m_w_enables_b_capture: assert property (
        m_w_hs && m_axi_wlast |=> m_axi_bready
    );

    // Presents a captured downstream B response to the upstream manager.
    ast_captured_b_is_presented: assert property (
        m_b_hs |=> s_axi_bvalid
    );

    // Presents BVALID only while a write transaction owner exists.
    ast_s_b_has_owner: assert property (
        s_axi_bvalid |-> f_write_owner && f_aw_seen
    );

    // Returns the original write transaction ID on the upstream B channel.
    ast_s_b_id: assert property (
        s_axi_bvalid |-> s_axi_bid == f_awid
    );

    // Requires a locally generated denied-write response to be DECERR after all expected upstream
    // write beats and with no downstream write activity.
    ast_local_denied_b: assert property (
        s_axi_bvalid && f_aw_decision_seen && !f_aw_allowed
        |-> s_axi_bresp == AXI_RESP_DECERR &&
            f_s_w_count == f_w_expected &&
            !f_m_aw_seen && (f_m_w_count == 0) &&
            !f_m_b_captured
    );

    // Generates the local B response once a denied write has drained through WLAST.
    ast_local_denied_b_generated: assert property (
        f_aw_seen && f_aw_decision_seen && !f_aw_allowed &&
        f_s_wlast_seen && !s_axi_bvalid
        |=> s_axi_bvalid
    );

    // Produces a denied-write B response within the specified bound after the final write beat.
    ast_denied_final_w_bounded_response: assert property (
        f_aw_seen && f_aw_decision_seen && !f_aw_allowed &&
        s_w_hs && s_axi_wlast
        |-> ##2 s_axi_bvalid
    );

    // Produces a denied-write B response within the specified bound when denial follows an already
    // completed write-data stream.
    ast_denied_aw_after_wlast_bounded_response: assert property (
        policy_rsp_hs && f_policy_is_write &&
        !policy_rsp_effective_allow &&
        (f_s_wlast_seen || (s_w_hs && s_axi_wlast))
        |-> ##2 s_axi_bvalid
    );

    // Returns the captured downstream B response only after complete authorized write forwarding.
    ast_forwarded_b: assert property (
        s_axi_bvalid && f_aw_allowed
        |-> f_m_aw_seen && f_m_b_captured &&
            (f_m_w_count == f_w_expected) &&
            (f_s_w_count == f_w_expected) &&
            (s_axi_bresp == f_expected_bresp)
    );

    // Converts a write response to DECERR when late revocation applies before upstream response
    // presentation.
    ast_revoked_write_returns_decerr: assert property (
        m_b_hs && (f_write_revoked || policy_revoke_valid)
        |=> s_axi_bvalid && s_axi_bresp == AXI_RESP_DECERR
    );

    // ------------------------------------------------------------------
    // Read address, data, and response conservation
    // ------------------------------------------------------------------
    // Allows a downstream AR only for a captured, legal, policy-authorized read that has not
    // already been forwarded.
    ast_m_ar_only_if_allowed: assert property (
        m_axi_arvalid
        |-> f_ar_seen && f_ar_decision_seen && f_ar_allowed &&
            f_policy_rsp_seen && f_policy_raw_allow && f_ar_legal &&
            !f_m_ar_seen
    );

    // Requires the forwarded AR payload to match the captured read-address transaction.
    ast_m_ar_payload: assert property (
        m_axi_arvalid
        |-> m_axi_arid == f_arid &&
            m_axi_araddr == f_araddr &&
            m_axi_arlen == f_arlen &&
            m_axi_arsize == f_arsize &&
            m_axi_arburst == f_arburst &&
            m_axi_aruser == f_aruser
    );

    // Issues the downstream read address after an effective read Allow decision.
    ast_allowed_ar_is_issued: assert property (
        policy_rsp_hs && !f_policy_is_write &&
        policy_rsp_effective_allow
        |=> m_axi_arvalid
    );

    // Allows at most one downstream AR handshake per read transaction.
    ast_one_m_ar: assert property (m_ar_hs |-> !f_m_ar_seen);
    // Deasserts downstream ARVALID after the read-address handshake.
    ast_m_ar_drops_after_handshake: assert property (
        f_m_ar_seen |-> !m_axi_arvalid
    );

    // Prevents downstream read activity for a denied read.
    ast_denied_read_isolated: assert property (
        f_ar_seen && f_ar_decision_seen && !f_ar_allowed
        |-> !m_axi_arvalid && !m_axi_rready
    );

    // Accepts downstream read data only for an active authorized read when the local read buffer
    // is available.
    ast_m_rready_only_when_expected: assert property (
        m_axi_rready
        |-> f_ar_seen && f_ar_decision_seen && f_ar_allowed &&
            f_m_ar_seen &&
            !f_r_fifo_valid && (f_m_r_count < f_r_expected)
    );

    // Prevents a downstream read beat from being captured and forwarded upstream in the same
    // cycle.
    ast_registered_r_no_simultaneous_transfer: assert property (
        !(m_r_hs && s_r_hs)
    );

    // Presents each captured downstream read beat to the upstream manager.
    ast_captured_r_is_presented: assert property (
        m_r_hs |=> s_axi_rvalid
    );

    // Keeps downstream and upstream read-beat counts consistent with at most one buffered beat.
    ast_r_fifo_conservation: assert property (
        f_ar_seen && f_ar_decision_seen && f_ar_allowed
        |-> f_s_r_count <= f_m_r_count &&
            (f_m_r_count - f_s_r_count <= 9'd1)
    );

    // Requires read-buffer validity to match the difference between captured and delivered
    // read-beat counts.
    ast_r_fifo_occupancy: assert property (
        f_ar_seen && f_ar_decision_seen && f_ar_allowed
        |-> f_r_fifo_valid == (f_m_r_count != f_s_r_count)
    );

    // Presents RVALID only while a read transaction owner exists.
    ast_s_r_has_owner: assert property (
        s_axi_rvalid |-> f_read_owner && f_ar_seen
    );

    // Requires locally generated denied-read beats to return the original RID, zero data, DECERR,
    // and correct RLAST with no downstream read activity.
    ast_local_denied_r: assert property (
        s_axi_rvalid && f_ar_decision_seen && !f_ar_allowed
        |-> s_axi_rid == f_arid &&
            s_axi_rdata == '0 &&
            s_axi_rresp == AXI_RESP_DECERR &&
            (s_axi_rlast ==
             ((f_s_r_count + 9'd1) == f_r_expected)) &&
            (f_m_r_count == 0) && !f_m_ar_seen
    );

    // Continues generating local read beats while a denied read remains incomplete.
    ast_local_denied_r_generated: assert property (
        f_ar_seen && f_ar_decision_seen && !f_ar_allowed &&
        !s_axi_rvalid
        |=> s_axi_rvalid
    );

    // Produces the first denied-read response beat within the specified bound after policy denial.
    ast_denied_ar_bounded_response: assert property (
        policy_rsp_hs && !f_policy_is_write &&
        !policy_rsp_effective_allow
        |-> ##2 s_axi_rvalid
    );

    // Requires each allowed upstream read response to match the buffered downstream response
    // payload.
    ast_forwarded_r_payload: assert property (
        s_axi_rvalid && f_ar_allowed
        |-> f_r_fifo_valid &&
            s_axi_rid == f_r_fifo_id &&
            s_axi_rdata == f_r_fifo_data &&
            s_axi_rresp == f_r_fifo_resp &&
            s_axi_rlast == f_r_fifo_last
    );

    // Requires upstream RLAST to occur exactly on the expected final read beat.
    ast_s_r_framing: assert property (
        s_r_hs
        |-> f_s_r_count < f_r_expected &&
            (s_axi_rlast ==
             ((f_s_r_count + 9'd1) == f_r_expected))
    );

    // Requires an allowed read to complete with matching expected downstream and upstream beat
    // counts.
    ast_read_final_conservation: assert property (
        s_r_hs && s_axi_rlast && f_ar_allowed
        |-> (f_s_r_count + 9'd1) == f_r_expected &&
            f_m_r_count == f_r_expected && f_m_ar_seen
    );

    // Requires a denied read to complete with exactly the expected local beat count and no
    // downstream read transfer.
    ast_denied_read_final_conservation: assert property (
        s_r_hs && s_axi_rlast && f_ar_decision_seen && !f_ar_allowed
        |-> (f_s_r_count + 9'd1) == f_r_expected &&
            (f_m_r_count == 0) && !f_m_ar_seen
    );

    // Converts a captured read beat to zero data and DECERR when late revocation applies.
    ast_revoked_read_capture_is_poisoned: assert property (
        m_r_hs && (f_read_revoked || policy_revoke_valid)
        |=> s_axi_rvalid && s_axi_rdata == '0 &&
            s_axi_rresp == AXI_RESP_DECERR
    );

    // ------------------------------------------------------------------
    // Reachability covers
    // ------------------------------------------------------------------
    // Exercises a legal single-beat write that is allowed and completes without DECERR.
    cvr_clean_single_write: cover property (
        s_aw_hs && ref_burst_legal(
            s_axi_awaddr, s_axi_awlen, s_axi_awsize, s_axi_awburst) &&
        (s_axi_awlen == 0)
        ##[1:$] policy_rsp_hs && f_policy_is_write &&
                  policy_rsp_effective_allow
        ##[1:$] s_b_hs && (s_axi_bresp != AXI_RESP_DECERR)
    );

    // Exercises an allowed write in which W is accepted before AW and later forwarded.
    cvr_allowed_w_before_aw: cover property (
        s_w_hs && !s_aw_hs
        ##[1:$] s_aw_hs && ref_burst_legal(
            s_axi_awaddr, s_axi_awlen, s_axi_awsize, s_axi_awburst)
        ##[1:$] policy_rsp_hs && f_policy_is_write &&
                  policy_rsp_effective_allow
        ##[1:$] m_w_hs
    );

    // Exercises a W-before-AW write that is denied and completed locally with DECERR.
    cvr_denied_w_before_aw: cover property (
        s_w_hs && !s_aw_hs
        ##[1:$] s_aw_hs
        ##[1:$] policy_rsp_hs && f_policy_is_write &&
                  !policy_rsp_allow
        ##[1:$] s_b_hs && (s_axi_bresp == AXI_RESP_DECERR)
    );

    // Exercises simultaneous AW and final W acceptance followed by policy denial and local DECERR.
    cvr_simultaneous_aw_wlast_denied: cover property (
        s_aw_hs && s_w_hs && s_axi_wlast
        ##[1:$] policy_rsp_hs && f_policy_is_write &&
                  !policy_rsp_allow
        ##[1:$] s_b_hs && (s_axi_bresp == AXI_RESP_DECERR)
    );

    // Exercises a legal allowed multibeat write through completion.
    cvr_multibeat_write: cover property (
        s_aw_hs && (s_axi_awlen > 0) &&
        ref_burst_legal(s_axi_awaddr, s_axi_awlen,
                        s_axi_awsize, s_axi_awburst)
        ##[1:$] policy_rsp_hs && f_policy_is_write &&
                  policy_rsp_effective_allow
        ##[1:$] s_b_hs && f_aw_allowed
    );

    // Exercises protected-side write-data backpressure followed by a successful W handshake.
    cvr_w_backpressure: cover property (
        m_axi_wvalid && !m_axi_wready
        ##[1:$] m_w_hs
    );

    // Exercises late write revocation before any protected-side W beat, causing zero-strobe
    // forwarding and DECERR completion.
    cvr_revoke_before_w: cover property (
        f_aw_seen && f_aw_allowed && (f_m_w_count == 0) &&
        policy_revoke_valid
        ##[1:$] m_axi_wvalid && (m_axi_wstrb == '0)
        ##[1:$] s_axi_bvalid && (s_axi_bresp == AXI_RESP_DECERR)
    );

    // Exercises late write revocation while a nonzero-strobe W beat is stalled, followed by DECERR
    // completion.
    cvr_revoke_during_w_stall: cover property (
        m_axi_wvalid && !m_axi_wready && (m_axi_wstrb != '0)
        ##1 m_axi_wvalid && !m_axi_wready && policy_revoke_valid
        ##[1:$] s_axi_bvalid && (s_axi_bresp == AXI_RESP_DECERR)
    );

    // Exercises revocation coincident with capture of the protected-side B response, followed by
    // DECERR upstream.
    cvr_revoke_at_b_capture: cover property (
        m_b_hs && policy_revoke_valid
        ##1 s_axi_bvalid && (s_axi_bresp == AXI_RESP_DECERR)
    );

    // Exercises a legal allowed multibeat read through the final read-data beat.
    cvr_allowed_multibeat_read: cover property (
        s_ar_hs && (s_axi_arlen > 0) &&
        ref_burst_legal(s_axi_araddr, s_axi_arlen,
                        s_axi_arsize, s_axi_arburst)
        ##[1:$] policy_rsp_hs && !f_policy_is_write &&
                  policy_rsp_effective_allow
        ##[1:$] s_r_hs && s_axi_rlast
    );

    // Exercises late read revocation before the first protected-side R beat, causing zero-data
    // DECERR upstream.
    cvr_revoke_before_first_r: cover property (
        f_ar_seen && f_ar_allowed && (f_m_r_count == 0) &&
        !m_r_hs && policy_revoke_valid
        ##[1:$] s_axi_rvalid && (s_axi_rdata == '0) &&
                  (s_axi_rresp == AXI_RESP_DECERR)
    );

    // Exercises late read revocation while a nonfinal upstream R beat is stalled, then transitions
    // to revoked completion.
    cvr_revoke_during_r_stall: cover property (
        s_axi_rvalid && !s_axi_rready && f_ar_allowed &&
        !s_axi_rlast && (s_axi_rresp != AXI_RESP_DECERR)
        ##1 s_axi_rvalid && !s_axi_rready && policy_revoke_valid
        ##[1:$] s_r_hs
        ##[1:$] s_axi_rvalid && (s_axi_rdata == '0) &&
                  (s_axi_rresp == AXI_RESP_DECERR)
    );

    // Exercises revocation coincident with protected-side R capture, followed by zero-data DECERR
    // upstream.
    cvr_revoke_at_r_capture: cover property (
        m_r_hs && !f_read_revoked && policy_revoke_valid
        ##1 s_axi_rvalid && (s_axi_rdata == '0) &&
             (s_axi_rresp == AXI_RESP_DECERR)
    );

    // Exercises a denied multibeat read that completes locally with DECERR through RLAST.
    cvr_denied_multibeat_read: cover property (
        s_ar_hs && (s_axi_arlen > 0)
        ##[1:$] policy_rsp_hs && !f_policy_is_write &&
                  !policy_rsp_allow
        ##[1:$] s_r_hs && s_axi_rlast &&
                  (s_axi_rresp == AXI_RESP_DECERR)
    );

    // Exercises local DECERR completion of a denied maximum-length 256-beat read.
    cvr_denied_256_beat_read: cover property (
        s_r_hs && s_axi_rlast && f_ar_seen && !f_ar_allowed &&
        ref_burst_legal(f_araddr, f_arlen, f_arsize, f_arburst) &&
        (f_r_expected == 9'd256) && (f_s_r_count == 9'd255) &&
        (s_axi_rresp == AXI_RESP_DECERR)
    );

    generate
        if (!SVA_INTEGRATION_MODE) begin : g_standalone_aw_ar_contention
            // Standalone-mode cover: exercises concurrent AW/AR contention with write admission
            // before read admission.
            cvr_aw_ar_contention: cover property (
                !f_write_owner && !f_read_owner &&
                s_axi_awvalid && s_axi_arvalid && s_aw_hs && !s_ar_hs
                ##[1:$] policy_req_hs && policy_req_is_write
                ##[1:$] s_b_hs
                ##[1:$] s_ar_hs
            );
        end
    endgenerate

    // Exercises an illegal write for which policy returns Allow but the firewall still completes
    // locally with DECERR.
    cvr_illegal_write_fail_closed: cover property (
        s_aw_hs && !ref_burst_legal(
            s_axi_awaddr, s_axi_awlen, s_axi_awsize, s_axi_awburst)
        ##[1:$] policy_rsp_hs && f_policy_is_write &&
                  policy_rsp_allow && !policy_revoke_valid
        ##[1:$] s_b_hs && (s_axi_bresp == AXI_RESP_DECERR)
    );

    // Exercises an illegal read for which policy returns Allow but the firewall still completes
    // locally with DECERR.
    cvr_illegal_read_fail_closed: cover property (
        s_ar_hs && !ref_burst_legal(
            s_axi_araddr, s_axi_arlen, s_axi_arsize, s_axi_arburst)
        ##[1:$] policy_rsp_hs && !f_policy_is_write &&
                  policy_rsp_allow && !policy_revoke_valid
        ##[1:$] s_r_hs && s_axi_rlast &&
                  (s_axi_rresp == AXI_RESP_DECERR)
    );

    // New policy-interface reachability.
    // Exercises multiple cycles of policy-request backpressure before request acceptance.
    cvr_policy_req_backpressure: cover property (
        policy_req_valid && !policy_req_ready
        ##1 policy_req_valid && !policy_req_ready
        ##1 policy_req_valid && !policy_req_ready
        ##1 policy_req_hs
    );

    // Exercises a backpressured policy response followed by response acceptance.
    cvr_policy_rsp_backpressure: cover property (
        policy_req_hs
        ##1 policy_rsp_valid && !policy_rsp_ready
        ##1 policy_rsp_hs
    );

    // Exercises a delayed Allow decision for a write request.
    cvr_delayed_write_allow: cover property (
        s_aw_hs
        ##[1:$] policy_req_hs && policy_req_is_write
        ##1 !policy_rsp_hs
        ##1 !policy_rsp_hs
        ##1 policy_rsp_hs && f_policy_is_write &&
              policy_rsp_effective_allow
    );

    // Exercises a delayed Deny decision for a write request.
    cvr_delayed_write_deny: cover property (
        s_aw_hs
        ##[1:$] policy_req_hs && policy_req_is_write
        ##1 !policy_rsp_hs
        ##1 !policy_rsp_hs
        ##1 policy_rsp_hs && f_policy_is_write && !policy_rsp_allow
    );

    // Exercises a delayed Allow decision for a read request.
    cvr_delayed_read_allow: cover property (
        s_ar_hs
        ##[1:$] policy_req_hs && !policy_req_is_write
        ##1 !policy_rsp_hs
        ##1 !policy_rsp_hs
        ##1 policy_rsp_hs && !f_policy_is_write &&
              policy_rsp_effective_allow
    );

    // Exercises a delayed Deny decision for a read request.
    cvr_delayed_read_deny: cover property (
        s_ar_hs
        ##[1:$] policy_req_hs && !policy_req_is_write
        ##1 !policy_rsp_hs
        ##1 !policy_rsp_hs
        ##1 policy_rsp_hs && !f_policy_is_write && !policy_rsp_allow
    );

    // Exercises a W-before-AW transaction that remains buffered while the policy decision is
    // pending.
    cvr_w_before_aw_policy_latency: cover property (
        s_w_hs && !s_aw_hs
        ##[1:$] s_aw_hs
        ##1 f_policy_active && !f_policy_rsp_seen && f_w_pending
    );

    // Exercises simultaneous AW/W acceptance with buffered write data while the policy decision is
    // pending.
    cvr_simultaneous_aw_w_policy_latency: cover property (
        s_aw_hs && s_w_hs
        ##1 f_policy_active && !f_policy_rsp_seen && f_w_pending
    );

    // Shows that the policy Allow value may change while policy response VALID is low.
    cvr_policy_allow_changes_while_invalid: cover property (
        f_policy_active && f_policy_req_seen && !f_policy_rsp_seen &&
        !policy_rsp_valid && $changed(policy_rsp_allow)
    );

    // Exercises consecutive policy requests carrying different trusted MANAGER\_ID values.
    cvr_distinct_manager_ids: cover property (
        f_history_valid && policy_req_hs &&
        (policy_req_manager_id != f_history_manager_id)
    );

    // Exercises consecutive policy requests carrying different SUBORDINATE\_ID values.
    cvr_distinct_subordinate_ids: cover property (
        f_history_valid && policy_req_hs &&
        (policy_req_subordinate_id != f_history_subordinate_id)
    );

    // Exercises one manager issuing transactions to different protected subordinates.
    cvr_one_manager_different_subordinates: cover property (
        f_history_valid && policy_req_hs &&
        (policy_req_manager_id == f_history_manager_id) &&
        (policy_req_subordinate_id != f_history_subordinate_id)
    );

    // Exercises both read and write transactions to the same protected subordinate.
    cvr_one_subordinate_read_and_write: cover property (
        f_history_valid && policy_req_hs &&
        (policy_req_subordinate_id == f_history_subordinate_id) &&
        (policy_req_is_write != f_history_is_write)
    );

    // Exercises a late revocation after an initial write or read transaction has been allowed.
    cvr_valid_late_revocation: cover property (
        policy_revoke_valid &&
        ((f_aw_decision_seen && f_aw_allowed) ||
         (f_ar_decision_seen && f_ar_allowed))
    );

    // Exercises write Allow and revocation on the same policy-response handshake, producing local
    // denial.
    cvr_simultaneous_write_allow_revoke_local_deny: cover property (
        policy_initial_revoke_hs && f_policy_is_write
        ##1 f_policy_initial_revoke && !f_aw_allowed &&
             !m_axi_awvalid && !m_axi_wvalid && !m_axi_bready
        ##[1:$] s_b_hs && (s_axi_bresp == AXI_RESP_DECERR)
    );

    // Exercises read Allow and revocation on the same policy-response handshake, producing local
    // denial.
    cvr_simultaneous_read_allow_revoke_local_deny: cover property (
        policy_initial_revoke_hs && !f_policy_is_write &&
        (f_r_expected > 9'd1)
        ##1 f_policy_initial_revoke && !f_ar_allowed &&
             !m_axi_arvalid && !m_axi_rready
        ##[1:$] s_r_hs && s_axi_rlast &&
                  (s_axi_rresp == AXI_RESP_DECERR)
    );

    // Exercises W-before-AW followed by simultaneous Allow/revocation and local write denial.
    cvr_w_before_aw_simultaneous_revoke_local_deny: cover property (
        s_w_hs && !s_aw_hs
        ##[1:$] s_aw_hs
        ##[1:$] policy_initial_revoke_hs &&
                  f_policy_is_write && f_w_pending
        ##1 f_policy_initial_revoke && !f_w_pending &&
             !m_axi_awvalid && !m_axi_wvalid
        ##[1:$] s_b_hs && (s_axi_bresp == AXI_RESP_DECERR)
    );

    // Exercises simultaneous Allow/revocation when a buffered final write beat is present,
    // followed by local DECERR.
    cvr_buffered_wlast_simultaneous_revoke_local_deny: cover property (
        policy_initial_revoke_hs && f_policy_is_write &&
        f_w_pending && f_w_last
        ##1 f_policy_initial_revoke && !f_w_pending &&
             !m_axi_awvalid && !m_axi_wvalid && !m_axi_bready
        ##1 s_b_hs && (s_axi_bid == f_awid) &&
             (s_axi_bresp == AXI_RESP_DECERR)
    );

    // Exercises simultaneous AW/W acceptance followed by simultaneous Allow/revocation and local
    // write denial.
    cvr_simultaneous_aw_w_initial_revoke_local_deny: cover property (
        s_aw_hs && s_w_hs
        ##[1:$] policy_initial_revoke_hs &&
                  f_policy_is_write && f_w_pending
        ##1 f_policy_initial_revoke && !f_w_pending &&
             !m_axi_awvalid && !m_axi_wvalid
        ##[1:$] s_b_hs && (s_axi_bresp == AXI_RESP_DECERR)
    );

    // Exercises a revocation before policy resolution and shows that no protected-side request is
    // released.
    cvr_predecision_revocation_is_ignored: cover property (
        f_policy_active && !f_policy_rsp_seen && !policy_rsp_hs &&
        policy_revoke_valid
        ##1 f_policy_active && !f_policy_rsp_seen &&
             !m_axi_awvalid && !m_axi_arvalid
    );

    // Exercises revocation while an already presented non-DECERR B response is stalled, preserving
    // that presented response.
    cvr_revoke_during_b_stall: cover property (
        s_axi_bvalid && !s_axi_bready &&
        (s_axi_bresp != AXI_RESP_DECERR)
        ##1 s_axi_bvalid && !s_axi_bready && policy_revoke_valid
        ##1 s_axi_bvalid && !s_axi_bready &&
             (s_axi_bresp != AXI_RESP_DECERR)
    );

    // Exercises policy Deny for an illegal write followed by local DECERR completion.
    cvr_illegal_write_deny: cover property (
        f_policy_active && f_policy_is_write && !f_policy_legal
        ##[1:$] policy_rsp_hs && !policy_rsp_allow
        ##[1:$] s_b_hs && (s_axi_bresp == AXI_RESP_DECERR)
    );

    // Exercises policy Deny for an illegal read followed by local DECERR completion.
    cvr_illegal_read_deny: cover property (
        f_policy_active && !f_policy_is_write && !f_policy_legal
        ##[1:$] policy_rsp_hs && !policy_rsp_allow
        ##[1:$] s_r_hs && s_axi_rlast &&
                  (s_axi_rresp == AXI_RESP_DECERR)
    );

    // Timeout and quarantine reachability. These covers add no progress
    // assumptions; a witness simply chooses progress on the relevant peers.
    generate
        if (POLICY_TIMEOUT_ENABLE) begin : g_timeout_covers
            if (POLICY_TIMEOUT_CYCLES > 1) begin : g_request_stall_timeout
            // Exercises timeout while the policy request is still waiting for request acceptance,
            // requiring no cancellation.
            cvr_timeout_waiting_policy_req_ready: cover property (
                policy_timeout_fire && policy_req_valid &&
                !policy_req_ready && !f_policy_req_seen
                ##1 f_policy_timed_out &&
                    !f_policy_timeout_after_req && !policy_cancel_valid
            );
            end

            if (POLICY_TIMEOUT_CYCLES > 2) begin : g_response_wait_timeout
            // Exercises timeout after request acceptance while waiting for a policy response,
            // entering cancellation quarantine.
            cvr_timeout_waiting_policy_rsp_valid: cover property (
                policy_timeout_fire && f_policy_req_seen &&
                !policy_rsp_valid
                ##1 f_policy_timed_out &&
                    f_policy_timeout_after_req && policy_cancel_valid
            );
            end

            if (POLICY_TIMEOUT_CYCLES > 4) begin : g_early_response
            // Exercises an effective Allow response before the final permitted policy cycle.
            cvr_timely_allow_before_timeout: cover property (
                policy_rsp_hs && policy_rsp_effective_allow &&
                !policy_timeout_final_cycle
            );

            // Exercises a Deny response before the final permitted policy cycle.
            cvr_timely_deny_before_timeout: cover property (
                policy_rsp_hs && !policy_rsp_allow && f_policy_legal &&
                !policy_timeout_final_cycle
            );
            end

            if (POLICY_TIMEOUT_CYCLES > 3) begin : g_deadline_response
            // Exercises an Allow response on the final permitted cycle and confirms that the
            // response wins over timeout.
            cvr_allow_on_final_permitted_cycle: cover property (
                policy_timeout_final_cycle && policy_rsp_hs &&
                policy_rsp_effective_allow
                ##1 f_policy_rsp_seen && !f_policy_timed_out
            );

            // Exercises a Deny response on the final permitted cycle and confirms that the
            // response wins over timeout.
            cvr_deny_on_final_permitted_cycle: cover property (
                policy_timeout_final_cycle && policy_rsp_hs &&
                !policy_rsp_allow && f_policy_legal
                ##1 f_policy_rsp_seen && !f_policy_timed_out
            );
            end

            // Exercises write timeout with no buffered W beat, draining to WLAST and returning
            // DECERR.
            cvr_write_timeout_without_buffered_w: cover property (
                policy_timeout_fire && policy_timeout_is_write &&
                !f_w_pending && !s_w_hs
                ##1 f_policy_timed_out
                ##[1:$] s_w_hs && s_axi_wlast
                ##2 s_b_hs && (s_axi_bresp == AXI_RESP_DECERR)
            );

            // Exercises write timeout with a buffered nonfinal W beat, discarding it and
            // completing locally with DECERR.
            cvr_write_timeout_with_buffered_nonfinal_w: cover property (
                policy_timeout_fire && policy_timeout_is_write &&
                f_w_pending && !f_w_last
                ##1 f_policy_timed_out && !f_w_pending
                ##[1:$] s_w_hs && s_axi_wlast
                ##2 s_b_hs && (s_axi_bresp == AXI_RESP_DECERR)
            );

            // Exercises write timeout with a buffered final W beat and local DECERR completion.
            cvr_write_timeout_with_buffered_wlast: cover property (
                policy_timeout_fire && policy_timeout_is_write &&
                f_w_pending && f_w_last
                ##2 s_b_hs && (s_axi_bid == f_awid) &&
                    (s_axi_bresp == AXI_RESP_DECERR)
            );

            if (POLICY_TIMEOUT_CYCLES > 1) begin : g_delayed_timeout_paths
            // Exercises W-before-AW followed by policy timeout and local write denial.
            cvr_w_before_aw_policy_timeout: cover property (
                s_w_hs && !s_aw_hs
                ##[1:$] s_aw_hs
                ##[1:$] policy_timeout_fire &&
                          policy_timeout_is_write && f_w_pending
                ##1 f_policy_timed_out && !f_w_pending
                ##[1:$] s_b_hs &&
                          (s_axi_bresp == AXI_RESP_DECERR)
            );

            // Exercises simultaneous AW/W acceptance followed by policy timeout and local write
            // denial.
            cvr_simultaneous_aw_w_policy_timeout: cover property (
                s_aw_hs && s_w_hs
                ##[1:$] policy_timeout_fire &&
                          policy_timeout_is_write && f_w_pending
                ##1 f_policy_timed_out && !f_w_pending
                ##[1:$] s_b_hs &&
                          (s_axi_bresp == AXI_RESP_DECERR)
            );

            // Exercises timeout of a single-beat read and zero-data DECERR completion.
            cvr_single_beat_read_timeout: cover property (
                s_ar_hs && (s_axi_arlen == 0)
                ##[1:$] policy_timeout_fire &&
                          !policy_timeout_is_write
                ##2 s_r_hs && s_axi_rlast &&
                    (s_axi_rdata == '0) &&
                    (s_axi_rresp == AXI_RESP_DECERR)
            );

            // Exercises timeout of a multibeat read and local DECERR completion through RLAST.
            cvr_multibeat_read_timeout: cover property (
                s_ar_hs && (s_axi_arlen > 0) &&
                (s_axi_arlen < 8'hff)
                ##[1:$] policy_timeout_fire &&
                          !policy_timeout_is_write
                ##[2:$] s_r_hs && s_axi_rlast &&
                          (s_axi_rresp == AXI_RESP_DECERR)
            );

            // Exercises timeout and complete local DECERR response for a 256-beat read.
            cvr_maximum_read_timeout_complete: cover property (
                s_ar_hs && (s_axi_arlen == 8'hff)
                ##[1:$] policy_timeout_fire &&
                          !policy_timeout_is_write
                ##[2:$] s_r_hs && s_axi_rlast &&
                          (f_s_r_count == 9'd255) &&
                          (s_axi_rresp == AXI_RESP_DECERR)
            );
            end

            if (POLICY_TIMEOUT_CYCLES > 1) begin : g_accepted_timeout_recovery
            // Exercises a late policy response after timeout while response acceptance is blocked
            // by quarantine.
            cvr_late_response_safely_quarantined: cover property (
                f_policy_timed_out && f_policy_timeout_after_req &&
                !f_policy_cancel_seen && policy_rsp_valid &&
                !policy_rsp_ready
            );

            // Exercises cancellation backpressure followed by a successful cancellation handshake.
            cvr_policy_cancel_backpressure_then_retire: cover property (
                policy_cancel_valid && !policy_cancel_ready
                ##1 policy_cancel_valid && !policy_cancel_ready
                ##1 policy_cancel_hs
            );

            // Exercises persistence of the retired-generation fence across multiple cycles.
            cvr_retirement_fence_multiple_cycles: cover property (
                f_policy_generation_retired && !policy_req_hs &&
                !policy_rsp_valid
                ##1 f_policy_generation_retired && !policy_req_hs &&
                    !policy_rsp_valid
            );

            // Exercises admission of a new transaction only after timed-out completion and
            // cancellation retirement.
            cvr_new_transaction_after_safe_retirement: cover property (
                f_policy_timed_out && f_policy_timeout_after_req &&
                policy_txn_complete_hs && !f_policy_cancel_seen
                ##[1:$] policy_cancel_hs
                ##1 (s_aw_hs || s_ar_hs)
            );

            // Exercises cancellation retirement before the local AXI denial has completed.
            cvr_cancel_before_local_completion: cover property (
                policy_cancel_hs && f_policy_timed_out &&
                !f_policy_axi_complete_seen
                ##[1:$] policy_txn_complete_hs
            );

            // Exercises cancellation and local AXI completion occurring in the same cycle.
            cvr_cancel_with_local_completion: cover property (
                policy_cancel_hs && policy_txn_complete_hs &&
                f_policy_timed_out
            );

            // Exercises policy-request acceptance on the timeout boundary, requiring cancellation
            // quarantine.
            cvr_request_accepts_on_timeout_boundary: cover property (
                policy_timeout_fire && policy_req_hs
                ##1 f_policy_timeout_after_req && policy_cancel_valid
            );

            // Exercises predecision revocation followed later by timeout, showing that the early
            // revocation does not become late revocation.
            cvr_revocation_before_timeout_is_ignored: cover property (
                f_policy_active && !f_policy_rsp_seen &&
                !f_policy_timed_out && policy_revoke_valid &&
                !policy_rsp_hs
                ##[1:$] policy_timeout_fire
                ##1 f_policy_timed_out &&
                    !f_write_revoked && !f_read_revoked
            );
            end
        end

        if (POLICY_TIMEOUT_ENABLE &&
            (POLICY_TIMEOUT_CYCLES == 1)) begin : g_timeout_one_cycle_covers
            // One-cycle-timeout-only cover: exercises simultaneous AW and final W acceptance
            // followed by local timeout DECERR.
            cvr_one_cycle_simultaneous_aw_wlast_timeout: cover property (
                s_aw_hs && s_w_hs && s_axi_wlast
                ##2 s_b_hs && (s_axi_bresp == AXI_RESP_DECERR)
            );
        end

        if (POLICY_TIMEOUT_ENABLE &&
            (POLICY_TIMEOUT_CYCLES == 2)) begin : g_timeout_two_cycle_covers
            // Two-cycle-timeout-only cover: exercises timeout with a stalled policy request on the
            // next clock edge after AW acceptance.
            cvr_two_cycle_stalled_request_timeout: cover property (
                s_aw_hs
                ##1 policy_timeout_fire && policy_req_valid &&
                    !policy_req_ready
            );

            // Two-cycle-timeout-only cover: exercises request acceptance on the read timeout
            // boundary followed by cancellation quarantine.
            cvr_two_cycle_boundary_request_quarantine: cover property (
                s_ar_hs
                ##1 policy_timeout_fire && policy_req_hs
                ##1 policy_cancel_valid
            );
        end
    endgenerate

endmodule

