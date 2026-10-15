`timescale 1ns / 1ps

// =============================================================================
// File        : axi_firewall.sv
// Module      : axi_firewall
// Purpose     : Transaction-level AXI4 security firewall with burst-footprint
//               validation, serialized external policy authorization, local
//               fail-closed responses, and late-revocation enforcement.
//
// Integration contract:
//   - Receives one arbitrated manager transaction at its s_axi interface;
//     the integrated wrapper replaces the manager-controlled identity field
//     with the trusted physical-port MANAGER_ID before it reaches this module.
//   - An untagged policy channel serializes authorization. Protected-subordinate
//     selection is handled by the integrated downstream decoder, not this RTL.
//   - External policy decisions and compliant AXI4 peers are environmental
//     contracts; this module does not implement the automotive policy algorithm.
//
// =============================================================================

// AXI4 policy-enforcement point.
//
// The external policy interface is untagged. Consequently, this implementation
// permits only one complete read or write transaction at a time. AW/W has
// priority over AR while idle. An accepted address creates one registered
// policy request; no downstream address or data is issued until one registered
// policy response has been accepted. Local burst legality always overrides an
// external Allow response.
//
// A revocation sampled with an Allow response vetoes initial authorization and
// selects the local denial path. After an effective initial Allow, the same
// valid-qualified input is a late revocation. To preserve AXI payload
// stability, the revocation decision for a beat is locked when that beat is
// first presented. A later revocation poisons only beats not yet presented and
// cannot roll back a write beat that has already handshaken downstream.
// The security interpretation of a poisoned beat requires the subordinate to
// treat WSTRB=='0 as having no externally visible byte or MMIO side effect.
// Reset aborts local ownership, so the system reset contract must flush any
// downstream response and every outstanding policy request, response,
// cancellation, or quarantine record. A revocation before the policy-response
// handshake is ignored, a response-coincident revocation vetoes Allow, and a
// later revocation refers only to the current initially authorized transaction.
//
// With policy timeout enabled, the address-acceptance edge is counted as
// unresolved cycle one. The final permitted edge is therefore N-1 edges after
// acceptance. A policy-response handshake on that edge wins; without one, the
// transaction is locally denied. If the request had already handshaken, the
// untagged policy channel is quarantined until policy_cancel_valid/ready retires
// the old request and guarantees that it can no longer produce a response.

module axi_firewall #(
    parameter int AXI_ID_W       = 4,
    parameter int AXI_ADDR_W     = 32,
    parameter int AXI_DATA_W     = 32,
    parameter int AXI_STRB_W     = AXI_DATA_W / 8,
    parameter int MANAGER_ID_W    = 4,
    parameter int SUBORDINATE_ID_W  = 8,
    parameter int AXI_USER_W     = MANAGER_ID_W + SUBORDINATE_ID_W,
    parameter bit POLICY_TIMEOUT_ENABLE = 1'b1,
    parameter int unsigned POLICY_TIMEOUT_CYCLES = 32,
    // Formal-only composition selector. The default preserves the standalone
    // checker contract; the integrated wrapper sets this so AXI peer contracts
    // at the firewall boundary are proved instead of assumed.
    parameter bit SVA_INTEGRATION_MODE = 1'b0
) (
    input  logic                    clk,
    input  logic                    rst_n,

    // Policy request: captured owner identity, selected subordinate metadata,
    // operation, and inclusive full-burst address envelope.
    output logic                    policy_req_valid,
    input  logic                    policy_req_ready,
    output logic [MANAGER_ID_W-1:0]  policy_req_manager_id,
    output logic [SUBORDINATE_ID_W-1:0] policy_req_subordinate_id,
    output logic                    policy_req_is_write,
    output logic [AXI_ADDR_W-1:0]   policy_req_start_addr,
    output logic [AXI_ADDR_W-1:0]   policy_req_end_addr,

    // Response is meaningful only on policy_rsp_valid && policy_rsp_ready.
    input  logic                    policy_rsp_valid,
    output logic                    policy_rsp_ready,
    input  logic                    policy_rsp_allow,

    // A cancel handshake acknowledges permanent retirement of the sole
    // accepted request and every response associated with it.
    output logic                    policy_cancel_valid,
    input  logic                    policy_cancel_ready,

    // Revocation is evaluated separately from the registered policy decision.
    input  logic                    policy_revoke_valid,

    // Upstream (arbitrated-manager) AXI4 write-address/data/response channels.
    input  logic [AXI_ID_W-1:0]     s_axi_awid,
    input  logic [AXI_ADDR_W-1:0]   s_axi_awaddr,
    input  logic [7:0]              s_axi_awlen,
    input  logic [2:0]              s_axi_awsize,
    input  logic [1:0]              s_axi_awburst,
    input  logic [AXI_USER_W-1:0]   s_axi_awuser,
    input  logic                    s_axi_awvalid,
    output logic                    s_axi_awready,

    input  logic [AXI_DATA_W-1:0]   s_axi_wdata,
    input  logic [AXI_STRB_W-1:0]   s_axi_wstrb,
    input  logic                    s_axi_wlast,
    input  logic                    s_axi_wvalid,
    output logic                    s_axi_wready,

    output logic [AXI_ID_W-1:0]     s_axi_bid,
    output logic [1:0]              s_axi_bresp,
    output logic                    s_axi_bvalid,
    input  logic                    s_axi_bready,

    // Downstream AXI4 write channels toward the integrated routing decoder.
    output logic [AXI_ID_W-1:0]     m_axi_awid,
    output logic [AXI_ADDR_W-1:0]   m_axi_awaddr,
    output logic [7:0]              m_axi_awlen,
    output logic [2:0]              m_axi_awsize,
    output logic [1:0]              m_axi_awburst,
    output logic [AXI_USER_W-1:0]   m_axi_awuser,
    output logic                    m_axi_awvalid,
    input  logic                    m_axi_awready,

    output logic [AXI_DATA_W-1:0]   m_axi_wdata,
    output logic [AXI_STRB_W-1:0]   m_axi_wstrb,
    output logic                    m_axi_wlast,
    output logic                    m_axi_wvalid,
    input  logic                    m_axi_wready,

    input  logic [AXI_ID_W-1:0]     m_axi_bid,
    input  logic [1:0]              m_axi_bresp,
    input  logic                    m_axi_bvalid,
    output logic                    m_axi_bready,

    // Upstream AXI4 read address channel.
    input  logic [AXI_ID_W-1:0]     s_axi_arid,
    input  logic [AXI_ADDR_W-1:0]   s_axi_araddr,
    input  logic [7:0]              s_axi_arlen,
    input  logic [2:0]              s_axi_arsize,
    input  logic [1:0]              s_axi_arburst,
    input  logic [AXI_USER_W-1:0]   s_axi_aruser,
    input  logic                    s_axi_arvalid,
    output logic                    s_axi_arready,

    // Downstream AXI4 read address/data channels.
    output logic [AXI_ID_W-1:0]     m_axi_arid,
    output logic [AXI_ADDR_W-1:0]   m_axi_araddr,
    output logic [7:0]              m_axi_arlen,
    output logic [2:0]              m_axi_arsize,
    output logic [1:0]              m_axi_arburst,
    output logic [AXI_USER_W-1:0]   m_axi_aruser,
    output logic                    m_axi_arvalid,
    input  logic                    m_axi_arready,

    input  logic [AXI_ID_W-1:0]     m_axi_rid,
    input  logic [AXI_DATA_W-1:0]   m_axi_rdata,
    input  logic [1:0]              m_axi_rresp,
    input  logic                    m_axi_rlast,
    input  logic                    m_axi_rvalid,
    output logic                    m_axi_rready,

    output logic [AXI_ID_W-1:0]     s_axi_rid,
    output logic [AXI_DATA_W-1:0]   s_axi_rdata,
    output logic [1:0]              s_axi_rresp,
    output logic                    s_axi_rlast,
    output logic                    s_axi_rvalid,
    input  logic                    s_axi_rready
);

    // Derived widths for overflow-safe burst envelopes and inclusive timeout
    // counting. The encoded AXI length allows up to 256 beats.
    localparam logic [1:0] AXI_RESP_DECERR = 2'b11;
    // AXI's maximum encoded burst span is 256 beats * 128 bytes = 2^15.
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

    generate
        if (POLICY_TIMEOUT_ENABLE && (POLICY_TIMEOUT_CYCLES == 0)) begin : g_bad_policy_timeout
            initial $fatal(1,
                "POLICY_TIMEOUT_CYCLES must be greater than zero when enabled");
        end
    endgenerate

    // Return the inclusive byte-address envelope of a legal AXI burst. Reserved
    // burst encodings conservatively expose the entire address space.
    function automatic logic [AXI_ADDR_W-1:0] burst_start_addr(
        input logic [AXI_ADDR_W-1:0] addr,
        input logic [7:0]            len,
        input logic [2:0]            size,
        input logic [1:0]            burst
    );
        logic [RANGE_W-1:0] addr_x;
        logic [RANGE_W-1:0] span_bytes;
        logic [RANGE_W-1:0] wrap_base;
        begin
            addr_x     = {{(RANGE_W-AXI_ADDR_W){1'b0}}, addr};
            span_bytes = ({{(RANGE_W-8){1'b0}}, len} + 1'b1) << size;
            wrap_base  = addr_x & ~(span_bytes - 1'b1);

            case (burst)
                2'b00, 2'b01: burst_start_addr = addr;
                2'b10:        burst_start_addr = wrap_base[AXI_ADDR_W-1:0];
                default:      burst_start_addr = '0;
            endcase
        end
    endfunction

    // The end address is computed in an extended width to detect overflow;
    // unaligned INCR bursts use the aligned first-beat base and full span.
    function automatic logic [AXI_ADDR_W-1:0] burst_end_addr(
        input logic [AXI_ADDR_W-1:0] addr,
        input logic [7:0]            len,
        input logic [2:0]            size,
        input logic [1:0]            burst
    );
        logic [RANGE_W-1:0] addr_x;
        logic [RANGE_W-1:0] beat_bytes;
        logic [RANGE_W-1:0] span_bytes;
        logic [RANGE_W-1:0] aligned_addr;
        logic [RANGE_W-1:0] wrap_base;
        logic [RANGE_W-1:0] end_x;
        begin
            addr_x       = {{(RANGE_W-AXI_ADDR_W){1'b0}}, addr};
            beat_bytes   = {{(RANGE_W-1){1'b0}}, 1'b1} << size;
            span_bytes   = ({{(RANGE_W-8){1'b0}}, len} + 1'b1) << size;
            aligned_addr = addr_x & ~(beat_bytes - 1'b1);
            wrap_base    = addr_x & ~(span_bytes - 1'b1);

            case (burst)
                2'b00:   end_x = aligned_addr + beat_bytes - 1'b1;
                2'b01:   end_x = aligned_addr + span_bytes - 1'b1;
                2'b10:   end_x = wrap_base + span_bytes - 1'b1;
                default: end_x = {RANGE_W{1'b1}};
            endcase

            if (|end_x[RANGE_W-1:AXI_ADDR_W])
                burst_end_addr = {AXI_ADDR_W{1'b1}};
            else
                burst_end_addr = end_x[AXI_ADDR_W-1:0];
        end
    endfunction

    // Validate transfer size, burst encoding/length and WRAP alignment, plus
    // address overflow and the AXI 4-KiB boundary restriction.
    function automatic logic burst_legal(
        input logic [AXI_ADDR_W-1:0] addr,
        input logic [7:0]            len,
        input logic [2:0]            size,
        input logic [1:0]            burst
    );
        logic [RANGE_W-1:0] addr_x;
        logic [RANGE_W-1:0] beat_bytes;
        logic [RANGE_W-1:0] span_bytes;
        logic [RANGE_W-1:0] aligned_addr;
        logic [RANGE_W-1:0] wrap_base;
        logic [RANGE_W-1:0] first_x;
        logic [RANGE_W-1:0] last_x;
        begin
            addr_x       = {{(RANGE_W-AXI_ADDR_W){1'b0}}, addr};
            beat_bytes   = {{(RANGE_W-1){1'b0}}, 1'b1} << size;
            span_bytes   = ({{(RANGE_W-8){1'b0}}, len} + 1'b1) << size;
            aligned_addr = addr_x & ~(beat_bytes - 1'b1);
            wrap_base    = addr_x & ~(span_bytes - 1'b1);
            first_x      = addr_x;
            last_x       = addr_x;
            burst_legal  = 1'b1;

            if (beat_bytes > AXI_STRB_W)
                burst_legal = 1'b0;

            case (burst)
                2'b00: begin
                    last_x = aligned_addr + beat_bytes - 1'b1;
                    if (len > 8'd15)
                        burst_legal = 1'b0;
                end
                2'b01: begin
                    last_x = aligned_addr + span_bytes - 1'b1;
                end
                2'b10: begin
                    first_x = wrap_base;
                    last_x  = wrap_base + span_bytes - 1'b1;
                    if (!((len == 8'd1) || (len == 8'd3) ||
                          (len == 8'd7) || (len == 8'd15)))
                        burst_legal = 1'b0;
                    if ((addr_x & (beat_bytes - 1'b1)) != '0)
                        burst_legal = 1'b0;
                end
                default: burst_legal = 1'b0;
            endcase

            if (|last_x[RANGE_W-1:AXI_ADDR_W])
                burst_legal = 1'b0;
            if ((first_x >> 12) != (last_x >> 12))
                burst_legal = 1'b0;
        end
    endfunction

    // Illegal bursts have a deliberately invalid policy range (all addresses)
    // so that an external ALLOW can never override local legality checking.
    function automatic logic [AXI_ADDR_W-1:0] policy_start_addr(
        input logic [AXI_ADDR_W-1:0] addr,
        input logic [7:0]            len,
        input logic [2:0]            size,
        input logic [1:0]            burst
    );
        begin
            policy_start_addr = burst_legal(addr, len, size, burst) ?
                                burst_start_addr(addr, len, size, burst) : '0;
        end
    endfunction

    function automatic logic [AXI_ADDR_W-1:0] policy_end_addr(
        input logic [AXI_ADDR_W-1:0] addr,
        input logic [7:0]            len,
        input logic [2:0]            size,
        input logic [1:0]            burst
    );
        begin
            policy_end_addr = burst_legal(addr, len, size, burst) ?
                              burst_end_addr(addr, len, size, burst) :
                              {AXI_ADDR_W{1'b1}};
        end
    endfunction

    // All transaction and policy state transitions use completed VALID/READY
    // handshakes; accepted upstream address starts the policy deadline.
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

    // Untagged policy protocol: request, registered response-ready phase,
    // resolved decision, or quarantine awaiting cancellation retirement.
    typedef enum logic [2:0] {
        POLICY_IDLE,
        POLICY_REQUEST,
        POLICY_RESPONSE_WAIT,
        POLICY_RESPONSE_READY,
        POLICY_RESOLVED,
        POLICY_QUARANTINE
    } policy_phase_t;

    policy_phase_t                 policy_phase;
    logic [MANAGER_ID_W-1:0]        policy_ctx_manager_id;
    logic [SUBORDINATE_ID_W-1:0]      policy_ctx_subordinate_id;
    logic                          policy_ctx_is_write;
    logic [AXI_ADDR_W-1:0]         policy_ctx_start_addr;
    logic [AXI_ADDR_W-1:0]         policy_ctx_end_addr;
    logic                          policy_ctx_legal;
    logic                          policy_timeout_active;
    logic [POLICY_TIMEOUT_CNT_W-1:0] policy_timeout_count;

    wire policy_timeout_final_cycle = POLICY_TIMEOUT_ENABLE &&
        ((policy_addr_hs && (POLICY_TIMEOUT_CYCLES == 1)) ||
         (policy_timeout_active &&
          (policy_timeout_count == POLICY_TIMEOUT_LAST_COUNT)));
    // Response acceptance has priority on the final permitted edge.
    wire policy_timeout_fire = policy_timeout_final_cycle &&
                               !policy_rsp_hs;
    wire policy_timeout_is_write = policy_timeout_active ?
                                   policy_ctx_is_write : s_aw_hs;
    wire policy_timeout_request_accepted =
        (policy_phase == POLICY_RESPONSE_WAIT) ||
        (policy_phase == POLICY_RESPONSE_READY) || policy_req_hs;
    wire policy_timeout_write_fire = policy_timeout_fire &&
                                     policy_timeout_is_write;
    wire policy_timeout_read_fire = policy_timeout_fire &&
                                    !policy_timeout_is_write;

    // A response ALLOW becomes effective only for a legal burst without a
    // same-cycle revoke; otherwise write/read logic follows initial denial.
    wire policy_rsp_effective_allow = policy_rsp_allow &&
                                      policy_ctx_legal &&
                                      !policy_revoke_valid;
    wire policy_write_initial_deny_hs = policy_rsp_hs &&
                                        policy_ctx_is_write &&
                                        !policy_rsp_effective_allow;

    // Write transaction state.
    logic                    active_txn;
    logic                    aw_received;
    logic                    aw_authorized;
    logic                    early_denied;
    logic                    late_denied;
    logic                    aw_pending;
    logic                    aw_forwarded;
    logic                    w_done;
    logic                    w_forward_done;
    logic [AXI_ID_W-1:0]     active_awid;
    logic [AXI_ADDR_W-1:0]   active_awaddr;
    logic [7:0]              active_awlen;
    logic [2:0]              active_awsize;
    logic [1:0]              active_awburst;
    logic [AXI_USER_W-1:0]   active_awuser;

    // One-entry W-before-AW and downstream W output stage.
    // Capture one upstream W beat, even before AW; arm its fixed output strobe
    // only when the authorized downstream address has been accepted.
    logic                    w_buf_valid;
    logic                    w_buf_armed;
    logic [AXI_DATA_W-1:0]   w_buf_data;
    logic [AXI_STRB_W-1:0]   w_buf_strb;
    logic [AXI_STRB_W-1:0]   w_buf_out_strb;
    logic                    w_buf_last;

    // Registered upstream write response.
    logic                    b_rsp_valid;
    logic [AXI_ID_W-1:0]     b_rsp_id;
    logic [1:0]              b_rsp_resp;

    // Read transaction and registered upstream R response state.
    logic                    read_active;
    logic                    ar_authorized;
    logic                    read_denied;
    logic                    read_revoked;
    logic                    ar_pending;
    logic                    ar_forwarded;
    logic [8:0]              read_beats_left;
    logic [AXI_ID_W-1:0]     active_arid;
    logic [AXI_ADDR_W-1:0]   active_araddr;
    logic [7:0]              active_arlen;
    logic [2:0]              active_arsize;
    logic [1:0]              active_arburst;
    logic [AXI_USER_W-1:0]   active_aruser;
    // A single registered R beat isolates downstream capture from upstream
    // backpressure. The register retains an already presented beat unchanged.
    logic                    r_rsp_valid;
    logic [AXI_ID_W-1:0]     r_rsp_id;
    logic [AXI_DATA_W-1:0]   r_rsp_data;
    logic [1:0]              r_rsp_resp;
    logic                    r_rsp_last;

    // Unified untagged policy channel. Context is captured only with AW or AR;
    // W-before-AW ownership alone leaves the policy interface idle. The
    // RESPONSE_WAIT phase deliberately registers response readiness, so neither
    // policy channel can form a combinational READY/VALID loop. QUARANTINE never
    // accepts a response: cancellation acknowledgement is the external contract
    // that the accepted old request and any associated response are retired.
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            policy_phase           <= POLICY_IDLE;
            policy_ctx_manager_id   <= '0;
            policy_ctx_subordinate_id <= '0;
            policy_ctx_is_write    <= 1'b0;
            policy_ctx_start_addr  <= '0;
            policy_ctx_end_addr    <= '0;
            policy_ctx_legal       <= 1'b0;
        end
        else if (policy_txn_complete_hs) begin
            // Local timeout completion is independent of stale-response
            // retirement. Preserve quarantine until cancellation is accepted.
            if ((policy_phase == POLICY_QUARANTINE) &&
                !policy_cancel_hs) begin
                policy_phase <= POLICY_QUARANTINE;
            end
            else begin
                policy_phase           <= POLICY_IDLE;
                policy_ctx_manager_id   <= '0;
                policy_ctx_subordinate_id <= '0;
                policy_ctx_is_write    <= 1'b0;
                policy_ctx_start_addr  <= '0;
                policy_ctx_end_addr    <= '0;
                policy_ctx_legal       <= 1'b0;
            end
        end
        // Decision acceptance has precedence over timeout at the deadline.
        else if (policy_rsp_hs) begin
            // A handshake on the deadline edge wins over timeout.
            policy_phase <= POLICY_RESOLVED;
        end
        // Timeout before request acceptance needs no cancellation. An accepted
        // unanswered request instead enters quarantine until retirement.
        else if (policy_timeout_fire) begin
            policy_phase <= policy_timeout_request_accepted ?
                            POLICY_QUARANTINE : POLICY_RESOLVED;
        end
        else if (policy_cancel_hs) begin
            policy_phase           <= POLICY_IDLE;
            policy_ctx_manager_id   <= '0;
            policy_ctx_subordinate_id <= '0;
            policy_ctx_is_write    <= 1'b0;
            policy_ctx_start_addr  <= '0;
            policy_ctx_end_addr    <= '0;
            policy_ctx_legal       <= 1'b0;
        end
        else begin
            case (policy_phase)
                POLICY_IDLE: begin
                    if (s_aw_hs) begin
                        policy_phase <= POLICY_REQUEST;
                        policy_ctx_manager_id <=
                            s_axi_awuser[AXI_USER_W-1 -: MANAGER_ID_W];
                        policy_ctx_subordinate_id <=
                            s_axi_awuser[SUBORDINATE_ID_W-1:0];
                        policy_ctx_is_write   <= 1'b1;
                        policy_ctx_start_addr <= policy_start_addr(
                            s_axi_awaddr, s_axi_awlen,
                            s_axi_awsize, s_axi_awburst);
                        policy_ctx_end_addr <= policy_end_addr(
                            s_axi_awaddr, s_axi_awlen,
                            s_axi_awsize, s_axi_awburst);
                        policy_ctx_legal <= burst_legal(
                            s_axi_awaddr, s_axi_awlen,
                            s_axi_awsize, s_axi_awburst);
                    end
                    else if (s_ar_hs) begin
                        policy_phase <= POLICY_REQUEST;
                        policy_ctx_manager_id <=
                            s_axi_aruser[AXI_USER_W-1 -: MANAGER_ID_W];
                        policy_ctx_subordinate_id <=
                            s_axi_aruser[SUBORDINATE_ID_W-1:0];
                        policy_ctx_is_write   <= 1'b0;
                        policy_ctx_start_addr <= policy_start_addr(
                            s_axi_araddr, s_axi_arlen,
                            s_axi_arsize, s_axi_arburst);
                        policy_ctx_end_addr <= policy_end_addr(
                            s_axi_araddr, s_axi_arlen,
                            s_axi_arsize, s_axi_arburst);
                        policy_ctx_legal <= burst_legal(
                            s_axi_araddr, s_axi_arlen,
                            s_axi_arsize, s_axi_arburst);
                    end
                end

                POLICY_REQUEST: begin
                    if (policy_req_hs)
                        policy_phase <= POLICY_RESPONSE_WAIT;
                end

                POLICY_RESPONSE_WAIT: begin
                    policy_phase <= POLICY_RESPONSE_READY;
                end

                POLICY_RESPONSE_READY,
                POLICY_RESOLVED,
                POLICY_QUARANTINE: policy_phase <= policy_phase;

                default: begin
                    policy_phase <= policy_phase;
                end
            endcase
        end
    end

    // The counter stores the number of unresolved cycles already counted. It
    // starts at one on address acceptance and can reach only N-1; expiration or
    // a timely response clears it before an increment could wrap.
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            policy_timeout_active <= 1'b0;
            policy_timeout_count  <= '0;
        end
        else if (policy_txn_complete_hs) begin
            policy_timeout_active <= 1'b0;
            policy_timeout_count  <= '0;
        end
        else if (policy_rsp_hs) begin
            policy_timeout_active <= 1'b0;
            policy_timeout_count  <= '0;
        end
        else if (policy_timeout_fire) begin
            policy_timeout_active <= 1'b0;
            policy_timeout_count  <= '0;
        end
        else if (policy_addr_hs && POLICY_TIMEOUT_ENABLE &&
                 (POLICY_TIMEOUT_CYCLES > 1)) begin
            policy_timeout_active <= 1'b1;
            policy_timeout_count  <= POLICY_TIMEOUT_COUNT_ONE;
        end
        else if (policy_timeout_active) begin
            policy_timeout_count <= policy_timeout_count +
                                    POLICY_TIMEOUT_COUNT_ONE;
        end
    end

    // Outputs are neutral outside their matching policy phases. In particular,
    // QUARANTINE asserts CANCEL, not response readiness or a new request.
    always_comb begin
        policy_req_valid       = 1'b0;
        policy_req_manager_id   = '0;
        policy_req_subordinate_id = '0;
        policy_req_is_write    = 1'b0;
        policy_req_start_addr  = '0;
        policy_req_end_addr    = '0;
        policy_rsp_ready       = 1'b0;
        policy_cancel_valid    = 1'b0;

        if (rst_n && (policy_phase == POLICY_REQUEST)) begin
            policy_req_valid       = 1'b1;
            policy_req_manager_id   = policy_ctx_manager_id;
            policy_req_subordinate_id = policy_ctx_subordinate_id;
            policy_req_is_write    = policy_ctx_is_write;
            policy_req_start_addr  = policy_ctx_start_addr;
            policy_req_end_addr    = policy_ctx_end_addr;
        end

        if (rst_n && (policy_phase == POLICY_RESPONSE_READY))
            policy_rsp_ready = 1'b1;

        if (rst_n && (policy_phase == POLICY_QUARANTINE))
            policy_cancel_valid = 1'b1;
    end

    // One policy owner at a time. Address requests are accepted into local
    // holding registers rather than being coupled to downstream READY.
    assign s_axi_awready = rst_n && (policy_phase == POLICY_IDLE) &&
                           !read_active && !aw_received;
    assign s_axi_arready = rst_n && !active_txn && !read_active &&
                           (policy_phase == POLICY_IDLE) &&
                           !s_axi_awvalid && !s_axi_wvalid;

    // Denied writes drain remaining upstream W beats through WLAST without
    // filling the output buffer; non-denied writes observe one-entry capacity.
    always_comb begin
        s_axi_wready = 1'b0;
        if (rst_n && !read_active &&
            (active_txn || (policy_phase == POLICY_IDLE))) begin
            if (early_denied)
                s_axi_wready = !w_done;
            else
                s_axi_wready = !w_done && !w_buf_valid;
        end
    end

    // Write address holding register and local B response register.
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            active_txn      <= 1'b0;
            aw_received     <= 1'b0;
            aw_authorized   <= 1'b0;
            early_denied    <= 1'b0;
            late_denied     <= 1'b0;
            aw_pending      <= 1'b0;
            aw_forwarded    <= 1'b0;
            w_done          <= 1'b0;
            w_forward_done  <= 1'b0;
            active_awid     <= '0;
            active_awaddr   <= '0;
            active_awlen    <= '0;
            active_awsize   <= '0;
            active_awburst  <= '0;
            active_awuser   <= '0;
            b_rsp_valid     <= 1'b0;
            b_rsp_id        <= '0;
            b_rsp_resp      <= '0;
        end
        else if (s_b_hs) begin
            active_txn      <= 1'b0;
            aw_received     <= 1'b0;
            aw_authorized   <= 1'b0;
            early_denied    <= 1'b0;
            late_denied     <= 1'b0;
            aw_pending      <= 1'b0;
            aw_forwarded    <= 1'b0;
            w_done          <= 1'b0;
            w_forward_done  <= 1'b0;
            active_awid     <= '0;
            active_awaddr   <= '0;
            active_awlen    <= '0;
            active_awsize   <= '0;
            active_awburst  <= '0;
            active_awuser   <= '0;
            b_rsp_valid     <= 1'b0;
            b_rsp_id        <= '0;
            b_rsp_resp      <= '0;
        end
        else begin
            if (!active_txn && (s_aw_hs || s_w_hs))
                active_txn <= 1'b1;

            if (s_aw_hs) begin
                active_txn     <= 1'b1;
                aw_received    <= 1'b1;
                aw_authorized  <= 1'b0;
                early_denied   <= 1'b0;
                late_denied    <= 1'b0;
                aw_pending     <= 1'b0;
                aw_forwarded   <= 1'b0;
                active_awid    <= s_axi_awid;
                active_awaddr  <= s_axi_awaddr;
                active_awlen   <= s_axi_awlen;
                active_awsize  <= s_axi_awsize;
                active_awburst <= s_axi_awburst;
                active_awuser  <= s_axi_awuser;
            end

            // Effective authorization releases the captured AW; an initial
            // denial or timeout keeps downstream AW/W isolated.
            if (policy_rsp_hs && policy_ctx_is_write) begin
                aw_authorized <= policy_rsp_effective_allow;
                early_denied  <= !policy_rsp_effective_allow;
                late_denied   <= 1'b0;
                aw_pending    <= policy_rsp_effective_allow;
            end
            else if (policy_timeout_write_fire) begin
                aw_authorized <= 1'b0;
                early_denied  <= 1'b1;
                late_denied   <= 1'b0;
                aw_pending    <= 1'b0;
            end

            if (m_aw_hs) begin
                aw_pending   <= 1'b0;
                aw_forwarded <= 1'b1;
            end

            if (s_w_hs && s_axi_wlast)
                w_done <= 1'b1;

            if (active_txn && aw_received && aw_authorized &&
                !early_denied && policy_revoke_valid)
                late_denied <= 1'b1;

            if (m_w_hs && m_axi_wlast)
                w_forward_done <= 1'b1;

            // Initial denial synthesizes local DECERR after WLAST. Authorized
            // writes capture subordinate BRESP unless late revocation overrides it.
            if (!b_rsp_valid) begin
                if (early_denied && w_done) begin
                    b_rsp_valid <= 1'b1;
                    b_rsp_id    <= active_awid;
                    b_rsp_resp  <= AXI_RESP_DECERR;
                end
                else if (m_b_hs) begin
                    b_rsp_valid <= 1'b1;
                    b_rsp_id    <= active_awid;
                    b_rsp_resp  <= (late_denied || policy_revoke_valid) ?
                                   AXI_RESP_DECERR : m_axi_bresp;
                end
            end
        end
    end

    // Every upstream W beat uses this output stage. The effective WSTRB is
    // selected before M_WVALID rises and is immutable until handshake.
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            w_buf_valid      <= 1'b0;
            w_buf_armed      <= 1'b0;
            w_buf_data       <= '0;
            w_buf_strb       <= '0;
            w_buf_out_strb   <= '0;
            w_buf_last       <= 1'b0;
        end
        else if (s_b_hs || early_denied ||
                 policy_write_initial_deny_hs ||
                 policy_timeout_write_fire) begin
            w_buf_valid      <= 1'b0;
            w_buf_armed      <= 1'b0;
            w_buf_data       <= '0;
            w_buf_strb       <= '0;
            w_buf_out_strb   <= '0;
            w_buf_last       <= 1'b0;
        end
        else if (s_w_hs) begin
            w_buf_valid      <= 1'b1;
            w_buf_armed      <= 1'b0;
            w_buf_data       <= s_axi_wdata;
            w_buf_strb       <= s_axi_wstrb;
            w_buf_out_strb   <= '0;
            w_buf_last       <= s_axi_wlast;
        end
        else if (m_w_hs) begin
            w_buf_valid      <= 1'b0;
            w_buf_armed      <= 1'b0;
            w_buf_data       <= '0;
            w_buf_strb       <= '0;
            w_buf_out_strb   <= '0;
            w_buf_last       <= 1'b0;
        end
        // Latch the byte strobes when the output beat is first presented;
        // revocation cannot alter a beat already stalled with WVALID asserted.
        else if (w_buf_valid && !w_buf_armed && aw_authorized &&
                 aw_forwarded && !early_denied) begin
            w_buf_armed    <= 1'b1;
            w_buf_out_strb <= (late_denied || policy_revoke_valid) ?
                              '0 : w_buf_strb;
        end
    end

    // Write forwarding is enabled only by effective authorization; the
    // registered upstream B response completes ownership on its handshake.
    assign m_axi_awid    = active_awid;
    assign m_axi_awaddr  = active_awaddr;
    assign m_axi_awlen   = active_awlen;
    assign m_axi_awsize  = active_awsize;
    assign m_axi_awburst = active_awburst;
    assign m_axi_awuser  = active_awuser;
    assign m_axi_awvalid = rst_n && aw_pending;

    assign m_axi_wdata   = w_buf_data;
    assign m_axi_wstrb   = w_buf_out_strb;
    assign m_axi_wlast   = w_buf_last;
    assign m_axi_wvalid  = rst_n && active_txn && aw_authorized &&
                           aw_forwarded && w_buf_valid && w_buf_armed;

    assign m_axi_bready  = rst_n && active_txn && aw_authorized &&
                           aw_forwarded && w_forward_done && !b_rsp_valid;

    assign s_axi_bid     = b_rsp_id;
    assign s_axi_bresp   = b_rsp_resp;
    assign s_axi_bvalid  = rst_n && b_rsp_valid;

    // Read address holding register, response counter, and R output stage.
    // Denied bursts receive exactly ARLEN+1 zero-data DECERR beats.
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            read_active      <= 1'b0;
            ar_authorized    <= 1'b0;
            read_denied      <= 1'b0;
            read_revoked     <= 1'b0;
            ar_pending       <= 1'b0;
            ar_forwarded     <= 1'b0;
            read_beats_left  <= '0;
            active_arid      <= '0;
            active_araddr    <= '0;
            active_arlen     <= '0;
            active_arsize    <= '0;
            active_arburst   <= '0;
            active_aruser    <= '0;
            r_rsp_valid      <= 1'b0;
            r_rsp_id         <= '0;
            r_rsp_data       <= '0;
            r_rsp_resp       <= '0;
            r_rsp_last       <= 1'b0;
        end
        else begin
            if (s_ar_hs) begin
                read_active     <= 1'b1;
                ar_authorized   <= 1'b0;
                read_denied     <= 1'b0;
                read_revoked    <= 1'b0;
                ar_pending      <= 1'b0;
                ar_forwarded    <= 1'b0;
                read_beats_left <= {1'b0, s_axi_arlen} + 9'd1;
                active_arid     <= s_axi_arid;
                active_araddr   <= s_axi_araddr;
                active_arlen    <= s_axi_arlen;
                active_arsize   <= s_axi_arsize;
                active_arburst  <= s_axi_arburst;
                active_aruser   <= s_axi_aruser;
            end

            if (policy_rsp_hs && !policy_ctx_is_write) begin
                ar_authorized <= policy_rsp_effective_allow;
                read_denied   <= !policy_rsp_effective_allow;
                read_revoked  <= 1'b0;
                ar_pending    <= policy_rsp_effective_allow;
            end
            else if (policy_timeout_read_fire) begin
                ar_authorized <= 1'b0;
                read_denied   <= 1'b1;
                read_revoked  <= 1'b0;
                ar_pending    <= 1'b0;
            end

            if (m_ar_hs) begin
                ar_pending   <= 1'b0;
                ar_forwarded <= 1'b1;
            end

            if (read_active && ar_authorized && !read_denied &&
                policy_revoke_valid)
                read_revoked <= 1'b1;

            // No protected-side AR/R activity for initial denial or timeout:
            // generate ARLEN+1 local zero-data DECERR beats with final RLAST.
            if (read_active && read_denied && !r_rsp_valid) begin
                r_rsp_valid <= 1'b1;
                r_rsp_id    <= active_arid;
                r_rsp_data  <= '0;
                r_rsp_resp  <= AXI_RESP_DECERR;
                r_rsp_last  <= (read_beats_left == 9'd1);
            end
            // Late revocation poisons newly captured R beats, while an already
            // presented/stalled upstream response retains its registered value.
            else if (m_r_hs) begin
                r_rsp_valid <= 1'b1;
                r_rsp_id    <= active_arid;
                r_rsp_data  <= (read_revoked || policy_revoke_valid) ?
                               '0 : m_axi_rdata;
                r_rsp_resp  <= (read_revoked || policy_revoke_valid) ?
                               AXI_RESP_DECERR : m_axi_rresp;
                r_rsp_last  <= (read_beats_left == 9'd1);
            end

            if (s_r_hs) begin
                r_rsp_valid <= 1'b0;
                if (r_rsp_last) begin
                    read_active     <= 1'b0;
                    ar_authorized   <= 1'b0;
                    read_denied     <= 1'b0;
                    read_revoked    <= 1'b0;
                    ar_pending      <= 1'b0;
                    ar_forwarded    <= 1'b0;
                    read_beats_left <= '0;
                    active_arid     <= '0;
                    active_araddr   <= '0;
                    active_arlen    <= '0;
                    active_arsize   <= '0;
                    active_arburst  <= '0;
                    active_aruser   <= '0;
                    r_rsp_id        <= '0;
                    r_rsp_data      <= '0;
                    r_rsp_resp      <= '0;
                    r_rsp_last      <= 1'b0;
                end
                else begin
                    read_beats_left <= read_beats_left - 9'd1;
                end
            end
        end
    end

    // Read address forwarding and one-beat response buffering remain gated
    // by the captured transaction's effective initial authorization.
    assign m_axi_arid    = active_arid;
    assign m_axi_araddr  = active_araddr;
    assign m_axi_arlen   = active_arlen;
    assign m_axi_arsize  = active_arsize;
    assign m_axi_arburst = active_arburst;
    assign m_axi_aruser  = active_aruser;
    assign m_axi_arvalid = rst_n && ar_pending;

    assign m_axi_rready  = rst_n && read_active && ar_authorized &&
                           ar_forwarded && !r_rsp_valid;

    assign s_axi_rid     = r_rsp_id;
    assign s_axi_rdata   = r_rsp_data;
    assign s_axi_rresp   = r_rsp_resp;
    assign s_axi_rlast   = r_rsp_last;
    assign s_axi_rvalid  = rst_n && r_rsp_valid;

endmodule

// Formal checker binding: pass the original dimensions and timeout settings
// unchanged; the checker observes the firewall without changing its datapath.
bind axi_firewall axi_firewall_sva #(
    .AXI_ID_W      (AXI_ID_W),
    .AXI_ADDR_W    (AXI_ADDR_W),
    .AXI_DATA_W    (AXI_DATA_W),
    .AXI_STRB_W    (AXI_STRB_W),
    .MANAGER_ID_W   (MANAGER_ID_W),
    .SUBORDINATE_ID_W (SUBORDINATE_ID_W),
    .AXI_USER_W    (AXI_USER_W),
    .POLICY_TIMEOUT_ENABLE (POLICY_TIMEOUT_ENABLE),
    .POLICY_TIMEOUT_CYCLES (POLICY_TIMEOUT_CYCLES),
    .SVA_INTEGRATION_MODE  (SVA_INTEGRATION_MODE)
) i_axi_firewall_sva (.*);


