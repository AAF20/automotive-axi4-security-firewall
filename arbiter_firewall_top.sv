`timescale 1ns / 1ps

// =============================================================================
// File        : arbiter_firewall_top.sv
// Module      : arbiter_firewall_top
// Purpose     : Integrates fixed-priority arbitration, physical-port-derived
//               identity, one transaction-level AXI4 firewall, protected-side
//               routing, and a local error target for unmapped destinations.
//
// Evaluated defaults: six manager ports, seven protected subordinate ports,
//                     and an enabled 32-cycle policy-resolution timeout.
//
// The external policy-decision algorithm is NOT implemented in this module.
// This wrapper supplies the shared path and routing; axi_firewall is responsible
// for authorization, timeouts, cancellation, and late-revocation enforcement.
// =============================================================================

// Six-manager AXI4 integration wrapper.
//
// Arbitration is performed only when no transaction owner is present. Physical
// manager port 0 has the highest priority and port NUM_MANAGERS-1 the lowest.
// After the highest-priority requesting manager is selected, AW/W has priority
// over AR for that manager, preserving the firewall's idle write preference
// without changing fixed manager priority. The combinational arbiter is
// intentionally unchanged; this wrapper locks the selected manager through B or
// the final R handshake and, after a timed-out accepted policy request, through
// cancellation retirement as well.
//
// The upper USER field is replaced by a trusted ID derived solely from the
// selected physical port. The selected manager's lower SUBORDINATE_ID field is
// preserved. After the firewall authorizes and forwards an address, the lower
// USER field selects one protected-subordinate port. This decoder is routing only:
// it does not compare addresses with subordinates or reproduce policy. An unmapped
// SUBORDINATE_ID is accepted by a local AXI error target, which drains writes or
// generates the complete read burst and returns DECERR without driving a
// physical subordinate.

module arbiter_firewall_top #(
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

    // Entry i occupies bits i*width +: width. Defaults therefore map physical
    // managers 0..5 to 1..6 and subordinate ports 0..6 to the listed IDs.
    parameter logic [NUM_MANAGERS*MANAGER_ID_W-1:0] MANAGER_ID_MAP =
        24'h65_43_21,
    parameter logic [NUM_SUBORDINATES*SUBORDINATE_ID_W-1:0] SUBORDINATE_ID_MAP =
        56'h60_51_50_40_30_20_10
) (
    input  logic clk,
    input  logic rst_n,

    // External policy module. Its Allow/Deny value is not interpreted by the
    // wrapper; all initial authorization, timeout, cancellation, and revocation
    // enforcement remains inside axi_firewall.
    output logic                     policy_req_valid,
    input  logic                     policy_req_ready,
    output logic [MANAGER_ID_W-1:0]   policy_req_manager_id,
    output logic [SUBORDINATE_ID_W-1:0] policy_req_subordinate_id,
    output logic                     policy_req_is_write,
    output logic [AXI_ADDR_W-1:0]    policy_req_start_addr,
    output logic [AXI_ADDR_W-1:0]    policy_req_end_addr,
    input  logic                     policy_rsp_valid,
    output logic                     policy_rsp_ready,
    input  logic                     policy_rsp_allow,
    output logic                     policy_cancel_valid,
    input  logic                     policy_cancel_ready,
    input  logic                     policy_revoke_valid,

    // Upstream AXI4 manager ports.
    input  logic [NUM_MANAGERS-1:0][AXI_ID_W-1:0]     s_axi_awid,
    input  logic [NUM_MANAGERS-1:0][AXI_ADDR_W-1:0]   s_axi_awaddr,
    input  logic [NUM_MANAGERS-1:0][7:0]              s_axi_awlen,
    input  logic [NUM_MANAGERS-1:0][2:0]              s_axi_awsize,
    input  logic [NUM_MANAGERS-1:0][1:0]              s_axi_awburst,
    input  logic [NUM_MANAGERS-1:0][AXI_USER_W-1:0]   s_axi_awuser,
    input  logic [NUM_MANAGERS-1:0]                   s_axi_awvalid,
    output logic [NUM_MANAGERS-1:0]                   s_axi_awready,

    input  logic [NUM_MANAGERS-1:0][AXI_DATA_W-1:0]   s_axi_wdata,
    input  logic [NUM_MANAGERS-1:0][AXI_STRB_W-1:0]   s_axi_wstrb,
    input  logic [NUM_MANAGERS-1:0]                   s_axi_wlast,
    input  logic [NUM_MANAGERS-1:0]                   s_axi_wvalid,
    output logic [NUM_MANAGERS-1:0]                   s_axi_wready,

    output logic [NUM_MANAGERS-1:0][AXI_ID_W-1:0]     s_axi_bid,
    output logic [NUM_MANAGERS-1:0][1:0]              s_axi_bresp,
    output logic [NUM_MANAGERS-1:0]                   s_axi_bvalid,
    input  logic [NUM_MANAGERS-1:0]                   s_axi_bready,

    input  logic [NUM_MANAGERS-1:0][AXI_ID_W-1:0]     s_axi_arid,
    input  logic [NUM_MANAGERS-1:0][AXI_ADDR_W-1:0]   s_axi_araddr,
    input  logic [NUM_MANAGERS-1:0][7:0]              s_axi_arlen,
    input  logic [NUM_MANAGERS-1:0][2:0]              s_axi_arsize,
    input  logic [NUM_MANAGERS-1:0][1:0]              s_axi_arburst,
    input  logic [NUM_MANAGERS-1:0][AXI_USER_W-1:0]   s_axi_aruser,
    input  logic [NUM_MANAGERS-1:0]                   s_axi_arvalid,
    output logic [NUM_MANAGERS-1:0]                   s_axi_arready,

    output logic [NUM_MANAGERS-1:0][AXI_ID_W-1:0]     s_axi_rid,
    output logic [NUM_MANAGERS-1:0][AXI_DATA_W-1:0]   s_axi_rdata,
    output logic [NUM_MANAGERS-1:0][1:0]              s_axi_rresp,
    output logic [NUM_MANAGERS-1:0]                   s_axi_rlast,
    output logic [NUM_MANAGERS-1:0]                   s_axi_rvalid,
    input  logic [NUM_MANAGERS-1:0]                   s_axi_rready,

    // Protected-subordinate AXI4 ports. Port i implements SUBORDINATE_ID_MAP entry i.
    output logic [NUM_SUBORDINATES-1:0][AXI_ID_W-1:0]    m_axi_awid,
    output logic [NUM_SUBORDINATES-1:0][AXI_ADDR_W-1:0]  m_axi_awaddr,
    output logic [NUM_SUBORDINATES-1:0][7:0]             m_axi_awlen,
    output logic [NUM_SUBORDINATES-1:0][2:0]             m_axi_awsize,
    output logic [NUM_SUBORDINATES-1:0][1:0]             m_axi_awburst,
    output logic [NUM_SUBORDINATES-1:0][AXI_USER_W-1:0]  m_axi_awuser,
    output logic [NUM_SUBORDINATES-1:0]                  m_axi_awvalid,
    input  logic [NUM_SUBORDINATES-1:0]                  m_axi_awready,

    output logic [NUM_SUBORDINATES-1:0][AXI_DATA_W-1:0]  m_axi_wdata,
    output logic [NUM_SUBORDINATES-1:0][AXI_STRB_W-1:0]  m_axi_wstrb,
    output logic [NUM_SUBORDINATES-1:0]                  m_axi_wlast,
    output logic [NUM_SUBORDINATES-1:0]                  m_axi_wvalid,
    input  logic [NUM_SUBORDINATES-1:0]                  m_axi_wready,

    input  logic [NUM_SUBORDINATES-1:0][AXI_ID_W-1:0]    m_axi_bid,
    input  logic [NUM_SUBORDINATES-1:0][1:0]             m_axi_bresp,
    input  logic [NUM_SUBORDINATES-1:0]                  m_axi_bvalid,
    output logic [NUM_SUBORDINATES-1:0]                  m_axi_bready,

    output logic [NUM_SUBORDINATES-1:0][AXI_ID_W-1:0]    m_axi_arid,
    output logic [NUM_SUBORDINATES-1:0][AXI_ADDR_W-1:0]  m_axi_araddr,
    output logic [NUM_SUBORDINATES-1:0][7:0]             m_axi_arlen,
    output logic [NUM_SUBORDINATES-1:0][2:0]             m_axi_arsize,
    output logic [NUM_SUBORDINATES-1:0][1:0]             m_axi_arburst,
    output logic [NUM_SUBORDINATES-1:0][AXI_USER_W-1:0]  m_axi_aruser,
    output logic [NUM_SUBORDINATES-1:0]                  m_axi_arvalid,
    input  logic [NUM_SUBORDINATES-1:0]                  m_axi_arready,

    input  logic [NUM_SUBORDINATES-1:0][AXI_ID_W-1:0]    m_axi_rid,
    input  logic [NUM_SUBORDINATES-1:0][AXI_DATA_W-1:0]  m_axi_rdata,
    input  logic [NUM_SUBORDINATES-1:0][1:0]             m_axi_rresp,
    input  logic [NUM_SUBORDINATES-1:0]                  m_axi_rlast,
    input  logic [NUM_SUBORDINATES-1:0]                  m_axi_rvalid,
    output logic [NUM_SUBORDINATES-1:0]                  m_axi_rready,

    // Non-authoritative status/observation outputs. They are not policy inputs.
    output logic [NUM_MANAGERS-1:0]                    arb_grant,
    output logic [MANAGER_IDX_W-1:0]                   active_manager,
    output logic                                      transaction_active,
    output logic                                      write_active,
    output logic                                      read_active,
    output logic                                      subordinate_active,
    output logic [SUBORDINATE_IDX_W-1:0]                 active_subordinate,
    output logic                                      active_subordinate_implemented
);

    localparam logic [1:0] AXI_RESP_DECERR = 2'b11;

    // Elaboration-time guards reject unsupported widths and duplicate IDs.
    // The configured maps, rather than untrusted USER identity bits, determine
    // the trusted physical-port identity and implemented subordinate IDs.
    initial begin : p_parameter_checks
        if (NUM_MANAGERS < 1)
            $fatal(1, "NUM_MANAGERS must be greater than zero");
        if (NUM_SUBORDINATES < 1)
            $fatal(1, "NUM_SUBORDINATES must be greater than zero");
        if (MANAGER_IDX_W < ((NUM_MANAGERS <= 1) ? 1 : $clog2(NUM_MANAGERS)))
            $fatal(1, "MANAGER_IDX_W is too small for NUM_MANAGERS");
        if (SUBORDINATE_IDX_W <
            ((NUM_SUBORDINATES <= 1) ? 1 : $clog2(NUM_SUBORDINATES)))
            $fatal(1, "SUBORDINATE_IDX_W is too small for NUM_SUBORDINATES");
        if (AXI_USER_W != (MANAGER_ID_W + SUBORDINATE_ID_W))
            $fatal(1, "AXI_USER_W must equal MANAGER_ID_W + SUBORDINATE_ID_W");
        for (int i = 0; i < NUM_MANAGERS; i++) begin
            for (int j = i + 1; j < NUM_MANAGERS; j++) begin
                if (MANAGER_ID_MAP[i*MANAGER_ID_W +: MANAGER_ID_W] ==
                    MANAGER_ID_MAP[j*MANAGER_ID_W +: MANAGER_ID_W])
                    $fatal(1, "MANAGER_ID_MAP entries must be unique");
            end
        end
        for (int i = 0; i < NUM_SUBORDINATES; i++) begin
            for (int j = i + 1; j < NUM_SUBORDINATES; j++) begin
                if (SUBORDINATE_ID_MAP[i*SUBORDINATE_ID_W +: SUBORDINATE_ID_W] ==
                    SUBORDINATE_ID_MAP[j*SUBORDINATE_ID_W +: SUBORDINATE_ID_W])
                    $fatal(1, "SUBORDINATE_ID_MAP entries must be unique");
            end
        end
    end

    // Convert a one-hot grant to a physical port index. Arbitration priority
    // itself is established by arbiter_fp_rtl, not by this conversion helper.
    function automatic logic [MANAGER_IDX_W-1:0] onehot_to_manager_index(
        input logic [NUM_MANAGERS-1:0] onehot
    );
        logic [MANAGER_IDX_W-1:0] result;
        begin
            result = '0;
            for (int k = 0; k < NUM_MANAGERS; k++) begin
                if (onehot[k])
                    result = k[MANAGER_IDX_W-1:0];
            end
            return result;
        end
    endfunction

    // Derive the immutable policy-facing identity from the selected port's
    // configured map entry, never from the requesting manager's USER bits.
    function automatic logic [MANAGER_ID_W-1:0] trusted_manager_id(
        input logic [MANAGER_IDX_W-1:0] index
    );
        logic [MANAGER_ID_W-1:0] result;
        begin
            result = '0;
            for (int k = 0; k < NUM_MANAGERS; k++) begin
                if (index == k[MANAGER_IDX_W-1:0])
                    result = MANAGER_ID_MAP[k*MANAGER_ID_W +: MANAGER_ID_W];
            end
            return result;
        end
    endfunction

    // Lookup the destination ID among implemented protected-side ports.
    // An unmapped ID is handled by the local AXI error target below.
    function automatic logic subordinate_id_implemented(
        input logic [SUBORDINATE_ID_W-1:0] subordinate_id
    );
        logic result;
        begin
            result = 1'b0;
            for (int k = 0; k < NUM_SUBORDINATES; k++) begin
                if (subordinate_id ==
                    SUBORDINATE_ID_MAP[k*SUBORDINATE_ID_W +: SUBORDINATE_ID_W])
                    result = 1'b1;
            end
            return result;
        end
    endfunction

    // Translate a mapped destination ID into its physical subordinate index.
    function automatic logic [SUBORDINATE_IDX_W-1:0] subordinate_id_to_index(
        input logic [SUBORDINATE_ID_W-1:0] subordinate_id
    );
        logic [SUBORDINATE_IDX_W-1:0] result;
        begin
            result = '0;
            for (int k = 0; k < NUM_SUBORDINATES; k++) begin
                if (subordinate_id ==
                    SUBORDINATE_ID_MAP[k*SUBORDINATE_ID_W +: SUBORDINATE_ID_W])
                    result = k[SUBORDINATE_IDX_W-1:0];
            end
            return result;
        end
    endfunction

    // ---------------------------------------------------------------------
    // Fixed-priority selection and manager-owner lock
    // ---------------------------------------------------------------------
    logic [NUM_MANAGERS-1:0] write_req;
    logic [NUM_MANAGERS-1:0] read_req;
    logic [NUM_MANAGERS-1:0] arb_req;
    logic                    owner_completion_wait;
    logic                    owner_aw_seen;
    logic                    owner_w_done;
    logic                    owner_ar_seen;

    // W alone can request admission: a manager may legally present W before AW.
    // No new arbitration occurs during ownership or an active cancel fence.
    assign write_req = s_axi_awvalid | s_axi_wvalid;
    assign read_req  = s_axi_arvalid;
    assign arb_req   = rst_n && !transaction_active &&
                       !policy_cancel_valid ?
                       (write_req | read_req) : '0;

    arbiter_fp_rtl #(
        .NUM_REQS(NUM_MANAGERS),
        .SVA_INTEGRATION_MODE(1'b1)
    ) u_arbiter_fp_rtl (
        .clk   (clk),
        .req   (arb_req),
        .grant (arb_grant)
    );

    wire any_grant = |arb_grant;
    wire [MANAGER_IDX_W-1:0] granted_manager =
        onehot_to_manager_index(arb_grant);
    // A new grant is used only while idle; all subsequent beats and responses
    // stay associated with the registered transaction owner.
    wire [MANAGER_IDX_W-1:0] selected_manager =
        transaction_active ? active_manager : granted_manager;
    wire selected_valid = transaction_active || any_grant;
    wire route_write = transaction_active ? write_active :
                       (any_grant && write_req[granted_manager]);
    wire route_read = transaction_active ? read_active :
                      (any_grant && !write_req[granted_manager] &&
                       read_req[granted_manager]);

    // ---------------------------------------------------------------------
    // Firewall-facing upstream AXI interface
    // ---------------------------------------------------------------------
    logic [AXI_ID_W-1:0]    fw_awid;
    logic [AXI_ADDR_W-1:0]  fw_awaddr;
    logic [7:0]             fw_awlen;
    logic [2:0]             fw_awsize;
    logic [1:0]             fw_awburst;
    logic [AXI_USER_W-1:0]  fw_awuser;
    logic                   fw_awvalid;
    logic                   fw_awready;
    logic [AXI_DATA_W-1:0]  fw_wdata;
    logic [AXI_STRB_W-1:0]  fw_wstrb;
    logic                   fw_wlast;
    logic                   fw_wvalid;
    logic                   fw_wready;
    logic [AXI_ID_W-1:0]    fw_bid;
    logic [1:0]             fw_bresp;
    logic                   fw_bvalid;
    logic                   fw_bready;
    logic [AXI_ID_W-1:0]    fw_arid;
    logic [AXI_ADDR_W-1:0]  fw_araddr;
    logic [7:0]             fw_arlen;
    logic [2:0]             fw_arsize;
    logic [1:0]             fw_arburst;
    logic [AXI_USER_W-1:0]  fw_aruser;
    logic                   fw_arvalid;
    logic                   fw_arready;
    logic [AXI_ID_W-1:0]    fw_rid;
    logic [AXI_DATA_W-1:0]  fw_rdata;
    logic [1:0]             fw_rresp;
    logic                   fw_rlast;
    logic                   fw_rvalid;
    logic                   fw_rready;

    // Present only the chosen manager's request to the firewall. Replace the
    // upper AWUSER/ARUSER identity bits with the physical-port-derived value,
    // while retaining the manager-provided destination field unchanged.
    always_comb begin
        fw_awid    = '0;
        fw_awaddr  = '0;
        fw_awlen   = '0;
        fw_awsize  = '0;
        fw_awburst = '0;
        fw_awuser  = '0;
        fw_awvalid = 1'b0;
        fw_wdata   = '0;
        fw_wstrb   = '0;
        fw_wlast   = 1'b0;
        fw_wvalid  = 1'b0;
        fw_arid    = '0;
        fw_araddr  = '0;
        fw_arlen   = '0;
        fw_arsize  = '0;
        fw_arburst = '0;
        fw_aruser  = '0;
        fw_arvalid = 1'b0;
        s_axi_awready = '0;
        s_axi_wready  = '0;
        s_axi_arready = '0;

        if (selected_valid && route_write && !owner_completion_wait) begin
            fw_awid    = s_axi_awid[selected_manager];
            fw_awaddr  = s_axi_awaddr[selected_manager];
            fw_awlen   = s_axi_awlen[selected_manager];
            fw_awsize  = s_axi_awsize[selected_manager];
            fw_awburst = s_axi_awburst[selected_manager];
            fw_awuser  = {
                trusted_manager_id(selected_manager),
                s_axi_awuser[selected_manager][SUBORDINATE_ID_W-1:0]
            };
            fw_awvalid = !owner_aw_seen &&
                         s_axi_awvalid[selected_manager];
            fw_wdata   = s_axi_wdata[selected_manager];
            fw_wstrb   = s_axi_wstrb[selected_manager];
            fw_wlast   = s_axi_wlast[selected_manager];
            fw_wvalid  = !owner_w_done &&
                         s_axi_wvalid[selected_manager];
            s_axi_awready[selected_manager] =
                !owner_aw_seen && fw_awready;
            s_axi_wready[selected_manager] =
                !owner_w_done && fw_wready;
        end

        if (selected_valid && route_read && !owner_completion_wait) begin
            fw_arid    = s_axi_arid[selected_manager];
            fw_araddr  = s_axi_araddr[selected_manager];
            fw_arlen   = s_axi_arlen[selected_manager];
            fw_arsize  = s_axi_arsize[selected_manager];
            fw_arburst = s_axi_arburst[selected_manager];
            fw_aruser  = {
                trusted_manager_id(selected_manager),
                s_axi_aruser[selected_manager][SUBORDINATE_ID_W-1:0]
            };
            fw_arvalid = !owner_ar_seen &&
                         s_axi_arvalid[selected_manager];
            s_axi_arready[selected_manager] =
                !owner_ar_seen && fw_arready;
        end
    end

    // Demultiplex B and R responses exclusively to the locked owner. The
    // firewall sees that owner's READY, not readiness from other managers.
    always_comb begin
        s_axi_bid    = '0;
        s_axi_bresp  = '0;
        s_axi_bvalid = '0;
        fw_bready    = 1'b0;
        s_axi_rid    = '0;
        s_axi_rdata  = '0;
        s_axi_rresp  = '0;
        s_axi_rlast  = '0;
        s_axi_rvalid = '0;
        fw_rready    = 1'b0;

        if (transaction_active && write_active) begin
            s_axi_bid[active_manager]    = fw_bid;
            s_axi_bresp[active_manager]  = fw_bresp;
            s_axi_bvalid[active_manager] = fw_bvalid;
            fw_bready                   = s_axi_bready[active_manager];
        end

        if (transaction_active && read_active) begin
            s_axi_rid[active_manager]    = fw_rid;
            s_axi_rdata[active_manager]  = fw_rdata;
            s_axi_rresp[active_manager]  = fw_rresp;
            s_axi_rlast[active_manager]  = fw_rlast;
            s_axi_rvalid[active_manager] = fw_rvalid;
            fw_rready                   = s_axi_rready[active_manager];
        end
    end

    wire fw_s_aw_hs = fw_awvalid && fw_awready;
    wire fw_s_w_hs  = fw_wvalid  && fw_wready;
    wire fw_s_b_hs  = fw_bvalid  && fw_bready;
    wire fw_s_ar_hs = fw_arvalid && fw_arready;
    wire fw_s_r_hs  = fw_rvalid  && fw_rready;
    wire write_done = transaction_active && write_active && fw_s_b_hs;
    wire read_done  = transaction_active && read_active &&
                      fw_s_r_hs && fw_rlast;
    wire policy_cancel_hs = policy_cancel_valid && policy_cancel_ready;

    // Ownership begins on the first accepted AW, W, or AR transfer. Retain it
    // through upstream B or final R completion; if an accepted policy request
    // timed out, keep admission fenced until cancellation also retires it.
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            transaction_active    <= 1'b0;
            write_active          <= 1'b0;
            read_active           <= 1'b0;
            active_manager         <= '0;
            owner_completion_wait <= 1'b0;
            owner_aw_seen         <= 1'b0;
            owner_w_done          <= 1'b0;
            owner_ar_seen         <= 1'b0;
        end
        else if (!transaction_active) begin
            if (any_grant && route_write &&
                (fw_s_aw_hs || fw_s_w_hs)) begin
                transaction_active    <= 1'b1;
                write_active          <= 1'b1;
                read_active           <= 1'b0;
                active_manager         <= granted_manager;
                owner_completion_wait <= 1'b0;
                owner_aw_seen         <= fw_s_aw_hs;
                owner_w_done          <= fw_s_w_hs && fw_wlast;
                owner_ar_seen         <= 1'b0;
            end
            else if (any_grant && route_read && fw_s_ar_hs) begin
                transaction_active    <= 1'b1;
                write_active          <= 1'b0;
                read_active           <= 1'b1;
                active_manager         <= granted_manager;
                owner_completion_wait <= 1'b0;
                owner_aw_seen         <= 1'b0;
                owner_w_done          <= 1'b0;
                owner_ar_seen         <= 1'b1;
            end
        end
        // Local AXI completion may precede cancellation of a timed-out policy
        // request. Do not release the owner while that old request remains live.
        else if (owner_completion_wait) begin
            if (policy_cancel_hs) begin
                transaction_active    <= 1'b0;
                write_active          <= 1'b0;
                read_active           <= 1'b0;
                active_manager         <= '0;
                owner_completion_wait <= 1'b0;
                owner_aw_seen         <= 1'b0;
                owner_w_done          <= 1'b0;
                owner_ar_seen         <= 1'b0;
            end
        end
        else if (write_done || read_done) begin
            if (policy_cancel_valid && !policy_cancel_hs) begin
                owner_completion_wait <= 1'b1;
            end
            else begin
                transaction_active    <= 1'b0;
                write_active          <= 1'b0;
                read_active           <= 1'b0;
                active_manager         <= '0;
                owner_completion_wait <= 1'b0;
                owner_aw_seen         <= 1'b0;
                owner_w_done          <= 1'b0;
                owner_ar_seen         <= 1'b0;
            end
        end
        else begin
            if (fw_s_aw_hs)
                owner_aw_seen <= 1'b1;
            if (fw_s_w_hs && fw_wlast)
                owner_w_done <= 1'b1;
            if (fw_s_ar_hs)
                owner_ar_seen <= 1'b1;
        end
    end

    // ---------------------------------------------------------------------
    // Firewall core and its single downstream AXI interface
    // ---------------------------------------------------------------------
    logic [AXI_ID_W-1:0]    fw_m_awid;
    logic [AXI_ADDR_W-1:0]  fw_m_awaddr;
    logic [7:0]             fw_m_awlen;
    logic [2:0]             fw_m_awsize;
    logic [1:0]             fw_m_awburst;
    logic [AXI_USER_W-1:0]  fw_m_awuser;
    logic                   fw_m_awvalid;
    logic                   fw_m_awready;
    logic [AXI_DATA_W-1:0]  fw_m_wdata;
    logic [AXI_STRB_W-1:0]  fw_m_wstrb;
    logic                   fw_m_wlast;
    logic                   fw_m_wvalid;
    logic                   fw_m_wready;
    logic [AXI_ID_W-1:0]    fw_m_bid;
    logic [1:0]             fw_m_bresp;
    logic                   fw_m_bvalid;
    logic                   fw_m_bready;
    logic [AXI_ID_W-1:0]    fw_m_arid;
    logic [AXI_ADDR_W-1:0]  fw_m_araddr;
    logic [7:0]             fw_m_arlen;
    logic [2:0]             fw_m_arsize;
    logic [1:0]             fw_m_arburst;
    logic [AXI_USER_W-1:0]  fw_m_aruser;
    logic                   fw_m_arvalid;
    logic                   fw_m_arready;
    logic [AXI_ID_W-1:0]    fw_m_rid;
    logic [AXI_DATA_W-1:0]  fw_m_rdata;
    logic [1:0]             fw_m_rresp;
    logic                   fw_m_rlast;
    logic                   fw_m_rvalid;
    logic                   fw_m_rready;

    // Single shared firewall instance. Policy decisions are effective only
    // according to its own valid/ready, legality, and revocation controls.
    axi_firewall #(
        .AXI_ID_W              (AXI_ID_W),
        .AXI_ADDR_W            (AXI_ADDR_W),
        .AXI_DATA_W            (AXI_DATA_W),
        .AXI_STRB_W            (AXI_STRB_W),
        .MANAGER_ID_W           (MANAGER_ID_W),
        .SUBORDINATE_ID_W         (SUBORDINATE_ID_W),
        .AXI_USER_W            (AXI_USER_W),
        .POLICY_TIMEOUT_ENABLE (POLICY_TIMEOUT_ENABLE),
        .POLICY_TIMEOUT_CYCLES (POLICY_TIMEOUT_CYCLES),
        .SVA_INTEGRATION_MODE  (1'b1)
    ) u_axi_firewall (
        .clk                    (clk),
        .rst_n                  (rst_n),
        .policy_req_valid       (policy_req_valid),
        .policy_req_ready       (policy_req_ready),
        .policy_req_manager_id   (policy_req_manager_id),
        .policy_req_subordinate_id (policy_req_subordinate_id),
        .policy_req_is_write    (policy_req_is_write),
        .policy_req_start_addr  (policy_req_start_addr),
        .policy_req_end_addr    (policy_req_end_addr),
        .policy_rsp_valid       (policy_rsp_valid),
        .policy_rsp_ready       (policy_rsp_ready),
        .policy_rsp_allow       (policy_rsp_allow),
        .policy_cancel_valid    (policy_cancel_valid),
        .policy_cancel_ready    (policy_cancel_ready),
        .policy_revoke_valid    (policy_revoke_valid),

        .s_axi_awid             (fw_awid),
        .s_axi_awaddr           (fw_awaddr),
        .s_axi_awlen            (fw_awlen),
        .s_axi_awsize           (fw_awsize),
        .s_axi_awburst          (fw_awburst),
        .s_axi_awuser           (fw_awuser),
        .s_axi_awvalid          (fw_awvalid),
        .s_axi_awready          (fw_awready),
        .s_axi_wdata            (fw_wdata),
        .s_axi_wstrb            (fw_wstrb),
        .s_axi_wlast            (fw_wlast),
        .s_axi_wvalid           (fw_wvalid),
        .s_axi_wready           (fw_wready),
        .s_axi_bid              (fw_bid),
        .s_axi_bresp            (fw_bresp),
        .s_axi_bvalid           (fw_bvalid),
        .s_axi_bready           (fw_bready),

        .m_axi_awid             (fw_m_awid),
        .m_axi_awaddr           (fw_m_awaddr),
        .m_axi_awlen            (fw_m_awlen),
        .m_axi_awsize           (fw_m_awsize),
        .m_axi_awburst          (fw_m_awburst),
        .m_axi_awuser           (fw_m_awuser),
        .m_axi_awvalid          (fw_m_awvalid),
        .m_axi_awready          (fw_m_awready),
        .m_axi_wdata            (fw_m_wdata),
        .m_axi_wstrb            (fw_m_wstrb),
        .m_axi_wlast            (fw_m_wlast),
        .m_axi_wvalid           (fw_m_wvalid),
        .m_axi_wready           (fw_m_wready),
        .m_axi_bid              (fw_m_bid),
        .m_axi_bresp            (fw_m_bresp),
        .m_axi_bvalid           (fw_m_bvalid),
        .m_axi_bready           (fw_m_bready),

        .s_axi_arid             (fw_arid),
        .s_axi_araddr           (fw_araddr),
        .s_axi_arlen            (fw_arlen),
        .s_axi_arsize           (fw_arsize),
        .s_axi_arburst          (fw_arburst),
        .s_axi_aruser           (fw_aruser),
        .s_axi_arvalid          (fw_arvalid),
        .s_axi_arready          (fw_arready),
        .m_axi_arid             (fw_m_arid),
        .m_axi_araddr           (fw_m_araddr),
        .m_axi_arlen            (fw_m_arlen),
        .m_axi_arsize           (fw_m_arsize),
        .m_axi_arburst          (fw_m_arburst),
        .m_axi_aruser           (fw_m_aruser),
        .m_axi_arvalid          (fw_m_arvalid),
        .m_axi_arready          (fw_m_arready),
        .m_axi_rid              (fw_m_rid),
        .m_axi_rdata            (fw_m_rdata),
        .m_axi_rresp            (fw_m_rresp),
        .m_axi_rlast            (fw_m_rlast),
        .m_axi_rvalid           (fw_m_rvalid),
        .m_axi_rready           (fw_m_rready),
        .s_axi_rid              (fw_rid),
        .s_axi_rdata            (fw_rdata),
        .s_axi_rresp            (fw_rresp),
        .s_axi_rlast            (fw_rlast),
        .s_axi_rvalid           (fw_rvalid),
        .s_axi_rready           (fw_rready)
    );

    // ---------------------------------------------------------------------
    // Trusted subordinate decoder, subordinate locks, and local error target
    // ---------------------------------------------------------------------
    logic write_subordinate_active;
    logic write_subordinate_implemented;
    logic [SUBORDINATE_IDX_W-1:0] write_subordinate_index;
    logic read_subordinate_active;
    logic read_subordinate_implemented;
    logic [SUBORDINATE_IDX_W-1:0] read_subordinate_index;

    logic err_write_active;
    logic err_write_done;
    logic err_bvalid;
    logic [AXI_ID_W-1:0] err_bid;
    logic err_read_active;
    logic err_rvalid;
    logic [AXI_ID_W-1:0] err_rid;
    logic [8:0] err_read_beats_left;

    // The decoder observes the firewall-approved address metadata, not a
    // manager's raw request. A route is latched on AW/AR acceptance and then
    // remains fixed for write-data/read-data and response-channel routing.
    wire [SUBORDINATE_ID_W-1:0] live_write_subordinate_id =
        fw_m_awuser[SUBORDINATE_ID_W-1:0];
    wire live_write_subordinate_implemented =
        subordinate_id_implemented(live_write_subordinate_id);
    wire [SUBORDINATE_IDX_W-1:0] live_write_subordinate_index =
        subordinate_id_to_index(live_write_subordinate_id);
    wire [SUBORDINATE_ID_W-1:0] live_read_subordinate_id =
        fw_m_aruser[SUBORDINATE_ID_W-1:0];
    wire live_read_subordinate_implemented =
        subordinate_id_implemented(live_read_subordinate_id);
    wire [SUBORDINATE_IDX_W-1:0] live_read_subordinate_index =
        subordinate_id_to_index(live_read_subordinate_id);

    wire fw_m_aw_hs = fw_m_awvalid && fw_m_awready;
    wire fw_m_w_hs  = fw_m_wvalid  && fw_m_wready;
    wire fw_m_b_hs  = fw_m_bvalid  && fw_m_bready;
    wire fw_m_ar_hs = fw_m_arvalid && fw_m_arready;
    wire fw_m_r_hs  = fw_m_rvalid  && fw_m_rready;

    // Latch write routing at downstream AW acceptance. If the destination is
    // not implemented, the local target drains W through WLAST and then
    // presents a DECERR B response with the accepted transaction ID.
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            write_subordinate_active      <= 1'b0;
            write_subordinate_implemented <= 1'b0;
            write_subordinate_index       <= '0;
            err_write_active           <= 1'b0;
            err_write_done             <= 1'b0;
            err_bvalid                 <= 1'b0;
            err_bid                    <= '0;
        end
        else if (fw_s_b_hs) begin
            write_subordinate_active      <= 1'b0;
            write_subordinate_implemented <= 1'b0;
            write_subordinate_index       <= '0;
            err_write_active           <= 1'b0;
            err_write_done             <= 1'b0;
            err_bvalid                 <= 1'b0;
            err_bid                    <= '0;
        end
        else begin
            if (fw_m_aw_hs) begin
                write_subordinate_active      <= 1'b1;
                write_subordinate_implemented <=
                    live_write_subordinate_implemented;
                write_subordinate_index <= live_write_subordinate_index;
                if (!live_write_subordinate_implemented) begin
                    err_write_active <= 1'b1;
                    err_write_done   <= 1'b0;
                    err_bid          <= fw_m_awid;
                end
            end

            if (err_write_active && fw_m_w_hs && fw_m_wlast) begin
                err_write_done <= 1'b1;
                err_bvalid <= 1'b1;
            end

            if (err_bvalid && fw_m_bready)
                err_bvalid <= 1'b0;
        end
    end

    // Latch read routing at downstream AR acceptance. An unmapped read uses
    // a 9-bit counter for ARLEN+1 (including the 256-beat maximum), returning
    // zero-data DECERR beats and asserting RLAST on the final beat.
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            read_subordinate_active      <= 1'b0;
            read_subordinate_implemented <= 1'b0;
            read_subordinate_index       <= '0;
            err_read_active           <= 1'b0;
            err_rvalid                <= 1'b0;
            err_rid                   <= '0;
            err_read_beats_left       <= '0;
        end
        else if (fw_s_r_hs && fw_rlast) begin
            read_subordinate_active      <= 1'b0;
            read_subordinate_implemented <= 1'b0;
            read_subordinate_index       <= '0;
            err_read_active           <= 1'b0;
            err_rvalid                <= 1'b0;
            err_rid                   <= '0;
            err_read_beats_left       <= '0;
        end
        else begin
            if (fw_m_ar_hs) begin
                read_subordinate_active      <= 1'b1;
                read_subordinate_implemented <=
                    live_read_subordinate_implemented;
                read_subordinate_index <= live_read_subordinate_index;
                if (!live_read_subordinate_implemented) begin
                    err_read_active     <= 1'b1;
                    err_rvalid          <= 1'b1;
                    err_rid             <= fw_m_arid;
                    err_read_beats_left <= {1'b0, fw_m_arlen} + 9'd1;
                end
            end
            else if (err_read_active && err_rvalid && fw_m_rready) begin
                if (err_read_beats_left == 9'd1) begin
                    err_rvalid          <= 1'b0;
                    err_read_beats_left <= '0;
                end
                else begin
                    err_read_beats_left <= err_read_beats_left - 9'd1;
                end
            end
        end
    end

    // Multiplex only the implemented, selected subordinate port. All other
    // physical port VALIDs and response READYs default low. Unmapped accesses
    // are consumed locally and never activate a physical protected port.
    always_comb begin
        m_axi_awid    = '0;
        m_axi_awaddr  = '0;
        m_axi_awlen   = '0;
        m_axi_awsize  = '0;
        m_axi_awburst = '0;
        m_axi_awuser  = '0;
        m_axi_awvalid = '0;
        m_axi_wdata   = '0;
        m_axi_wstrb   = '0;
        m_axi_wlast   = '0;
        m_axi_wvalid  = '0;
        m_axi_bready  = '0;
        m_axi_arid    = '0;
        m_axi_araddr  = '0;
        m_axi_arlen   = '0;
        m_axi_arsize  = '0;
        m_axi_arburst = '0;
        m_axi_aruser  = '0;
        m_axi_arvalid = '0;
        m_axi_rready  = '0;

        fw_m_awready = 1'b0;
        fw_m_wready  = 1'b0;
        fw_m_bid     = '0;
        fw_m_bresp   = '0;
        fw_m_bvalid  = 1'b0;
        fw_m_arready = 1'b0;
        fw_m_rid     = '0;
        fw_m_rdata   = '0;
        fw_m_rresp   = '0;
        fw_m_rlast   = 1'b0;
        fw_m_rvalid  = 1'b0;

        // Address routing uses the firewall's registered USER field. Once the
        // address handshakes, all remaining channels use the locked selection.
        if (fw_m_awvalid && !write_subordinate_active) begin
            if (live_write_subordinate_implemented) begin
                m_axi_awid[live_write_subordinate_index]    = fw_m_awid;
                m_axi_awaddr[live_write_subordinate_index]  = fw_m_awaddr;
                m_axi_awlen[live_write_subordinate_index]   = fw_m_awlen;
                m_axi_awsize[live_write_subordinate_index]  = fw_m_awsize;
                m_axi_awburst[live_write_subordinate_index] = fw_m_awburst;
                m_axi_awuser[live_write_subordinate_index]  = fw_m_awuser;
                m_axi_awvalid[live_write_subordinate_index] = fw_m_awvalid;
                fw_m_awready = m_axi_awready[live_write_subordinate_index];
            end
            else begin
                fw_m_awready = !err_write_active;
            end
        end

        if (write_subordinate_active) begin
            if (write_subordinate_implemented) begin
                m_axi_wdata[write_subordinate_index]  = fw_m_wdata;
                m_axi_wstrb[write_subordinate_index]  = fw_m_wstrb;
                m_axi_wlast[write_subordinate_index]  = fw_m_wlast;
                m_axi_wvalid[write_subordinate_index] = fw_m_wvalid;
                fw_m_wready = m_axi_wready[write_subordinate_index];
                fw_m_bid    = m_axi_bid[write_subordinate_index];
                fw_m_bresp  = m_axi_bresp[write_subordinate_index];
                fw_m_bvalid = m_axi_bvalid[write_subordinate_index];
                m_axi_bready[write_subordinate_index] = fw_m_bready;
            end
            else begin
                fw_m_wready = err_write_active &&
                              !err_write_done && !err_bvalid;
                fw_m_bid    = err_bid;
                fw_m_bresp  = AXI_RESP_DECERR;
                fw_m_bvalid = err_bvalid;
            end
        end

        if (fw_m_arvalid && !read_subordinate_active) begin
            if (live_read_subordinate_implemented) begin
                m_axi_arid[live_read_subordinate_index]    = fw_m_arid;
                m_axi_araddr[live_read_subordinate_index]  = fw_m_araddr;
                m_axi_arlen[live_read_subordinate_index]   = fw_m_arlen;
                m_axi_arsize[live_read_subordinate_index]  = fw_m_arsize;
                m_axi_arburst[live_read_subordinate_index] = fw_m_arburst;
                m_axi_aruser[live_read_subordinate_index]  = fw_m_aruser;
                m_axi_arvalid[live_read_subordinate_index] = fw_m_arvalid;
                fw_m_arready = m_axi_arready[live_read_subordinate_index];
            end
            else begin
                fw_m_arready = !err_read_active;
            end
        end

        if (read_subordinate_active) begin
            if (read_subordinate_implemented) begin
                fw_m_rid    = m_axi_rid[read_subordinate_index];
                fw_m_rdata  = m_axi_rdata[read_subordinate_index];
                fw_m_rresp  = m_axi_rresp[read_subordinate_index];
                fw_m_rlast  = m_axi_rlast[read_subordinate_index];
                fw_m_rvalid = m_axi_rvalid[read_subordinate_index];
                m_axi_rready[read_subordinate_index] = fw_m_rready;
            end
            else begin
                fw_m_rid    = err_rid;
                fw_m_rdata  = '0;
                fw_m_rresp  = AXI_RESP_DECERR;
                fw_m_rlast  = (err_read_beats_left == 9'd1);
                fw_m_rvalid = err_rvalid;
            end
        end
    end

    // Read-only observation of the currently locked physical destination;
    // these status signals do not participate in external authorization.
    always_comb begin
        subordinate_active = write_subordinate_active || read_subordinate_active;
        active_subordinate = write_subordinate_active ? write_subordinate_index :
                          read_subordinate_index;
        active_subordinate_implemented = write_subordinate_active ?
                                      write_subordinate_implemented :
                                      read_subordinate_implemented;
    end

endmodule
