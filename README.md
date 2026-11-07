## Design and Formal Verification of an AXI4 Security Firewall for Automotive Central Gateways

This repository accompanies the research manuscript *Design and Formal Verification of an AXI4 Security Firewall for Automotive Central Gateways*. It provides the integrated synthesizable SystemVerilog architecture, its SystemVerilog Assertion (SVA) checkers, and the Synopsys VC Formal Tcl script used for the reported integrated proof configuration.

The design places a centralized enforcement point on a shared AXI4 path between multiple managers and protected subordinates. It combines physical-port-derived trusted manager identities, full-burst legality checks, external policy decisions, transaction ownership, subordinate routing, and fail-closed response handling. The policy-decision algorithm itself is **external** to this repository.

## 1. Architecture: six AXI4 managers, a fixed-priority arbiter, an AXI4 firewall, an external policy module, a decoder, and seven AXI4 subordinates. 


<img width="1121" height="950" alt="diagramFinal (1)" src="https://github.com/user-attachments/assets/a7305753-292d-48fa-8802-b78ecbee90a0" />

The arbiter admits a transaction when the shared path is available, and the integration wrapper retains its owner until the corresponding upstream write response or final read-data handshake. A timed-out accepted policy request also imposes a cancellation-retirement fence before safe interface reuse.

## 2. Repository contents

All seven files are kept in the repository root because the supplied Tcl script analyzes the six SystemVerilog files by relative filename.

| File | Purpose |
| --- | --- |
| [`arbiter_fp_rtl.sv`](arbiter_fp_rtl.sv) | Parameterized combinational fixed-priority arbiter; lower requester index has higher priority. |
| [`arbiter_fp_assertions.sv`](arbiter_fp_assertions.sv) | Bound arbiter safety assertions and reachability cover properties. |
| [`axi_firewall.sv`](axi_firewall.sv) | Transaction-level firewall, policy interface, burst checks, buffer, timeout/cancellation, and read/write enforcement. |
| [`axi_firewall_sva.sv`](axi_firewall_sva.sv) | Firewall interface-based reference models, assertions, policy assumptions, and cover properties. |
| [`arbiter_firewall_top.sv`](arbiter_firewall_top.sv) | Integrated arbitration, trusted identity, transaction-owner locking, firewall instantiation, decoder, and local error target. |
| [`arbiter_firewall_top_sva.sv`](arbiter_firewall_top_sva.sv) | End-to-end integration checker and external manager/subordinate AXI4 assumptions. |
| [`arbiter_firewall_fpv.tcl`](arbiter_firewall_fpv.tcl) | VC Formal setup, source analysis, elaboration, reset initialization, and integrated verification run. |

The formal checkers are source-level documentation of the implementation's expected external behavior. Property comments correspond to the manuscript's finalized **Formal Assertion Catalog**, **Formal Assumption Catalog**, and **Formal Cover Property Catalog**.

## 3. Reproducing the formal verification setup

### Requirements

- A licensed Synopsys **VC Formal** installation with SystemVerilog/SVA support. The reported evaluation used **W-2024.09-SP1** in Formal Property Verification (FPV) mode.
- A compatible execution environment with sufficient compute and memory. The provided script requests 12 remote-shell workers; grid availability depends on your installation.
- The seven repository files together in the working directory.

From the repository root, launch VC Formal with `arbiter_firewall_fpv.tcl` (for installations supporting the conventional `-f` invocation):

```sh
vcf -f arbiter_firewall_fpv.tcl
```

The script retains the following evaluated resource settings:

```tcl
set_fml_var fml_max_time 200H
set_fml_var fml_max_mem 12GB
set_fml_var fml_auto_scale_task_count 16
set_grid_usage -type rsh=12
```

Adapting the tool version, grid configuration, resource budget, design parameters, assumptions, or executable source may change proof effort or results.

## 4. Reported formal results

The manuscript reports the following results: 

| Measure | Reported result |
| --- | ---: |
| Source-level assertion statements | 277 |
| Elaborated assertion instances | **409 / 409 proven** |
| Active source-level cover templates | 103 |
| Elaborated cover properties | **149 / 149 reached** |
| Reported vacuity checks | **439 / 439 non-vacuous** |
| Generated witnesses | **469 / 469 covered** |
| Elaborated SVA assumptions | 60 |
| Additional saved-reset constraint | 1 |
| Total formal constraints | **61** |

## 5. Manuscript and citation

**Associated manuscript:** *Design and Formal Verification of an AXI4 Security Firewall for Automotive Central Gateways.*

The manuscript is currently **under review at IEEE Transactions on Computer-Aided Design of Integrated Circuits and Systems (IEEE TCAD)**. It presents the proposed architecture, formal verification methodology and assumptions, verification results, FPGA and ASIC implementation evaluations, and comprehensive assertion, assumption, and cover-property catalogs. Bibliographic information, including publication details and DOI, will be updated accordingly later. 


## 6. License and research use

The associated manuscript is currently under review at IEEE Transactions on Computer-Aided Design of Integrated Circuits and Systems (IEEE TCAD).

During the review process, the RTL implementation, formal verification source code, and supplementary materials are made available for academic reference, transparency, and research reproducibility. No open-source license has been assigned to this repository at this stage. All rights are reserved by the respective copyright holders. Public availability does not constitute permission to redistribute, modify, or commercially use the materials without prior authorization.

Licensing terms may be updated following the completion of the manuscript review and publication process.

## 8. Acknowledgments

This work was supported in part by the U.S. National Science Foundation (NSF) Research Initiation Award under Grant No. 2500079 and NSF TRAILS under Award No. 2229885.

**AI Assistance Statement:** During the preparation of this work, the authors used ChatGPT (OpenAI) to assist with language polishing, technical phrasing, and improving the clarity of exposition, and Codex (OpenAI) to assist with RTL and assertion development and refinement. All AI-assisted content and code were reviewed, verified, and edited by the authors as needed. The authors take full responsibility for the content and technical results presented in this work.
