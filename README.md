# Artefact: Modbus-Aware Zero Trust Policy Enforcement Point (PEP)

This artefact accompanies the final report *"Zero Trust Architecture for
Operational Technology in the Energy Sector"* (MOD002726). It contains the
working source code for the custom Policy Enforcement Point (PEP) described in
Chapter 4 (Design and Development) and evaluated in Chapter 5 (Implementation
and Testing) of the report.

## Contents

```
artefact/
├── README.md                          (this file)
├── v1_request_filtering_pep/          Report: Section 4.2 (v1); Chapter 5, Table 2 (Command Injection results)
│   ├── modbus_pep.py                  Modbus-aware proxy: function-code allow-list only
│   ├── policy.json                    Policy configuration (allowed function codes)
│   └── Dockerfile                     Container build definition
└── v2_historical_baseline_pep/        Report: Section 4.2 (v2); Chapter 5, Table 2 (False Data Injection results)
    ├── modbus_pep_v2.py               Extended proxy: adds response-side historical-baseline checking
    ├── policy_v2.json                 Policy configuration (allow-list + baseline/tolerance settings)
    └── Dockerfile                     Container build definition
```

## What this artefact demonstrates

- **v1** implements protocol-aware request filtering: it inspects the Modbus
  function code of every request from the subject (OpenPLC) and forwards only
  permitted read operations, blocking write/command function codes. This is
  the mechanism evaluated against the Command Injection attack scenario.
- **v2** extends v1 with response-side inspection: it learns a historical
  baseline for each register's value over an initial observation window, then
  flags and blocks subsequent responses that deviate beyond a defined
  tolerance, returning a Modbus protocol exception rather than forwarding
  falsified data. This is the mechanism evaluated against the False Data
  Injection attack scenario (see report Section 5.2 and 5.3 for the two-stage
  v1-then-v2 evaluation narrative).

Both versions were run as Docker containers, positioned as the sole network
bridge between two isolated Docker bridge networks (see report Section 3.4,
Figure 1), acting as the framework's Policy Enforcement Point (report Section
4.1).

## How to build and run

These containers depend on two other components not included in this
artefact, since they are third-party, publicly available Docker images used
as-is (see report Section 3.3 for full justification):

- `tuttas/openplc_v3` — the soft PLC acting as the subject
- `honeynet/conpot` — the ICS honeypot repurposed as the simulated resource

**To build either PEP image:**

```bash
cd v1_request_filtering_pep   # or v2_historical_baseline_pep
docker build -t modbus-pep .
```

**To run the full testbed** (summarised; see report Chapter 3 and Chapter 5
for full command sequences and evaluation methodology):

```bash
# Create the isolated field-device network
docker network create --subnet=172.21.0.0/24 ot-field-net

# Run OpenPLC and Conpot (third-party images)
docker run -d -p 8080:8080 -p 502:502 --name openplc tuttas/openplc_v3
docker run -d -p 8800:8800 -p 5020:5020 -p 10201:10201 -p 16100:16100/udp --name conpot honeynet/conpot
docker network disconnect bridge conpot
docker network connect ot-field-net conpot

# Run the PEP, bridging both networks
docker run -d --network ot-testbed-net -p 5030:5020 --name pep modbus-pep
docker network connect ot-field-net pep
```

Full evaluation commands (the exact hand-crafted Modbus TCP frames used to
test each attack scenario) are documented in report Section 3.5 and shown
byte-for-byte in the evidence figures in Chapter 5.

## Relationship to the report

This artefact is the actual, runnable implementation of the design described
in Chapter 4. The full commented source (with additional inline explanation)
is also reproduced in the report's Appendix A (v1) and Appendix B (v2) for
convenient reading without needing to open these files separately.
