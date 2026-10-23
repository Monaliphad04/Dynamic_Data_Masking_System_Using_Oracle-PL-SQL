# Context-Aware Dynamic Data Masking System Using Oracle PL/SQL

[![Database](https://img.shields.io/badge/Database-Oracle%2023ai%20%7C%2021c%20XE-F80000?logo=oracle&logoColor=white)](https://www.oracle.com/database/)
[![Language](https://img.shields.io/badge/Language-PL%2FSQL-orange)](#)
[![Security](https://img.shields.io/badge/Security-VPD%20%7C%20SYS__CONTEXT%20%7C%20DBMS__RLS-darkgreen)](#)
[![Auditing](https://img.shields.io/badge/Audit-DBMS__FGA%20%7C%20Autonomous-blue)](#)
[![License](https://img.shields.io/badge/License-Academic%20Project-lightgrey)](#)

An enterprise-grade, risk-adaptive database security solution designed in Oracle PL/SQL. The system dynamically modulates the visibility of sensitive database columns (PII, contact details, national identifiers, and financial balances) based on real-time operational context—such as user role, access time, network origin, query velocity, and historical anomalies.

---

## 1. Problem Statement

Traditional Discretionary Access Control (DAC) and static column masking models enforce uniform visibility rules:
- **Excessive Exposure:** An authorized user querying sensitive data outside business hours or from an unrecognized network receives the exact same unmasked view as during routine operations.
- **Over-Restriction:** Permanent hard redaction inhibits legitimate operational workflows.
- **Static Inflexibility:** Masking rules do not adapt to anomalous query velocity or credential compromise signals.

## 2. Proposed Solution

This project implements a **Context-Aware Dynamic Data Masking Engine** operating natively inside Oracle Database:
1. **Dynamic Risk Evaluation:** Evaluates multi-variable session context and assigns a real-time risk score ($0$ to $100$).
2. **Three-Tier Adaptive Obfuscation:**
   - **Low Risk (0–29):** Full cleartext data displayed according to role authorization.
   - **Medium Risk (30–69):** In-flight partial masking (e.g., phone: `+1-555-***-**49`, email: `j***@corp.com`).
   - **High Risk (70–100):** Complete column redaction (e.g., `[REDACTED]`, `***-***-****`).
3. **Guaranteed Non-Escalation:** Risk evaluation can only *downgrade* visibility (increase masking); it can **never** reveal data beyond what the user's base role permits.
4. **Zero Persistent Alteration:** Underlying disk storage retains pristine, unmasked data. All masking is computed ephemerally in-memory during query projection.
5. **Fail-Closed Security:** Corrupted, missing, or unauthenticated contexts automatically default to maximum risk ($100$) and full data redaction.

---

## 3. System Architecture

```text
       +--------------------------------------------------------+
       |               Client Tier (SQL Client / App)           |
       +--------------------------------------------------------+
                                   |
                         1. Connect & Initialize
                                   v
       +--------------------------------------------------------+
       |   Trusted Context Engine (PKG_SESSION_CTX / SYS_CTX)   |
       +--------------------------------------------------------+
                                   |
                          2. Execute SELECT Query
                                   v
       +--------------------------------------------------------+
       |           Secure Views (VW_CUSTOMERS) + VPD            |
       |                   (DBMS_RLS Policy)                    |
       +--------------------------------------------------------+
                 |                                    |
     3. Query Risk Level                     4. Transform Columns
                 v                                    v
       +-----------------------+            +-------------------+
       |    PKG_RISK_ENGINE    |            |  PKG_MASK_ENGINE  |
       | (Weights, Rules, Logs)|            | (Phone, Email, ID)|
       +-----------------------+            +-------------------+
                 |                                    |
                 +-----------------+------------------+
                                   |
                          5. In-Flight Projection
                                   v
       +--------------------------------------------------------+
       |        Base Tables (CUSTOMERS, Protected Schema)       |
       +--------------------------------------------------------+
                                   |
                         6. Autonomous Read Audit
                                   v
       +--------------------------------------------------------+
       |         ACCESS_LOGS (Autonomous Transaction / FGA)     |
       +--------------------------------------------------------+
```

---

## 4. Technology Stack

- **RDBMS:** Oracle Database Free (23ai) or Oracle Database 21c Express Edition (XE).
- **Database Programming:** Oracle PL/SQL (Packages, Deterministic Functions, Autonomous Procedures).
- **Access Control:** Virtual Private Database (`DBMS_RLS`), Application Context (`SYS_CONTEXT`), and Oracle Role Separation.
- **Audit Logging:** Oracle Fine-Grained Auditing (`DBMS_FGA`) & Autonomous Transaction Audit Buffers.
- **SQL Clients:** Oracle SQL Developer, SQLcl, or VS Code Oracle Developer Tools.
- **Optional Demonstration UI (Phase 12):** Python FastAPI backend with a React.js + Vite + Tailwind CSS dashboard.

---

## 5. Repository Structure

```text
DB_Project_M/
├── PLAN.md                               # Master Phased Implementation Plan & Checklist
├── README.md                             # Project Overview & Quickstart Guide
├── .gitignore                            # Secret & environment exclusions
│
├── docs/                                 # Academic Documentation & Technical Specs
│   ├── ARCHITECTURE.md                   # Detailed Architecture & Threat Model
│   ├── DATABASE_DESIGN.md                # Data Dictionary & Schema Specifications
│   ├── RISK_SCORING_SPEC.md              # Mathematical Scoring & Signal Specifications
│   ├── BENCHMARK_RESULTS.md              # Empirical Performance Test Logs
│   ├── USER_GUIDE.md                     # Installation & Runbook
│   └── FINAL_REPORT.md                   # Academic Project Report & Presentation Summary
│
├── sql/                                  # Sequential Database Source Scripts
│   ├── schema/                           # DDL: Base tables, sequences, constraints, mock data
│   ├── security/                         # User accounts, least-privilege roles, contexts, FGA
│   ├── procedures/                       # PL/SQL packages: Session context, risk engine, audit
│   ├── functions/                        # PL/SQL packages: Dynamic masking engine algorithms
│   ├── views/                            # Secure dynamic views (VW_CUSTOMERS)
│   └── policies/                         # Oracle VPD / DBMS_RLS security policies
│
├── tests/                                # Automated SQL Test Harnesses
│   ├── functional/                       # Unit tests for masking and scoring logic
│   ├── security/                         # Negative testing: Bypass attempts, injection, tampering
│   └── performance/                      # Latency, execution plan, and overhead benchmarks
│
├── app/                                  # Optional Interactive Demonstration (Phase 12)
│   ├── requirements.txt                  # Python dependencies (fastapi, oracledb, uvicorn)
│   ├── database.py                       # Connection pooling and query gateway
│   ├── main.py                           # REST API endpoints
│   └── frontend/                         # React.js + Vite + Tailwind CSS web dashboard
│
└── screenshots/                          # Visual Test Evidence & Defense Demonstrations
```

---

## 6. Implementation Roadmap

| Phase | Milestone | Status |
|:---:|---|:---:|
| **Phase 1** | Workspace & Requirements Baseline | Completed |
| **Phase 2** | Oracle Environment & User Setup | Completed |
| **Phase 3** | Schema Creation & Synthetic Data Population | Completed |
| **Phase 4** | Trusted Context & Session Management | Completed |
| **Phase 5** | Core Masking Functions & Algorithms | Completed |
| **Phase 6** | Rule-Based Risk Scoring Engine | Completed |
| **Phase 7** | Auditing Architecture & Autonomous Logging | Completed |
| **Phase 8** | Dynamic Masking Views & Integration | Completed |
| **Phase 9** | Oracle VPD (`DBMS_RLS`) Policy Enforcement | Completed |
| **Phase 10** | Comprehensive Security & Bypass Testing | Completed |
| **Phase 11** | Performance Benchmarking & Optimization | Completed |
| **Phase 12** | Interactive Web API & Dynamic Dashboard (FastAPI + Cyber UI) | Completed |
| **Phase 13** | Academic Documentation, Demo, & Presentation | Ready |

---

## 7. Security & Academic Integrity Notes

- **Synthetic Data Only:** The database schema is populated exclusively with realistically generated fictional customer records. No real PII or confidential information is used.
- **Fail-Closed Design:** Any failure in the risk calculation engine falls back to maximum security (full redaction).
- **Separation of Duties:** Base tables are strictly locked from application users; access is mediated exclusively through secure views and VPD policies.
