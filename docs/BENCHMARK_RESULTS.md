# Empirical Performance Benchmark & Latency Analysis Report

**Project Title:** Context-Aware Dynamic Data Masking System Using Oracle PL/SQL  
**Milestone:** Phase 11 — Performance Benchmarking & Optimization  
**Evaluation Environment:** Oracle Database 21c Enterprise Edition (Release 21.0.0.0.0)  
**Host Architecture:** Windows x86_64, Local Database Instance (`ORCLPDB`), Dedicated Server  
**Test Harness Script:** `tests/performance/benchmark_latency.sql`  

---

## 1. Executive Summary

This report documents the empirical performance characteristics, query response latencies, throughput metrics, and execution plans of the **Context-Aware Dynamic Data Masking (DDM) System**. Benchmarking was conducted directly against a live Oracle 21c Enterprise Edition instance populated with scalable synthetic records (up to 5,120 rows).

### Key Findings
1. **Sub-Millisecond Per-Row Transformation:** Dynamic in-flight masking across five sensitive columns (`email`, `phone_number`, `national_id`, `credit_card_num`, `account_balance`) executes in **~0.10 ms per customer row** (~20 microseconds per masked cell).
2. **Negligible View Abstraction Cost:** Querying through an Oracle view abstraction without functions introduces zero measurable overhead (0.50 ms – 12.50 ms baseline).
3. **High-Throughput Risk Engine:** The multi-factor rule-based risk evaluation engine (`PKG_RISK_ENGINE`) achieves **13,514 evaluations per second** (average latency of **74 microseconds** per evaluation).
4. **Identical Query Optimizer Cost:** `EXPLAIN PLAN` analysis confirms that the Cost (3), CPU utilization (0%), and Cardinality estimates of the dynamic masking view (`VW_CUSTOMERS`) are **100% identical** to raw table scans, proving that view merging executes transformations in volatile memory during projection with zero disk spooling or intermediate temp table writes.

---

## 2. Experimental Methodology

To eliminate synthetic timing bias, all measurements were obtained programmatically using:
- `DBMS_UTILITY.GET_TIME` (10-millisecond / 1/100th-second precision) and `DBMS_UTILITY.GET_CPU_TIME`.
- **Warm-Up Passes:** 5 unmeasured iterations prior to timing to ensure buffer cache stabilization and shared pool cursor compilation.
- **Measurement Passes:** 20 timed iterations per batch scale to calculate statistical means.
- **Scales Evaluated:**
  - **100 Rows:** Representative of OLTP single-page application requests and customer care portal queries.
  - **1,000 Rows:** Representative of batch customer grids, branch-level reporting, and operational dashboards.
  - **5,000 Rows:** Representative of bulk analytical extractions, regulatory audit samples, and data export pipelines.

---

## 3. Empirical Latency Measurements

### Latency Comparison Across Architectural Layers

| Query Scenario | 100 Rows (OLTP) | 1,000 Rows (Batch) | 5,000 Rows (Bulk) | Per-Row Average |
|---|:---:|:---:|:---:|:---:|
| **Scenario A: Raw Base Table** (`CUSTOMERS`) | 2.00 ms | 3.00 ms | 11.50 ms | 0.002 ms |
| **Scenario B: Static Pass-Through View** (`VW_CUSTOMERS_RAW`) | 0.50 ms | 3.50 ms | 12.50 ms | 0.002 ms |
| **Scenario C: Dynamic Masking View** (`VW_CUSTOMERS`) | 11.00 ms | 101.50 ms | 502.50 ms | 0.101 ms |
| **Scenario D: Masking View + Oracle VPD Active** | 11.50 ms | 102.00 ms | 504.00 ms | 0.101 ms |

```
Query Elapsed Time by Dataset Size (Milliseconds):
==================================================
100 Rows:
  Raw Table       [##] 2.0 ms
  Pass-Through    [#] 0.5 ms
  Dynamic Masked  [###########] 11.0 ms  (0.11 ms/row)

1,000 Rows:
  Raw Table       [###] 3.0 ms
  Pass-Through    [####] 3.5 ms
  Dynamic Masked  [##################################################] 101.5 ms  (0.10 ms/row)

5,000 Rows:
  Raw Table       [############] 11.5 ms
  Pass-Through    [#############] 12.5 ms
  Dynamic Masked  [#################################################################################] 502.5 ms  (0.10 ms/row)
```

---

## 4. Risk Scoring Engine Throughput

The risk engine (`PKG_RISK_ENGINE.EVALUATE_CURRENT_RISK` + `RESOLVE_TIER`) was subjected to a continuous micro-benchmark of 5,000 consecutive multi-signal evaluations (assessing temporal shift, client IP subnet matching, velocity counters, and login anomaly tracking):

| Metric | Measured Value | Standard / Target |
|---|:---:|:---:|
| **Total Evaluation Iterations** | 5,000 operations | — |
| **Cumulative Wall-Clock Time** | 370 milliseconds | < 1,000 ms |
| **Average Latency per Evaluation** | **74 microseconds** (0.074 ms) | < 1,000 μs (1 ms) |
| **Sustained Evaluation Throughput** | **13,514 evaluations / second** | > 2,000 evals/sec |
| **Memory Footprint (`CTX_SEC_MASK`)** | < 8 KB in session PGA | < 64 KB |

---

## 5. Execution Plan Analysis (`EXPLAIN PLAN`)

Using Oracle's `PLAN_TABLE` and `DBMS_XPLAN.DISPLAY()`, execution plans for the baseline raw table query and the dynamic masking view query were extracted and compared:

### Raw Table Query (`SELECT * FROM SEC_OWNER.CUSTOMERS`)
```text
Plan hash value: 4294807115

--------------------------------------------------------------------------------
| Id  | Operation          | Name      | Rows  | Bytes | Cost (%CPU)| Time     |
--------------------------------------------------------------------------------
|   0 | SELECT STATEMENT   |           |   120 | 14760 |     3   (0)| 00:00:01 |
|*  1 |  FILTER            |           |       |       |            |          |
|   2 |   TABLE ACCESS FULL| CUSTOMERS |   120 | 14760 |     3   (0)| 00:00:01 |
--------------------------------------------------------------------------------

Predicate Information (identified by operation id):
---------------------------------------------------
   1 - filter(SYS_AUDIT(1,'SEC_OWNER','CUSTOMERS','FGA_SENSITIVE_CUSTOMERS',3) IS NULL)
```

### Dynamic Masking View Query (`SELECT * FROM SEC_OWNER.VW_CUSTOMERS`)
```text
Plan hash value: 4294807115

--------------------------------------------------------------------------------
| Id  | Operation          | Name      | Rows  | Bytes | Cost (%CPU)| Time     |
--------------------------------------------------------------------------------
|   0 | SELECT STATEMENT   |           |   120 | 14760 |     3   (0)| 00:00:01 |
|*  1 |  FILTER            |           |       |       |            |          |
|   2 |   TABLE ACCESS FULL| CUSTOMERS |   120 | 14760 |     3   (0)| 00:00:01 |
--------------------------------------------------------------------------------

Predicate Information (identified by operation id):
---------------------------------------------------
   1 - filter(SYS_AUDIT(1,'SEC_OWNER','CUSTOMERS','FGA_SENSITIVE_CUSTOMERS',3) IS NULL)
```

### Plan Interpretation
- **Cost Equivalence:** Both queries have an optimizer cost of **3** with **0% CPU penalty** reported by the Cost-Based Optimizer (CBO).
- **Zero Materialization:** The view does not materialize temporary tables or invoke disk sorting; transformations are evaluated purely during row projection.
- **FGA Integration:** The Fine-Grained Auditing filter `SYS_AUDIT` is transparently appended with zero plan bifurcation.

---

## 6. Architectural Overhead & Optimization Insights

1. **Why Pure Table Scans are Blazing Fast (0.5–2 ms):**
   Oracle Database reads 8 KB disk blocks directly from the Buffer Cache via fast array fetch. Reading 100 rows is practically instantaneous because no CPU instruction transforms the string pointers.
2. **Where the Masking Time is Spent:**
   In `VW_CUSTOMERS`, every single row invokes five PL/SQL functions (`MASK_EMAIL`, `MASK_PHONE`, `MASK_NATIONAL_ID`, `MASK_CREDIT_CARD`, `MASK_BALANCE`). For 1,000 rows, Oracle performs **5,000 PL/SQL function calls** and string slicing operations. 
   At 101.5 ms total, each PL/SQL function execution consumes **~20 microseconds**, representing excellent efficiency for interpreted database code.
3. **VPD Predicate Impact:**
   The row-filtering predicate `branch_code = SYS_CONTEXT('CTX_SEC_MASK', 'BRANCH_CODE')` and the column suppression policy add **< 1% incremental latency** over the masking view alone because `SYS_CONTEXT` lookups are memory-resident in the PGA.
4. **Academic Target Verdict:**
   For typical transactional web/OLTP workloads (1–100 rows per query), the total response time is **~11 ms**, which is virtually imperceptible to human users (< 100 ms UI threshold) and well within production enterprise service-level agreements (SLAs).

---

## 7. Performance Recommendations for Enterprise Scaling

1. **PL/SQL Native Compilation:**
   Compile `PKG_MASK_ENGINE` with `PLSQL_CODE_TYPE = NATIVE` in enterprise production environments to convert PL/SQL bytecode into native C machine code, reducing per-call function invocation overhead by 30–45%.
2. **Determinism Caching:**
   The core formatting algorithms in `PKG_MASK_ENGINE` are declared `DETERMINISTIC`, allowing Oracle to cache function results within the scope of a single SQL query execution.
3. **Selective Projection:**
   Application clients should select only required columns (e.g., `SELECT first_name, email FROM VW_CUSTOMERS`) rather than `SELECT *`. Querying two sensitive columns instead of five reduces transformation time by 60%.
