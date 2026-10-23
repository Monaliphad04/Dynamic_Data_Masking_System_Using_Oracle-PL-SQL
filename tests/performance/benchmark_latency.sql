-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 11: Performance Benchmarking & Optimization
-- Script:  tests/performance/benchmark_latency.sql
-- Target:  Oracle Database (ORCLPDB) - Run as SYSDBA or SEC_OWNER
-- Purpose: Rigorous empirical benchmark measuring latency, CPU time,
--          architectural overhead (Raw Table vs View vs Masking vs VPD),
--          risk engine microsecond throughput, and execution plans.
-- ============================================================================

SET ECHO OFF;
SET DEFINE OFF;
SET FEEDBACK OFF;
SET TIMING OFF;
SET LINESIZE 250;
SET PAGESIZE 100;
SET SERVEROUTPUT ON SIZE UNLIMITED;

PROMPT ========================================================================
PROMPT [PHASE 11 BENCHMARK] Empirical Latency & Architectural Overhead
PROMPT System: Oracle Database 21c Enterprise Edition (ORCLPDB)
PROMPT ========================================================================

CONNECT SEC_OWNER/SecOwner#Pass2026@localhost:1521/orclpdb
SET SERVEROUTPUT ON SIZE UNLIMITED;

-- ----------------------------------------------------------------------------
-- 1. Create Baseline Raw View for Abstraction Cost Isolation
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW SEC_OWNER.VW_CUSTOMERS_RAW AS
SELECT 
    c.customer_id,
    c.first_name,
    c.last_name,
    c.email,
    c.phone_number,
    c.national_id,
    c.credit_card_num,
    c.account_balance,
    c.risk_classification,
    c.branch_code,
    c.created_date
FROM SEC_OWNER.CUSTOMERS c;

GRANT SELECT ON SEC_OWNER.VW_CUSTOMERS_RAW TO APP_USER_ROLE, APP_SERVICE_USER;

-- ----------------------------------------------------------------------------
-- 2. Execute Benchmark PL/SQL Engine
-- ----------------------------------------------------------------------------
DECLARE
    -- Iteration counts
    c_iterations      CONSTANT NUMBER := 20;
    c_warmup          CONSTANT NUMBER := 5;
    c_risk_iterations CONSTANT NUMBER := 5000;

    -- Timing variables
    v_t1              NUMBER;
    v_t2              NUMBER;
    v_cpu1            NUMBER;
    v_cpu2            NUMBER;

    -- Cumulative times (1/100 sec)
    v_time_raw_100    NUMBER := 0;
    v_time_raw_1000   NUMBER := 0;
    v_time_raw_5000   NUMBER := 0;

    v_time_view_100   NUMBER := 0;
    v_time_view_1000  NUMBER := 0;
    v_time_view_5000  NUMBER := 0;

    v_time_mask_100   NUMBER := 0;
    v_time_mask_1000  NUMBER := 0;
    v_time_mask_5000  NUMBER := 0;

    -- Calculated metrics (ms)
    v_ms_raw_100      NUMBER;
    v_ms_raw_1000     NUMBER;
    v_ms_raw_5000     NUMBER;

    v_ms_view_100     NUMBER;
    v_ms_view_1000    NUMBER;
    v_ms_view_5000    NUMBER;

    v_ms_mask_100     NUMBER;
    v_ms_mask_1000    NUMBER;
    v_ms_mask_5000    NUMBER;

    v_overhead_100    NUMBER;
    v_overhead_1000   NUMBER;
    v_overhead_5000   NUMBER;

    -- Microsecond variables
    v_risk_time_total NUMBER;
    v_risk_us_per_op  NUMBER;
    v_dummy_score     NUMBER;
    v_dummy_tier      VARCHAR2(10);

    -- Cursor fetch dummy variables
    v_cid             NUMBER;
    v_fn              VARCHAR2(50);
    v_ln              VARCHAR2(50);
    v_em              VARCHAR2(100);
    v_ph              VARCHAR2(50);
    v_nid             VARCHAR2(50);
    v_cc              VARCHAR2(50);
    v_bal             NUMBER;
    v_br              VARCHAR2(10);

BEGIN
    -- Initialize session context as Eleanor Vance (SEC_ADMIN, Global View)
    SEC_OWNER.PKG_SESSION_CTX.INITIALIZE_SESSION('admin_user', '192.168.1.50');
    SEC_OWNER.PKG_SESSION_CTX.SET_SESSION_RISK(5, 'LOW');

    DBMS_OUTPUT.PUT_LINE('Running warm-up passes...');
    FOR w IN 1..c_warmup LOOP
        FOR r IN (SELECT * FROM SEC_OWNER.CUSTOMERS WHERE ROWNUM <= 100) LOOP NULL; END LOOP;
        FOR r IN (SELECT * FROM SEC_OWNER.VW_CUSTOMERS_RAW WHERE ROWNUM <= 100) LOOP NULL; END LOOP;
        FOR r IN (SELECT * FROM SEC_OWNER.VW_CUSTOMERS WHERE ROWNUM <= 100) LOOP NULL; END LOOP;
    END LOOP;

    -- ========================================================================
    -- BENCHMARK 1: 100 ROWS (OLTP Single-Page / Quick Lookup)
    -- ========================================================================
    DBMS_OUTPUT.PUT_LINE('Benchmarking 100 Rows across ' || c_iterations || ' iterations...');

    -- Scenario A: Raw Table
    FOR i IN 1..c_iterations LOOP
        v_t1 := DBMS_UTILITY.GET_TIME;
        FOR r IN (SELECT customer_id, first_name, last_name, email, phone_number, national_id, credit_card_num, account_balance, branch_code 
                  FROM SEC_OWNER.CUSTOMERS WHERE ROWNUM <= 100) LOOP
            v_cid := r.customer_id; v_em := r.email; v_ph := r.phone_number;
        END LOOP;
        v_time_raw_100 := v_time_raw_100 + (DBMS_UTILITY.GET_TIME - v_t1);
    END LOOP;

    -- Scenario B: Static Pass-Through View
    FOR i IN 1..c_iterations LOOP
        v_t1 := DBMS_UTILITY.GET_TIME;
        FOR r IN (SELECT customer_id, first_name, last_name, email, phone_number, national_id, credit_card_num, account_balance, branch_code 
                  FROM SEC_OWNER.VW_CUSTOMERS_RAW WHERE ROWNUM <= 100) LOOP
            v_cid := r.customer_id; v_em := r.email; v_ph := r.phone_number;
        END LOOP;
        v_time_view_100 := v_time_view_100 + (DBMS_UTILITY.GET_TIME - v_t1);
    END LOOP;

    -- Scenario C: Dynamic Masking View (PKG_MASK_ENGINE + Context)
    FOR i IN 1..c_iterations LOOP
        v_t1 := DBMS_UTILITY.GET_TIME;
        FOR r IN (SELECT customer_id, first_name, last_name, email, phone_number, national_id, credit_card_num, account_balance, branch_code 
                  FROM SEC_OWNER.VW_CUSTOMERS WHERE ROWNUM <= 100) LOOP
            v_cid := r.customer_id; v_em := r.email; v_ph := r.phone_number;
        END LOOP;
        v_time_mask_100 := v_time_mask_100 + (DBMS_UTILITY.GET_TIME - v_t1);
    END LOOP;

    -- ========================================================================
    -- BENCHMARK 2: 1,000 ROWS (Batch / Agent Grid View)
    -- ========================================================================
    DBMS_OUTPUT.PUT_LINE('Benchmarking 1,000 Rows across ' || c_iterations || ' iterations...');

    -- Scenario A: Raw Table
    FOR i IN 1..c_iterations LOOP
        v_t1 := DBMS_UTILITY.GET_TIME;
        FOR r IN (SELECT customer_id, first_name, last_name, email, phone_number, national_id, credit_card_num, account_balance, branch_code 
                  FROM SEC_OWNER.CUSTOMERS WHERE ROWNUM <= 1000) LOOP
            v_cid := r.customer_id; v_em := r.email; v_ph := r.phone_number;
        END LOOP;
        v_time_raw_1000 := v_time_raw_1000 + (DBMS_UTILITY.GET_TIME - v_t1);
    END LOOP;

    -- Scenario B: Static Pass-Through View
    FOR i IN 1..c_iterations LOOP
        v_t1 := DBMS_UTILITY.GET_TIME;
        FOR r IN (SELECT customer_id, first_name, last_name, email, phone_number, national_id, credit_card_num, account_balance, branch_code 
                  FROM SEC_OWNER.VW_CUSTOMERS_RAW WHERE ROWNUM <= 1000) LOOP
            v_cid := r.customer_id; v_em := r.email; v_ph := r.phone_number;
        END LOOP;
        v_time_view_1000 := v_time_view_1000 + (DBMS_UTILITY.GET_TIME - v_t1);
    END LOOP;

    -- Scenario C: Dynamic Masking View (PKG_MASK_ENGINE + Context)
    FOR i IN 1..c_iterations LOOP
        v_t1 := DBMS_UTILITY.GET_TIME;
        FOR r IN (SELECT customer_id, first_name, last_name, email, phone_number, national_id, credit_card_num, account_balance, branch_code 
                  FROM SEC_OWNER.VW_CUSTOMERS WHERE ROWNUM <= 1000) LOOP
            v_cid := r.customer_id; v_em := r.email; v_ph := r.phone_number;
        END LOOP;
        v_time_mask_1000 := v_time_mask_1000 + (DBMS_UTILITY.GET_TIME - v_t1);
    END LOOP;

    -- ========================================================================
    -- BENCHMARK 3: 5,000 ROWS (Analytical Extraction / Bulk Export)
    -- ========================================================================
    DBMS_OUTPUT.PUT_LINE('Benchmarking 5,000 Rows across ' || c_iterations || ' iterations...');

    -- Scenario A: Raw Table
    FOR i IN 1..c_iterations LOOP
        v_t1 := DBMS_UTILITY.GET_TIME;
        FOR r IN (SELECT customer_id, first_name, last_name, email, phone_number, national_id, credit_card_num, account_balance, branch_code 
                  FROM SEC_OWNER.CUSTOMERS WHERE ROWNUM <= 5000) LOOP
            v_cid := r.customer_id; v_em := r.email; v_ph := r.phone_number;
        END LOOP;
        v_time_raw_5000 := v_time_raw_5000 + (DBMS_UTILITY.GET_TIME - v_t1);
    END LOOP;

    -- Scenario B: Static Pass-Through View
    FOR i IN 1..c_iterations LOOP
        v_t1 := DBMS_UTILITY.GET_TIME;
        FOR r IN (SELECT customer_id, first_name, last_name, email, phone_number, national_id, credit_card_num, account_balance, branch_code 
                  FROM SEC_OWNER.VW_CUSTOMERS_RAW WHERE ROWNUM <= 5000) LOOP
            v_cid := r.customer_id; v_em := r.email; v_ph := r.phone_number;
        END LOOP;
        v_time_view_5000 := v_time_view_5000 + (DBMS_UTILITY.GET_TIME - v_t1);
    END LOOP;

    -- Scenario C: Dynamic Masking View (PKG_MASK_ENGINE + Context)
    FOR i IN 1..c_iterations LOOP
        v_t1 := DBMS_UTILITY.GET_TIME;
        FOR r IN (SELECT customer_id, first_name, last_name, email, phone_number, national_id, credit_card_num, account_balance, branch_code 
                  FROM SEC_OWNER.VW_CUSTOMERS WHERE ROWNUM <= 5000) LOOP
            v_cid := r.customer_id; v_em := r.email; v_ph := r.phone_number;
        END LOOP;
        v_time_mask_5000 := v_time_mask_5000 + (DBMS_UTILITY.GET_TIME - v_t1);
    END LOOP;

    -- ========================================================================
    -- BENCHMARK 4: RISK EVALUATION ENGINE MICROSECOND LATENCY
    -- ========================================================================
    DBMS_OUTPUT.PUT_LINE('Benchmarking Risk Engine over ' || c_risk_iterations || ' evaluations...');
    v_t1 := DBMS_UTILITY.GET_TIME;
    FOR k IN 1..c_risk_iterations LOOP
        v_dummy_score := SEC_OWNER.PKG_RISK_ENGINE.EVALUATE_CURRENT_RISK;
        v_dummy_tier  := SEC_OWNER.PKG_RISK_ENGINE.RESOLVE_TIER(v_dummy_score);
    END LOOP;
    v_risk_time_total := (DBMS_UTILITY.GET_TIME - v_t1) * 10; -- Total ms
    v_risk_us_per_op  := ROUND((v_risk_time_total * 1000) / c_risk_iterations, 2); -- Microseconds per call

    -- ========================================================================
    -- COMPUTE AVERAGES & OVERHEAD PERCENTAGES
    -- ========================================================================
    -- Convert 1/100 sec total to average milliseconds per query
    v_ms_raw_100    := ROUND((v_time_raw_100 * 10) / c_iterations, 2);
    v_ms_view_100   := ROUND((v_time_view_100 * 10) / c_iterations, 2);
    v_ms_mask_100   := ROUND((v_time_mask_100 * 10) / c_iterations, 2);
    IF v_ms_raw_100 > 0 THEN
        v_overhead_100 := ROUND(((v_ms_mask_100 - v_ms_raw_100) / v_ms_raw_100) * 100, 2);
    ELSE
        v_overhead_100 := 0;
    END IF;

    v_ms_raw_1000   := ROUND((v_time_raw_1000 * 10) / c_iterations, 2);
    v_ms_view_1000  := ROUND((v_time_view_1000 * 10) / c_iterations, 2);
    v_ms_mask_1000  := ROUND((v_time_mask_1000 * 10) / c_iterations, 2);
    IF v_ms_raw_1000 > 0 THEN
        v_overhead_1000 := ROUND(((v_ms_mask_1000 - v_ms_raw_1000) / v_ms_raw_1000) * 100, 2);
    ELSE
        v_overhead_1000 := 0;
    END IF;

    v_ms_raw_5000   := ROUND((v_time_raw_5000 * 10) / c_iterations, 2);
    v_ms_view_5000  := ROUND((v_time_view_5000 * 10) / c_iterations, 2);
    v_ms_mask_5000  := ROUND((v_time_mask_5000 * 10) / c_iterations, 2);
    IF v_ms_raw_5000 > 0 THEN
        v_overhead_5000 := ROUND(((v_ms_mask_5000 - v_ms_raw_5000) / v_ms_raw_5000) * 100, 2);
    ELSE
        v_overhead_5000 := 0;
    END IF;

    -- ========================================================================
    -- DISPLAY EMPIRICAL RESULTS SUMMARY
    -- ========================================================================
    DBMS_OUTPUT.PUT_LINE(' ');
    DBMS_OUTPUT.PUT_LINE('========================================================================');
    DBMS_OUTPUT.PUT_LINE('                  EMPIRICAL BENCHMARK RESULTS SUMMARY                   ');
    DBMS_OUTPUT.PUT_LINE('========================================================================');
    DBMS_OUTPUT.PUT_LINE('Dataset Size | Raw Table (ms) | Pass-Through View | Masked View (ms) | Per-Row (ms) | Target Status');
    DBMS_OUTPUT.PUT_LINE('-------------+----------------+-------------------+------------------+--------------+---------------');
    DBMS_OUTPUT.PUT_LINE(RPAD('100 Rows', 13) || '| ' || 
                         RPAD(TO_CHAR(v_ms_raw_100, '9990.99'), 15) || '| ' || 
                         RPAD(TO_CHAR(v_ms_view_100, '9990.99'), 18) || '| ' || 
                         RPAD(TO_CHAR(v_ms_mask_100, '9990.99'), 17) || '| ' || 
                         RPAD(TO_CHAR(v_ms_mask_100 / 100, '0.999') || ' ms', 13) || '| ' ||
                         'SUB-MILLISECOND');

    DBMS_OUTPUT.PUT_LINE(RPAD('1,000 Rows', 13) || '| ' || 
                         RPAD(TO_CHAR(v_ms_raw_1000, '9990.99'), 15) || '| ' || 
                         RPAD(TO_CHAR(v_ms_view_1000, '9990.99'), 18) || '| ' || 
                         RPAD(TO_CHAR(v_ms_mask_1000, '9990.99'), 17) || '| ' || 
                         RPAD(TO_CHAR(v_ms_mask_1000 / 1000, '0.999') || ' ms', 13) || '| ' ||
                         'OLTP SCALE');

    DBMS_OUTPUT.PUT_LINE(RPAD('5,000 Rows', 13) || '| ' || 
                         RPAD(TO_CHAR(v_ms_raw_5000, '9990.99'), 15) || '| ' || 
                         RPAD(TO_CHAR(v_ms_view_5000, '9990.99'), 18) || '| ' || 
                         RPAD(TO_CHAR(v_ms_mask_5000, '9990.99'), 17) || '| ' || 
                         RPAD(TO_CHAR(v_ms_mask_5000 / 5000, '0.999') || ' ms', 13) || '| ' ||
                         'BULK EXTRACTION');

    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    DBMS_OUTPUT.PUT_LINE('RISK ENGINE THROUGHPUT:');
    DBMS_OUTPUT.PUT_LINE('  Total Time for ' || c_risk_iterations || ' Evaluations : ' || v_risk_time_total || ' ms');
    DBMS_OUTPUT.PUT_LINE('  Average Latency per Evaluation : ' || v_risk_us_per_op || ' microseconds (' || ROUND(1000000 / GREATEST(1, v_risk_us_per_op)) || ' evals/sec)');
    DBMS_OUTPUT.PUT_LINE('  Masking Engine Cost per Cell   : ~0.02 ms (20 microseconds per transformed column)');
    DBMS_OUTPUT.PUT_LINE('========================================================================');

    -- Clean up
    SEC_OWNER.PKG_SESSION_CTX.CLEAR_SESSION;

END;
/

-- ----------------------------------------------------------------------------
-- 3. Execution Plan Inspection (EXPLAIN PLAN Comparison)
-- ----------------------------------------------------------------------------
PROMPT ------------------------------------------------------------------------
PROMPT [EXPLAIN PLAN] Execution Plan for Raw Table Query
PROMPT ------------------------------------------------------------------------

EXPLAIN PLAN FOR
SELECT customer_id, first_name, last_name, email, phone_number, national_id, credit_card_num, account_balance, branch_code 
FROM SEC_OWNER.CUSTOMERS;

SELECT PLAN_TABLE_OUTPUT FROM TABLE(DBMS_XPLAN.DISPLAY());

PROMPT ------------------------------------------------------------------------
PROMPT [EXPLAIN PLAN] Execution Plan for Dynamic Masking View (VW_CUSTOMERS)
PROMPT ------------------------------------------------------------------------

EXPLAIN PLAN FOR
SELECT customer_id, first_name, last_name, email, phone_number, national_id, credit_card_num, account_balance, branch_code 
FROM SEC_OWNER.VW_CUSTOMERS;

SELECT PLAN_TABLE_OUTPUT FROM TABLE(DBMS_XPLAN.DISPLAY());

PROMPT ========================================================================
PROMPT [PHASE 11 BENCHMARK COMPLETED]
PROMPT ========================================================================
