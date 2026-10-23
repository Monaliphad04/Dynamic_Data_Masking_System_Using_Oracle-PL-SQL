-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 9: Oracle VPD (DBMS_RLS) Policy Enforcement
-- Script:  tests/functional/test_phase9_vpd.sql
-- Target:  Oracle Database (ORCLPDB) - Run as APP_SERVICE_USER
-- Purpose: Rigorous test suite validating Oracle Virtual Private Database
--          kernel policies for row-level confinement and column suppression.
-- ============================================================================

SET ECHO OFF;
SET DEFINE OFF;
SET FEEDBACK OFF;
SET TIMING OFF;
SET LINESIZE 250;
SET PAGESIZE 50;
SET SERVEROUTPUT ON SIZE UNLIMITED;

PROMPT ========================================================================
PROMPT [PHASE 9 TEST SUITE] Oracle Virtual Private Database (VPD / RLS) Tests
PROMPT Connecting as APP_SERVICE_USER (Least-Privilege Application Client)
PROMPT ========================================================================

CONNECT APP_SERVICE_USER/AppService#Pass2026@localhost:1521/orclpdb
SET SERVEROUTPUT ON SIZE UNLIMITED;

DECLARE
    v_total_tests    INTEGER := 0;
    v_passed_tests   INTEGER := 0;
    v_failed_tests   INTEGER := 0;

    v_count          NUMBER;
    v_foreign_count  NUMBER;
    v_branch_count   NUMBER;
    v_sqlcode        NUMBER;
    v_null_email_cnt NUMBER;
    v_null_phone_cnt NUMBER;
    v_null_natid_cnt NUMBER;

    -- Assertion helper
    PROCEDURE ASSERT_TRUE(
        p_test_id   IN VARCHAR2,
        p_desc      IN VARCHAR2,
        p_condition IN BOOLEAN,
        p_details   IN VARCHAR2 DEFAULT NULL
    ) IS
    BEGIN
        v_total_tests := v_total_tests + 1;
        IF p_condition THEN
            v_passed_tests := v_passed_tests + 1;
            DBMS_OUTPUT.PUT_LINE('  [PASS] ' || RPAD(p_test_id, 14) || ' | ' || RPAD(p_desc, 50) || 
                                 CASE WHEN p_details IS NOT NULL THEN ' | ' || p_details END);
        ELSE
            v_failed_tests := v_failed_tests + 1;
            DBMS_OUTPUT.PUT_LINE('  [FAIL] ' || RPAD(p_test_id, 14) || ' | ' || RPAD(p_desc, 50) || 
                                 ' | ASSERTION FAILED: ' || p_details);
        END IF;
    END ASSERT_TRUE;

BEGIN
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    DBMS_OUTPUT.PUT_LINE('TEST CATEGORY 1: FAIL-CLOSED ROW CONFINEMENT (UNAUTHENTICATED CONTEXT)');
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');

    -- Test 1: Unauthenticated Session (Context Not Initialized)
    SEC_OWNER.PKG_SESSION_CTX.CLEAR_SESSION;
    SELECT COUNT(*) INTO v_count FROM VW_CUSTOMERS;
    ASSERT_TRUE(
        'TC_VPD_01',
        'Unauthenticated session returns zero rows',
        (v_count = 0),
        'Returned: ' || v_count || ' rows (Expected: 0)'
    );

    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    DBMS_OUTPUT.PUT_LINE('TEST CATEGORY 2: FRONTLINE AGENT ROW ISOLATION BY BRANCH');
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');

    -- Test 2: Agent Sarah (Assigned BR_NYC_01)
    SEC_OWNER.PKG_SESSION_CTX.INITIALIZE_SESSION('agent_sarah', '192.168.1.102');
    SEC_OWNER.PKG_SESSION_CTX.SET_SESSION_RISK(10, 'LOW');
    
    SELECT COUNT(*) INTO v_count FROM VW_CUSTOMERS;
    SELECT COUNT(*) INTO v_foreign_count FROM VW_CUSTOMERS WHERE branch_code != 'BR_NYC_01';
    
    ASSERT_TRUE(
        'TC_VPD_02A',
        'agent_sarah sees exactly 24 NYC customers',
        (v_count = 24),
        'Returned: ' || v_count || ' rows (Expected: 24)'
    );
    ASSERT_TRUE(
        'TC_VPD_02B',
        'agent_sarah cannot see any non-NYC rows',
        (v_foreign_count = 0),
        'Foreign branch rows leaked: ' || v_foreign_count || ' (Expected: 0)'
    );

    -- Test 3: Agent Mike (Assigned BR_LDN_02)
    SEC_OWNER.PKG_SESSION_CTX.INITIALIZE_SESSION('agent_mike', '192.168.1.102');
    SEC_OWNER.PKG_SESSION_CTX.SET_SESSION_RISK(15, 'LOW');

    SELECT COUNT(*) INTO v_count FROM VW_CUSTOMERS;
    SELECT COUNT(*) INTO v_foreign_count FROM VW_CUSTOMERS WHERE branch_code != 'BR_LDN_02';

    ASSERT_TRUE(
        'TC_VPD_03A',
        'agent_mike sees exactly 24 London customers',
        (v_count = 24),
        'Returned: ' || v_count || ' rows (Expected: 24)'
    );
    ASSERT_TRUE(
        'TC_VPD_03B',
        'agent_mike cannot see any non-London rows',
        (v_foreign_count = 0),
        'Foreign branch rows leaked: ' || v_foreign_count || ' (Expected: 0)'
    );

    -- Test 4: Analyst Bob (Assigned BR_SGP_03)
    SEC_OWNER.PKG_SESSION_CTX.INITIALIZE_SESSION('analyst_bob', '10.0.1.50');
    SEC_OWNER.PKG_SESSION_CTX.SET_SESSION_RISK(20, 'LOW');

    SELECT COUNT(*) INTO v_count FROM VW_CUSTOMERS;
    SELECT COUNT(*) INTO v_foreign_count FROM VW_CUSTOMERS WHERE branch_code != 'BR_SGP_03';

    ASSERT_TRUE(
        'TC_VPD_04A',
        'analyst_bob sees exactly 24 Singapore customers',
        (v_count = 24),
        'Returned: ' || v_count || ' rows (Expected: 24)'
    );
    ASSERT_TRUE(
        'TC_VPD_04B',
        'analyst_bob cannot see any non-Singapore rows',
        (v_foreign_count = 0),
        'Foreign branch rows leaked: ' || v_foreign_count || ' (Expected: 0)'
    );

    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    DBMS_OUTPUT.PUT_LINE('TEST CATEGORY 3: ADMINISTRATIVE & AUDIT CROSS-BRANCH VISIBILITY');
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');

    -- Test 5: Security Administrator Eleanor (SEC_ADMIN)
    SEC_OWNER.PKG_SESSION_CTX.INITIALIZE_SESSION('admin_user', '192.168.1.50');
    SEC_OWNER.PKG_SESSION_CTX.SET_SESSION_RISK(5, 'LOW');

    SELECT COUNT(*) INTO v_count FROM VW_CUSTOMERS;
    SELECT COUNT(DISTINCT branch_code) INTO v_branch_count FROM VW_CUSTOMERS;

    ASSERT_TRUE(
        'TC_VPD_05A',
        'admin_user (SEC_ADMIN) has full 120-row visibility',
        (v_count = 120),
        'Total rows visible: ' || v_count || ' (Expected: 120)'
    );
    ASSERT_TRUE(
        'TC_VPD_05B',
        'admin_user sees all 5 distinct branch locations',
        (v_branch_count = 5),
        'Distinct branches: ' || v_branch_count || ' (Expected: 5)'
    );

    -- Test 6: Compliance Auditor Carol (AUDITOR)
    SEC_OWNER.PKG_SESSION_CTX.INITIALIZE_SESSION('auditor_carol', '192.168.1.50');
    SEC_OWNER.PKG_SESSION_CTX.SET_SESSION_RISK(0, 'LOW');

    SELECT COUNT(*) INTO v_count FROM VW_CUSTOMERS;
    SELECT COUNT(DISTINCT branch_code) INTO v_branch_count FROM VW_CUSTOMERS;

    ASSERT_TRUE(
        'TC_VPD_06A',
        'auditor_carol (AUDITOR) has full 120-row visibility',
        (v_count = 120),
        'Total rows visible: ' || v_count || ' (Expected: 120)'
    );
    ASSERT_TRUE(
        'TC_VPD_06B',
        'auditor_carol spans all 5 distinct branch locations',
        (v_branch_count = 5),
        'Distinct branches: ' || v_branch_count || ' (Expected: 5)'
    );

    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    DBMS_OUTPUT.PUT_LINE('TEST CATEGORY 4: DYNAMIC MID-SESSION BRANCH SWITCHING');
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');

    -- Test 7: Switch branch dynamically without reconnecting
    SEC_OWNER.PKG_SESSION_CTX.INITIALIZE_SESSION('agent_sarah', '192.168.1.102');
    SEC_OWNER.PKG_SESSION_CTX.SET_BRANCH_CONTEXT('BR_TOK_05');

    SELECT COUNT(*) INTO v_count FROM VW_CUSTOMERS;
    SELECT COUNT(*) INTO v_foreign_count FROM VW_CUSTOMERS WHERE branch_code != 'BR_TOK_05';

    ASSERT_TRUE(
        'TC_VPD_07A',
        'Mid-session switch to BR_TOK_05 yields 24 rows',
        (v_count = 24),
        'Tokyo rows visible: ' || v_count || ' (Expected: 24)'
    );
    ASSERT_TRUE(
        'TC_VPD_07B',
        'Mid-session switch excludes all non-Tokyo rows',
        (v_foreign_count = 0),
        'Foreign branch rows leaked: ' || v_foreign_count || ' (Expected: 0)'
    );

    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    DBMS_OUTPUT.PUT_LINE('TEST CATEGORY 5: KERNEL COLUMN SUPPRESSION (DBMS_RLS.ALL_ROWS)');
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');

    -- Test 8: High Risk forces kernel column suppression to NULL
    SEC_OWNER.PKG_SESSION_CTX.INITIALIZE_SESSION('agent_sarah', '192.168.1.102');
    SEC_OWNER.PKG_SESSION_CTX.SET_SESSION_RISK(85, 'HIGH');

    -- Count sensitive columns that are suppressed to NULL by the kernel RLS policy
    SELECT 
        COUNT(CASE WHEN email IS NULL THEN 1 END),
        COUNT(CASE WHEN phone_number IS NULL THEN 1 END),
        COUNT(CASE WHEN national_id IS NULL THEN 1 END)
    INTO v_null_email_cnt, v_null_phone_cnt, v_null_natid_cnt
    FROM VW_CUSTOMERS;

    ASSERT_TRUE(
        'TC_VPD_08A',
        'High risk suppresses all 24 emails to NULL',
        (v_null_email_cnt = 24),
        'Suppressed emails: ' || v_null_email_cnt || '/24'
    );
    ASSERT_TRUE(
        'TC_VPD_08B',
        'High risk suppresses all 24 phone numbers to NULL',
        (v_null_phone_cnt = 24),
        'Suppressed phones: ' || v_null_phone_cnt || '/24'
    );
    ASSERT_TRUE(
        'TC_VPD_08C',
        'High risk suppresses all 24 national IDs to NULL',
        (v_null_natid_cnt = 24),
        'Suppressed national IDs: ' || v_null_natid_cnt || '/24'
    );

    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    DBMS_OUTPUT.PUT_LINE('TEST CATEGORY 6: BASE TABLE DIRECT ACCESS LOCKDOWN (DEFENSE IN DEPTH)');
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');

    -- Test 9: Direct Base Table Query Attempt by APP_SERVICE_USER
    BEGIN
        v_sqlcode := 0;
        EXECUTE IMMEDIATE 'SELECT COUNT(*) FROM SEC_OWNER.CUSTOMERS' INTO v_count;
    EXCEPTION
        WHEN OTHERS THEN
            v_sqlcode := SQLCODE;
    END;

    ASSERT_TRUE(
        'TC_VPD_09',
        'Direct query on SEC_OWNER.CUSTOMERS blocked (ORA-00942)',
        (v_sqlcode = -942),
        'Trapped SQLCODE: ' || v_sqlcode || ' (Expected: -942)'
    );

    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    DBMS_OUTPUT.PUT_LINE('TEST CATEGORY 7: ADMINISTRATIVE DISABLE / ENABLE TOGGLE');
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');

    -- Test 10: Toggle policy disable and re-enable
    BEGIN
        SEC_OWNER.PKG_VPD_POLICIES.DISABLE_POLICIES;
        SEC_OWNER.PKG_VPD_POLICIES.ENABLE_POLICIES;
        v_sqlcode := 0;
    EXCEPTION
        WHEN OTHERS THEN
            v_sqlcode := SQLCODE;
    END;

    ASSERT_TRUE(
        'TC_VPD_10',
        'Policy enable/disable helpers execute cleanly',
        (v_sqlcode = 0),
        'Executed without exception'
    );

    -- Clean up session
    SEC_OWNER.PKG_SESSION_CTX.CLEAR_SESSION;

    -- ------------------------------------------------------------------------
    -- Test Suite Summary
    -- ------------------------------------------------------------------------
    DBMS_OUTPUT.PUT_LINE('========================================================================');
    DBMS_OUTPUT.PUT_LINE('[PHASE 9 TEST SUITE SUMMARY]');
    DBMS_OUTPUT.PUT_LINE('  Total Tests Executed : ' || v_total_tests);
    DBMS_OUTPUT.PUT_LINE('  Tests Passed         : ' || v_passed_tests);
    DBMS_OUTPUT.PUT_LINE('  Tests Failed         : ' || v_failed_tests);

    IF v_failed_tests = 0 THEN
        DBMS_OUTPUT.PUT_LINE('  VERDICT              : 100% PASS - ALL VPD POLICIES VERIFIED!');
    ELSE
        DBMS_OUTPUT.PUT_LINE('  VERDICT              : FAILURE DETECTED - REVIEW FAILED ASSERTIONS.');
    END IF;
    DBMS_OUTPUT.PUT_LINE('========================================================================');

END;
/
