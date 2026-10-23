-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 10: Comprehensive Security & Adversarial Bypass Testing
-- Script:  tests/security/test_security_bypass.sql
-- Target:  Oracle Database (ORCLPDB) - Run as APP_SERVICE_USER / SEC_OWNER
-- Purpose: Rigorous adversarial negative testing suite verifying that injection
--          attacks, direct bypass attempts, tampering, and unauthenticated
--          states fail closed with ZERO information leakage.
-- ============================================================================

SET ECHO OFF;
SET DEFINE OFF;
SET FEEDBACK OFF;
SET TIMING OFF;
SET LINESIZE 250;
SET PAGESIZE 50;
SET SERVEROUTPUT ON SIZE UNLIMITED;

PROMPT ========================================================================
PROMPT [PHASE 10: SUITE 1] Adversarial Security & Bypass Resistance Tests
PROMPT Executing negative security tests against Oracle SQL engine & context
PROMPT ========================================================================

CONNECT APP_SERVICE_USER/AppService#Pass2026@localhost:1521/orclpdb
SET SERVEROUTPUT ON SIZE UNLIMITED;

DECLARE
    v_total_tests    INTEGER := 0;
    v_passed_tests   INTEGER := 0;
    v_failed_tests   INTEGER := 0;

    v_count          NUMBER;
    v_sqlcode        NUMBER;
    v_sqlerrm        VARCHAR2(255);
    v_status         VARCHAR2(50);
    v_risk_score     NUMBER;
    v_risk_tier      VARCHAR2(10);
    v_context_val    VARCHAR2(50);
    v_foreign_cnt    NUMBER;
    v_null_phone     VARCHAR2(50);
    v_null_email     VARCHAR2(50);

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
    -- ------------------------------------------------------------------------
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    DBMS_OUTPUT.PUT_LINE('TEST CATEGORY 1: DIRECT BASE TABLE ACCESS LOCKDOWN (NEGATIVE TEST)');
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    -- ------------------------------------------------------------------------

    -- TC_BYPASS_01: Direct query attempt on underlying base table CUSTOMERS
    BEGIN
        v_sqlcode := 0;
        EXECUTE IMMEDIATE 'SELECT COUNT(*) FROM SEC_OWNER.CUSTOMERS' INTO v_count;
    EXCEPTION
        WHEN OTHERS THEN
            v_sqlcode := SQLCODE;
            v_sqlerrm := SQLERRM;
    END;

    ASSERT_TRUE(
        'TC_BYPASS_01',
        'Direct query on SEC_OWNER.CUSTOMERS blocked',
        (v_sqlcode = -942),
        'Trapped SQLCODE: ' || v_sqlcode || ' (Expected: -942 table or view does not exist)'
    );

    -- TC_BYPASS_02: Direct DML attempt on CUSTOMERS table
    BEGIN
        v_sqlcode := 0;
        EXECUTE IMMEDIATE 'INSERT INTO SEC_OWNER.CUSTOMERS (first_name, last_name, email, phone_number, national_id, branch_code) ' ||
                          'VALUES (''Hacker'', ''Test'', ''h@x.com'', ''123'', ''999'', ''BR_NYC_01'')';
    EXCEPTION
        WHEN OTHERS THEN
            v_sqlcode := SQLCODE;
    END;

    ASSERT_TRUE(
        'TC_BYPASS_02',
        'Direct INSERT into SEC_OWNER.CUSTOMERS blocked',
        (v_sqlcode = -942),
        'Trapped SQLCODE: ' || v_sqlcode || ' (Expected: -942)'
    );

    -- ------------------------------------------------------------------------
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    DBMS_OUTPUT.PUT_LINE('TEST CATEGORY 2: DIRECT CONTEXT NAMESPACE TAMPERING ATTEMPTS');
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    -- ------------------------------------------------------------------------

    -- TC_BYPASS_03: Attempt to self-lower risk score directly via DBMS_SESSION
    BEGIN
        v_sqlcode := 0;
        DBMS_SESSION.SET_CONTEXT('CTX_SEC_MASK', 'RISK_SCORE', '0');
    EXCEPTION
        WHEN OTHERS THEN
            v_sqlcode := SQLCODE;
    END;

    ASSERT_TRUE(
        'TC_BYPASS_03',
        'Direct DBMS_SESSION.SET_CONTEXT(RISK_SCORE, 0) fails',
        (v_sqlcode = -1031),
        'Trapped SQLCODE: ' || v_sqlcode || ' (Expected: -1031 insufficient privileges)'
    );

    -- TC_BYPASS_04: Attempt to spoof role directly via DBMS_SESSION
    BEGIN
        v_sqlcode := 0;
        DBMS_SESSION.SET_CONTEXT('CTX_SEC_MASK', 'ROLE_NAME', 'SEC_ADMIN');
    EXCEPTION
        WHEN OTHERS THEN
            v_sqlcode := SQLCODE;
    END;

    ASSERT_TRUE(
        'TC_BYPASS_04',
        'Direct DBMS_SESSION.SET_CONTEXT(ROLE_NAME) fails',
        (v_sqlcode = -1031),
        'Trapped SQLCODE: ' || v_sqlcode || ' (Expected: -1031 insufficient privileges)'
    );

    -- TC_BYPASS_05: Attempt to spoof branch code directly via DBMS_SESSION
    BEGIN
        v_sqlcode := 0;
        DBMS_SESSION.SET_CONTEXT('CTX_SEC_MASK', 'BRANCH_CODE', 'ALL');
    EXCEPTION
        WHEN OTHERS THEN
            v_sqlcode := SQLCODE;
    END;

    ASSERT_TRUE(
        'TC_BYPASS_05',
        'Direct DBMS_SESSION.SET_CONTEXT(BRANCH_CODE) fails',
        (v_sqlcode = -1031),
        'Trapped SQLCODE: ' || v_sqlcode || ' (Expected: -1031 insufficient privileges)'
    );

    -- ------------------------------------------------------------------------
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    DBMS_OUTPUT.PUT_LINE('TEST CATEGORY 3: SQL INJECTION IN CONTEXT INITIALIZATION');
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    -- ------------------------------------------------------------------------

    -- TC_BYPASS_06: SQL injection payload in username (' OR '1'='1)
    BEGIN
        SEC_OWNER.PKG_SESSION_CTX.INITIALIZE_SESSION(''' OR ''1''=''1', '192.168.1.102');
        v_status     := SYS_CONTEXT('CTX_SEC_MASK', 'STATUS');
        v_risk_score := TO_NUMBER(SYS_CONTEXT('CTX_SEC_MASK', 'RISK_SCORE'));
        v_risk_tier  := SYS_CONTEXT('CTX_SEC_MASK', 'RISK_TIER');
    EXCEPTION
        WHEN OTHERS THEN
            v_status := 'EXCEPTION_TRAPPED';
    END;

    ASSERT_TRUE(
        'TC_BYPASS_06',
        'SQL injection username fails closed with max risk',
        (v_status = 'USER_NOT_FOUND' AND v_risk_score = 100 AND v_risk_tier = 'HIGH'),
        'Status: ' || v_status || ' | Score: ' || v_risk_score || ' | Tier: ' || v_risk_tier
    );

    -- TC_BYPASS_07: Tautological injection returns zero customer rows
    SELECT COUNT(*) INTO v_count FROM VW_CUSTOMERS;
    ASSERT_TRUE(
        'TC_BYPASS_07',
        'Query on VW_CUSTOMERS under injection context yields 0 rows',
        (v_count = 0),
        'Rows returned: ' || v_count || ' (Expected: 0)'
    );

    -- TC_BYPASS_08: Stacked query injection payload
    BEGIN
        SEC_OWNER.PKG_SESSION_CTX.INITIALIZE_SESSION('agent_sarah''; DROP TABLE CUSTOMERS; --', '192.168.1.102');
        v_status := SYS_CONTEXT('CTX_SEC_MASK', 'STATUS');
    EXCEPTION
        WHEN OTHERS THEN
            v_status := 'EXCEPTION_TRAPPED';
    END;

    ASSERT_TRUE(
        'TC_BYPASS_08',
        'Stacked query injection sanitized without execution',
        (v_status IN ('USER_NOT_FOUND', 'EXCEPTION_TRAPPED')),
        'Status: ' || v_status || ' (No DDL executed)'
    );

    -- ------------------------------------------------------------------------
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    DBMS_OUTPUT.PUT_LINE('TEST CATEGORY 4: UNREGISTERED & LOCKED ACCOUNT REJECTION');
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    -- ------------------------------------------------------------------------

    -- TC_BYPASS_09: Unknown non-existent user identity
    SEC_OWNER.PKG_SESSION_CTX.INITIALIZE_SESSION('ghost_intruder_99', '192.168.1.102');
    v_status := SYS_CONTEXT('CTX_SEC_MASK', 'STATUS');
    SELECT COUNT(*) INTO v_count FROM VW_CUSTOMERS;

    ASSERT_TRUE(
        'TC_BYPASS_09A',
        'Unregistered user flagged as USER_NOT_FOUND',
        (v_status = 'USER_NOT_FOUND'),
        'Context status: ' || v_status
    );
    ASSERT_TRUE(
        'TC_BYPASS_09B',
        'Unregistered user receives exactly 0 rows from view',
        (v_count = 0),
        'Rows returned: ' || v_count || ' (Expected: 0)'
    );

    -- TC_BYPASS_10: Locked account identity (Marcus Aurelius)
    SEC_OWNER.PKG_SESSION_CTX.INITIALIZE_SESSION('locked_user', '192.168.1.102');
    v_status := SYS_CONTEXT('CTX_SEC_MASK', 'STATUS');
    SELECT COUNT(*) INTO v_count FROM VW_CUSTOMERS;

    ASSERT_TRUE(
        'TC_BYPASS_10A',
        'Locked account flagged as ACCOUNT_LOCKED',
        (v_status = 'ACCOUNT_LOCKED'),
        'Context status: ' || v_status
    );
    ASSERT_TRUE(
        'TC_BYPASS_10B',
        'Locked account query on VW_CUSTOMERS returns 0 rows',
        (v_count = 0),
        'Rows returned: ' || v_count || ' (Expected: 0)'
    );

    -- ------------------------------------------------------------------------
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    DBMS_OUTPUT.PUT_LINE('TEST CATEGORY 5: WHERE-CLAUSE PREDICATE INJECTION RESISTANCE');
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    -- ------------------------------------------------------------------------

    -- TC_BYPASS_11: Frontline agent attempts WHERE 1=1 OR branch_code = 'BR_LDN_02'
    SEC_OWNER.PKG_SESSION_CTX.INITIALIZE_SESSION('agent_sarah', '192.168.1.102');
    SEC_OWNER.PKG_SESSION_CTX.SET_SESSION_RISK(10, 'LOW');

    -- Attacker attempts client query with disjunction bypass
    SELECT COUNT(*) INTO v_foreign_cnt
    FROM VW_CUSTOMERS 
    WHERE (1=1 OR branch_code = 'BR_LDN_02')
      AND branch_code != 'BR_NYC_01';

    ASSERT_TRUE(
        'TC_BYPASS_11',
        'VPD kernel wraps disjunction: Zero foreign branch rows leaked',
        (v_foreign_cnt = 0),
        'Foreign branch rows returned: ' || v_foreign_cnt || ' (Expected: 0)'
    );

    -- ------------------------------------------------------------------------
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    DBMS_OUTPUT.PUT_LINE('TEST CATEGORY 6: EDGE CASE & NULL DATA INTEGRITY');
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    -- ------------------------------------------------------------------------

    -- TC_BYPASS_12: Null input to masking engine does not throw exception
    BEGIN
        v_null_phone := SEC_OWNER.PKG_MASK_ENGINE.MASK_PHONE(NULL);
        v_null_email := SEC_OWNER.PKG_MASK_ENGINE.MASK_EMAIL(NULL);
        v_sqlcode := 0;
    EXCEPTION
        WHEN OTHERS THEN
            v_sqlcode := SQLCODE;
    END;

    ASSERT_TRUE(
        'TC_BYPASS_12',
        'Null inputs handled cleanly without VALUE_ERROR',
        (v_sqlcode = 0 AND v_null_phone IS NULL AND v_null_email IS NULL),
        'SQLCODE: ' || v_sqlcode || ' (Handled gracefully)'
    );

    -- Clean up session state
    SEC_OWNER.PKG_SESSION_CTX.CLEAR_SESSION;

    -- ------------------------------------------------------------------------
    -- Test Suite Summary
    -- ------------------------------------------------------------------------
    DBMS_OUTPUT.PUT_LINE('========================================================================');
    DBMS_OUTPUT.PUT_LINE('[PHASE 10: SUITE 1 SUMMARY]');
    DBMS_OUTPUT.PUT_LINE('  Total Tests Executed : ' || v_total_tests);
    DBMS_OUTPUT.PUT_LINE('  Tests Passed         : ' || v_passed_tests);
    DBMS_OUTPUT.PUT_LINE('  Tests Failed         : ' || v_failed_tests);

    IF v_failed_tests = 0 THEN
        DBMS_OUTPUT.PUT_LINE('  VERDICT              : 100% PASS - SYSTEM IS FULLY BYPASS-RESISTANT!');
    ELSE
        DBMS_OUTPUT.PUT_LINE('  VERDICT              : VULNERABILITY DETECTED - REVIEW FAILED TESTS.');
    END IF;
    DBMS_OUTPUT.PUT_LINE('========================================================================');

END;
/
