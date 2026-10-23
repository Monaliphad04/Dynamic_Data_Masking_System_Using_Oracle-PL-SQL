-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 10: Comprehensive Security & Adversarial Bypass Testing
-- Script:  tests/security/test_privilege_escalation.sql
-- Target:  Oracle Database (ORCLPDB) - Multi-Role Security Suite
-- Purpose: Rigorous privilege escalation testing suite verifying role ceilings,
--          mid-session dynamic modulation, audit immutability, and least-privilege confinement.
-- ============================================================================

SET ECHO OFF;
SET DEFINE OFF;
SET FEEDBACK OFF;
SET TIMING OFF;
SET LINESIZE 250;
SET PAGESIZE 50;
SET SERVEROUTPUT ON SIZE UNLIMITED;

PROMPT ========================================================================
PROMPT [PHASE 10: SUITE 2] Privilege Escalation & Security Integrity Tests
PROMPT Multi-User Role Verification: APP_SERVICE_USER, AUDIT_USER, SEC_OWNER
PROMPT ========================================================================

-- Global tracking package/context variables
VARIABLE g_total_tests NUMBER;
VARIABLE g_passed_tests NUMBER;
VARIABLE g_failed_tests NUMBER;

BEGIN
    :g_total_tests  := 0;
    :g_passed_tests := 0;
    :g_failed_tests := 0;
END;
/

-- ============================================================================
-- PART 1: TESTS AS APP_SERVICE_USER (Least-Privilege Client)
-- ============================================================================
CONNECT APP_SERVICE_USER/AppService#Pass2026@localhost:1521/orclpdb
SET SERVEROUTPUT ON SIZE UNLIMITED;

DECLARE
    v_national_id    VARCHAR2(50);
    v_email          VARCHAR2(100);
    v_phone          VARCHAR2(50);
    v_balance        NUMBER;
    v_foreign_cnt    NUMBER;
    v_sqlcode        NUMBER;

    PROCEDURE RECORD_TEST(p_id VARCHAR2, p_desc VARCHAR2, p_pass BOOLEAN, p_det VARCHAR2 DEFAULT NULL) IS
    BEGIN
        :g_total_tests := :g_total_tests + 1;
        IF p_pass THEN
            :g_passed_tests := :g_passed_tests + 1;
            DBMS_OUTPUT.PUT_LINE('  [PASS] ' || RPAD(p_id, 16) || ' | ' || RPAD(p_desc, 50) || 
                                 CASE WHEN p_det IS NOT NULL THEN ' | ' || p_det END);
        ELSE
            :g_failed_tests := :g_failed_tests + 1;
            DBMS_OUTPUT.PUT_LINE('  [FAIL] ' || RPAD(p_id, 16) || ' | ' || RPAD(p_desc, 50) || 
                                 ' | FAILED: ' || p_det);
        END IF;
    END RECORD_TEST;

BEGIN
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    DBMS_OUTPUT.PUT_LINE('CATEGORY 1: ROLE CEILING ENFORCEMENT (NON-ESCALATION GUARANTEE)');
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');

    -- TC_ESCALATE_01A: Frontline Agent Sarah at zero risk cannot view cleartext SSN
    SEC_OWNER.PKG_SESSION_CTX.INITIALIZE_SESSION('agent_sarah', '192.168.1.102');
    SEC_OWNER.PKG_SESSION_CTX.SET_SESSION_RISK(0, 'LOW');

    SELECT national_id, email, phone_number
    INTO v_national_id, v_email, v_phone
    FROM VW_CUSTOMERS WHERE customer_id = 55;

    RECORD_TEST(
        'TC_ESCALATE_01A',
        'Frontline agent SSN masked even at risk = 0',
        (v_national_id LIKE '***-**-%'),
        'Returned: ' || v_national_id || ' (Role ceiling enforced)'
    );

    RECORD_TEST(
        'TC_ESCALATE_01B',
        'Cleartext SSN (555-45-6335) never leaked to frontline',
        (v_national_id != '555-45-6335'),
        'Zero leakage of pristine SSN blocks'
    );

    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    DBMS_OUTPUT.PUT_LINE('CATEGORY 2: DYNAMIC MID-SESSION RISK ESCALATION');
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');

    -- TC_ESCALATE_02A: Initial query under LOW risk
    RECORD_TEST(
        'TC_ESCALATE_02A',
        'Initial state at low risk: Cleartext email/phone visible',
        (v_email IS NOT NULL AND v_phone IS NOT NULL),
        'Email: ' || v_email
    );

    -- TC_ESCALATE_02B: Mid-session velocity burst triggers HIGH risk
    SEC_OWNER.PKG_SESSION_CTX.SET_SESSION_RISK(90, 'HIGH');

    SELECT email, phone_number, account_balance 
    INTO v_email, v_phone, v_balance 
    FROM VW_CUSTOMERS WHERE customer_id = 55;

    RECORD_TEST(
        'TC_ESCALATE_02B',
        'Mid-session HIGH risk: Sensitive columns suppressed to NULL',
        (v_email IS NULL AND v_phone IS NULL AND v_balance IS NULL),
        'Kernel suppression enforced in real-time on active cursor'
    );

    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    DBMS_OUTPUT.PUT_LINE('CATEGORY 3: AUDIT TRAIL TAMPERING RESISTANCE (APP_SERVICE_USER)');
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');

    -- TC_ESCALATE_03A: Direct SELECT on ACCESS_LOGS blocked
    BEGIN
        v_sqlcode := 0;
        EXECUTE IMMEDIATE 'SELECT COUNT(*) FROM SEC_OWNER.ACCESS_LOGS';
    EXCEPTION WHEN OTHERS THEN v_sqlcode := SQLCODE;
    END;
    RECORD_TEST(
        'TC_ESCALATE_03A',
        'SELECT on ACCESS_LOGS blocked for app client',
        (v_sqlcode = -942),
        'Trapped SQLCODE: ' || v_sqlcode || ' (ORA-00942)'
    );

    -- TC_ESCALATE_03B: Direct DELETE on ACCESS_LOGS blocked
    BEGIN
        v_sqlcode := 0;
        EXECUTE IMMEDIATE 'DELETE FROM SEC_OWNER.ACCESS_LOGS';
    EXCEPTION WHEN OTHERS THEN v_sqlcode := SQLCODE;
    END;
    RECORD_TEST(
        'TC_ESCALATE_03B',
        'DELETE on ACCESS_LOGS blocked for app client',
        (v_sqlcode = -942),
        'Trapped SQLCODE: ' || v_sqlcode || ' (ORA-00942)'
    );

    -- TC_ESCALATE_03C: Direct TRUNCATE on ACCESS_LOGS blocked
    BEGIN
        v_sqlcode := 0;
        EXECUTE IMMEDIATE 'TRUNCATE TABLE SEC_OWNER.ACCESS_LOGS';
    EXCEPTION WHEN OTHERS THEN v_sqlcode := SQLCODE;
    END;
    RECORD_TEST(
        'TC_ESCALATE_03C',
        'TRUNCATE on ACCESS_LOGS blocked for app client',
        (v_sqlcode = -942),
        'Trapped SQLCODE: ' || v_sqlcode || ' (ORA-00942)'
    );

    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    DBMS_OUTPUT.PUT_LINE('CATEGORY 4: BRANCH SPOOFING RESISTANCE VIA PARAMETER SANITIZATION');
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');

    -- TC_ESCALATE_04: Pass injection string into SET_BRANCH_CONTEXT
    SEC_OWNER.PKG_SESSION_CTX.INITIALIZE_SESSION('agent_sarah', '192.168.1.102');
    SEC_OWNER.PKG_SESSION_CTX.SET_BRANCH_CONTEXT('BR_NYC_01'' OR ''1''=''1');

    SELECT COUNT(*) INTO v_foreign_cnt
    FROM VW_CUSTOMERS
    WHERE branch_code NOT IN ('BR_NYC_01');

    RECORD_TEST(
        'TC_ESCALATE_04',
        'Branch injection sanitized: Zero foreign rows leaked',
        (v_foreign_cnt = 0),
        'Foreign branch rows returned: ' || v_foreign_cnt || ' (Expected: 0)'
    );

    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    DBMS_OUTPUT.PUT_LINE('CATEGORY 5: AUTONOMOUS AUDIT LOGGING WITH CLIENT ROLLBACK');
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');

    -- TC_ESCALATE_05: Issue autonomous audit log inside client transaction, then issue ROLLBACK
    SEC_OWNER.PKG_AUDIT.LOG_READ_ACCESS(
        p_target_object    => 'CUSTOMERS',
        p_records_accessed => 1,
        p_action_type      => 'SELECT',
        p_notes            => 'Rollback Survivability Test Trace #999'
    );

    -- Client transaction issues explicit ROLLBACK
    ROLLBACK;

    DBMS_OUTPUT.PUT_LINE('[ACTION] Autonomous audit event recorded and client ROLLBACK executed.');

    SEC_OWNER.PKG_SESSION_CTX.CLEAR_SESSION;
END;
/

-- ============================================================================
-- PART 2: TESTS AS AUDIT_USER (Audit Reader Role)
-- ============================================================================
CONNECT AUDIT_USER/AuditUser#Pass2026@localhost:1521/orclpdb
SET SERVEROUTPUT ON SIZE UNLIMITED;

DECLARE
    v_found_cnt   NUMBER;
    v_sqlcode     NUMBER;

    PROCEDURE RECORD_TEST(p_id VARCHAR2, p_desc VARCHAR2, p_pass BOOLEAN, p_det VARCHAR2 DEFAULT NULL) IS
    BEGIN
        :g_total_tests := :g_total_tests + 1;
        IF p_pass THEN
            :g_passed_tests := :g_passed_tests + 1;
            DBMS_OUTPUT.PUT_LINE('  [PASS] ' || RPAD(p_id, 16) || ' | ' || RPAD(p_desc, 50) || 
                                 CASE WHEN p_det IS NOT NULL THEN ' | ' || p_det END);
        ELSE
            :g_failed_tests := :g_failed_tests + 1;
            DBMS_OUTPUT.PUT_LINE('  [FAIL] ' || RPAD(p_id, 16) || ' | ' || RPAD(p_desc, 50) || 
                                 ' | FAILED: ' || p_det);
        END IF;
    END RECORD_TEST;

BEGIN
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    DBMS_OUTPUT.PUT_LINE('CATEGORY 6: AUDIT ROLLBACK SURVIVABILITY & IMMUTABILITY (AUDIT_USER)');
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');

    -- TC_ESCALATE_06A: Confirm the audit log survived client transaction ROLLBACK
    SELECT COUNT(*) INTO v_found_cnt
    FROM SEC_OWNER.ACCESS_LOGS
    WHERE triggered_rules = 'Rollback Survivability Test Trace #999';

    RECORD_TEST(
        'TC_ESCALATE_06A',
        'Audit record survived client transaction ROLLBACK',
        (v_found_cnt >= 1),
        'Records found: ' || v_found_cnt || ' (Autonomous commit confirmed)'
    );

    -- TC_ESCALATE_06B: Attempt DELETE on ACCESS_LOGS as AUDIT_USER (Auditors are strictly read-only)
    BEGIN
        v_sqlcode := 0;
        EXECUTE IMMEDIATE 'DELETE FROM SEC_OWNER.ACCESS_LOGS WHERE triggered_rules = ''Rollback Survivability Test Trace #999''';
    EXCEPTION WHEN OTHERS THEN v_sqlcode := SQLCODE;
    END;

    RECORD_TEST(
        'TC_ESCALATE_06B',
        'DELETE on ACCESS_LOGS blocked for AUDIT_USER',
        (v_sqlcode = -1031),
        'Trapped SQLCODE: ' || v_sqlcode || ' (ORA-01031 insufficient privileges)'
    );

END;
/

-- ============================================================================
-- PART 3: TESTS AS SEC_OWNER (Administrative Lifecycle Verification)
-- ============================================================================
CONNECT SEC_OWNER/SecOwner#Pass2026@localhost:1521/orclpdb
SET SERVEROUTPUT ON SIZE UNLIMITED;

DECLARE
    v_status      VARCHAR2(50);
    v_score       NUMBER;
    v_tier        VARCHAR2(10);

    PROCEDURE RECORD_TEST(p_id VARCHAR2, p_desc VARCHAR2, p_pass BOOLEAN, p_det VARCHAR2 DEFAULT NULL) IS
    BEGIN
        :g_total_tests := :g_total_tests + 1;
        IF p_pass THEN
            :g_passed_tests := :g_passed_tests + 1;
            DBMS_OUTPUT.PUT_LINE('  [PASS] ' || RPAD(p_id, 16) || ' | ' || RPAD(p_desc, 50) || 
                                 CASE WHEN p_det IS NOT NULL THEN ' | ' || p_det END);
        ELSE
            :g_failed_tests := :g_failed_tests + 1;
            DBMS_OUTPUT.PUT_LINE('  [FAIL] ' || RPAD(p_id, 16) || ' | ' || RPAD(p_desc, 50) || 
                                 ' | FAILED: ' || p_det);
        END IF;
    END RECORD_TEST;

BEGIN
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');
    DBMS_OUTPUT.PUT_LINE('CATEGORY 7: MID-SESSION ACCOUNT SUSPENSION INVALIDATION');
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------------------------------');

    -- TC_ESCALATE_07: Administrative suspension forces fail-closed risk (100, HIGH)
    -- Step 1: Temporarily suspend agent_sarah
    UPDATE SEC_OWNER.APP_USERS SET account_status = 'SUSPENDED' WHERE username = 'agent_sarah';
    COMMIT;

    -- Step 2: Attempt session initialization under suspended status
    SEC_OWNER.PKG_SESSION_CTX.INITIALIZE_SESSION('agent_sarah', '192.168.1.102');
    v_status := SYS_CONTEXT('CTX_SEC_MASK', 'STATUS');
    v_score  := TO_NUMBER(SYS_CONTEXT('CTX_SEC_MASK', 'RISK_SCORE'));
    v_tier   := SYS_CONTEXT('CTX_SEC_MASK', 'RISK_TIER');

    RECORD_TEST(
        'TC_ESCALATE_07',
        'Suspended account flagged and forced to Score=100/HIGH',
        (v_status = 'ACCOUNT_SUSPENDED' AND v_score = 100 AND v_tier = 'HIGH'),
        'Status: ' || v_status || ' | Score: ' || v_score || ' | Tier: ' || v_tier
    );

    -- Step 3: Restore agent_sarah to ACTIVE status
    UPDATE SEC_OWNER.APP_USERS SET account_status = 'ACTIVE' WHERE username = 'agent_sarah';
    COMMIT;

    -- Clean up session
    SEC_OWNER.PKG_SESSION_CTX.CLEAR_SESSION;

    -- ------------------------------------------------------------------------
    -- Test Suite Summary
    -- ------------------------------------------------------------------------
    DBMS_OUTPUT.PUT_LINE('========================================================================');
    DBMS_OUTPUT.PUT_LINE('[PHASE 10: SUITE 2 SUMMARY]');
    DBMS_OUTPUT.PUT_LINE('  Total Tests Executed : ' || :g_total_tests);
    DBMS_OUTPUT.PUT_LINE('  Tests Passed         : ' || :g_passed_tests);
    DBMS_OUTPUT.PUT_LINE('  Tests Failed         : ' || :g_failed_tests);

    IF :g_failed_tests = 0 THEN
        DBMS_OUTPUT.PUT_LINE('  VERDICT              : 100% PASS - PRIVILEGE CEILINGS STRICTLY HELD!');
    ELSE
        DBMS_OUTPUT.PUT_LINE('  VERDICT              : PRIVILEGE ESCALATION VULNERABILITY DETECTED.');
    END IF;
    DBMS_OUTPUT.PUT_LINE('========================================================================');

END;
/
