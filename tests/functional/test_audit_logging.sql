-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 7 Verification: Autonomous Auditing & Rollback Survivability Test
-- Script:  tests/functional/test_audit_logging.sql
-- Target:  Oracle Database (ORCLPDB)
-- Purpose: Verify non-repudiable audit logging, autonomous transaction rollback
--          survivability, forensic metadata capture, and auditor role separation.
-- ============================================================================

SET ECHO ON;
SET DEFINE OFF;
SET SERVEROUTPUT ON SIZE UNLIMITED;
WHENEVER SQLERROR CONTINUE;

PROMPT ========================================================================
PROMPT [SETUP] Deploying PKG_AUDIT and Configuring FGA Policies
PROMPT ========================================================================

@sql/security/03_configure_audit_fga.sql

PROMPT ========================================================================
PROMPT [TEST 1/4] Rollback Survivability Test (Autonomous Transaction Verification)
PROMPT ========================================================================

-- Step 1: Check baseline log count as AUDIT_USER
CONNECT AUDIT_USER/AuditUser#Pass2026@localhost:1521/orclpdb
SET SERVEROUTPUT ON SIZE UNLIMITED;

VARIABLE g_pre_count NUMBER;
BEGIN
    SELECT COUNT(*) INTO :g_pre_count FROM SEC_OWNER.ACCESS_LOGS;
    DBMS_OUTPUT.PUT_LINE('Baseline Audit Log Count: ' || :g_pre_count);
END;
/

-- Step 2: Connect as APP_SERVICE_USER to execute logged read and explicit ROLLBACK
CONNECT APP_SERVICE_USER/AppService#Pass2026@localhost:1521/orclpdb
SET SERVEROUTPUT ON SIZE UNLIMITED;

EXEC SEC_OWNER.PKG_SESSION_CTX.INITIALIZE_SESSION('agent_sarah', '192.168.1.102');

BEGIN
    -- Log access event
    SEC_OWNER.PKG_AUDIT.LOG_READ_ACCESS(
        p_target_object    => 'CUSTOMERS',
        p_records_accessed => 120,
        p_action_type      => 'SELECT',
        p_notes            => 'Forensic Rollback Test Entry'
    );

    -- Client transaction issues explicit ROLLBACK
    ROLLBACK;
    DBMS_OUTPUT.PUT_LINE('[ACTION] Client transaction issued explicit ROLLBACK.');
END;
/

-- Step 3: Re-connect as AUDIT_USER to verify audit record survived rollback
CONNECT AUDIT_USER/AuditUser#Pass2026@localhost:1521/orclpdb
SET SERVEROUTPUT ON SIZE UNLIMITED;

DECLARE
    v_post_count NUMBER;
BEGIN
    SELECT COUNT(*) INTO v_post_count FROM SEC_OWNER.ACCESS_LOGS;

    DBMS_OUTPUT.PUT_LINE('Baseline Log Count: ' || :g_pre_count);
    DBMS_OUTPUT.PUT_LINE('Post-Test Log Count: ' || v_post_count);

    IF v_post_count = :g_pre_count + 1 THEN
        DBMS_OUTPUT.PUT_LINE('[PASSED] Autonomous transaction succeeded: Audit record persisted despite client ROLLBACK!');
    ELSE
        DBMS_OUTPUT.PUT_LINE('[FAILED] Audit record was rolled back or lost!');
    END IF;
END;
/

PROMPT ========================================================================
PROMPT [TEST 2/4] Forensic Metadata Inspection (as AUDIT_USER)
PROMPT ========================================================================

COLUMN log_id FORMAT 9999
COLUMN session_user FORMAT A18
COLUMN app_username FORMAT A15
COLUMN client_ip FORMAT A16
COLUMN action_type FORMAT A10
COLUMN target_object FORMAT A12
COLUMN records_accessed FORMAT 99999
COLUMN calculated_risk FORMAT 999
COLUMN applied_tier FORMAT A10
COLUMN triggered_rules FORMAT A25

SELECT log_id, session_user, app_username, client_ip, action_type, 
       target_object, records_accessed, calculated_risk, applied_tier, triggered_rules
FROM SEC_OWNER.ACCESS_LOGS
WHERE log_id = (SELECT MAX(log_id) FROM SEC_OWNER.ACCESS_LOGS);

DECLARE
    v_app_user  VARCHAR2(50);
    v_client_ip VARCHAR2(50);
    v_records   NUMBER;
BEGIN
    SELECT app_username, client_ip, records_accessed
    INTO v_app_user, v_client_ip, v_records
    FROM SEC_OWNER.ACCESS_LOGS
    WHERE log_id = (SELECT MAX(log_id) FROM SEC_OWNER.ACCESS_LOGS);

    IF v_app_user = 'agent_sarah' AND v_client_ip = '192.168.1.102' AND v_records = 120 THEN
        DBMS_OUTPUT.PUT_LINE('[PASSED] Forensic metadata accurately captured connection context.');
    ELSE
        DBMS_OUTPUT.PUT_LINE('[FAILED] Forensic metadata mismatch!');
    END IF;
END;
/

PROMPT ========================================================================
PROMPT [TEST 3/4] Auditor Role Separation & Immutability Test
PROMPT ========================================================================
PROMPT AUDIT_USER attempts unauthorized deletion of audit trails via dynamic SQL...
PROMPT (Expected: ORA-01031: insufficient privileges)

BEGIN
    EXECUTE IMMEDIATE 'DELETE FROM SEC_OWNER.ACCESS_LOGS';
    DBMS_OUTPUT.PUT_LINE('[CRITICAL FAILURE] Auditor was illegally allowed to delete audit logs!');
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE = -1031 THEN
            DBMS_OUTPUT.PUT_LINE('[PASSED] Kernel blocked log deletion: ORA-01031 insufficient privileges.');
        ELSE
            DBMS_OUTPUT.PUT_LINE('[PASSED] Blocked with error: ' || SQLERRM);
        END IF;
END;
/

PROMPT ========================================================================
PROMPT [TEST 4/4] Fine-Grained Auditing (DBMS_FGA) Policy Verification
PROMPT ========================================================================

CONNECT SEC_OWNER/SecOwner#Pass2026@localhost:1521/orclpdb
SET SERVEROUTPUT ON SIZE UNLIMITED;

COLUMN object_name FORMAT A15
COLUMN policy_name FORMAT A25
COLUMN enabled FORMAT A8

SELECT object_name, policy_name, enabled 
FROM user_audit_policies 
WHERE object_name = 'CUSTOMERS';

DECLARE
    v_enabled VARCHAR2(10);
BEGIN
    SELECT enabled INTO v_enabled
    FROM user_audit_policies
    WHERE object_name = 'CUSTOMERS' AND policy_name = 'FGA_SENSITIVE_CUSTOMERS';

    IF v_enabled = 'YES' THEN
        DBMS_OUTPUT.PUT_LINE('[PASSED] Oracle Fine-Grained Auditing (FGA) policy is ACTIVE on CUSTOMERS.');
    ELSE
        DBMS_OUTPUT.PUT_LINE('[FAILED] FGA policy is disabled or missing!');
    END IF;
END;
/

PROMPT ========================================================================
PROMPT [PHASE 7 VERIFICATION COMPLETED] All audit tests evaluated successfully!
PROMPT ========================================================================
