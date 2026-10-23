-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 4 Verification: Trusted Context Security & Tamper-Resistance Test
-- Script:  tests/functional/test_phase4_context.sql
-- Target:  Oracle Database (ORCLPDB)
-- Purpose: Verify application context initialization, fail-closed enforcement,
--          getter functions, and tamper-resistance against direct SQL attacks.
-- ============================================================================

SET ECHO ON;
SET DEFINE OFF;
SET SERVEROUTPUT ON SIZE UNLIMITED;
WHENEVER SQLERROR CONTINUE;

PROMPT ========================================================================
PROMPT [TEST 1/5] Testing Context Initialization as APP_SERVICE_USER
PROMPT ========================================================================

CONNECT APP_SERVICE_USER/AppService#Pass2026@localhost:1521/orclpdb
SET SERVEROUTPUT ON SIZE UNLIMITED;

-- Initialize session for legitimate customer care agent
EXEC SEC_OWNER.PKG_SESSION_CTX.INITIALIZE_SESSION('agent_sarah', '192.168.1.105');

-- Inspect Context Attributes
COLUMN attribute_name FORMAT A25
COLUMN attribute_val  FORMAT A35

SELECT 'APP_USER' AS attribute_name, SYS_CONTEXT('CTX_SEC_MASK', 'APP_USER') AS attribute_val FROM dual
UNION ALL
SELECT 'USER_ID', SYS_CONTEXT('CTX_SEC_MASK', 'USER_ID') FROM dual
UNION ALL
SELECT 'ROLE_NAME', SYS_CONTEXT('CTX_SEC_MASK', 'ROLE_NAME') FROM dual
UNION ALL
SELECT 'CLIENT_IP', SYS_CONTEXT('CTX_SEC_MASK', 'CLIENT_IP') FROM dual
UNION ALL
SELECT 'MAX_PERMITTED_RISK', SYS_CONTEXT('CTX_SEC_MASK', 'MAX_PERMITTED_RISK') FROM dual
UNION ALL
SELECT 'RISK_SCORE', SYS_CONTEXT('CTX_SEC_MASK', 'RISK_SCORE') FROM dual
UNION ALL
SELECT 'RISK_TIER', SYS_CONTEXT('CTX_SEC_MASK', 'RISK_TIER') FROM dual
UNION ALL
SELECT 'IS_INITIALIZED', SYS_CONTEXT('CTX_SEC_MASK', 'IS_INITIALIZED') FROM dual;

-- Test Package Getter Functions
DECLARE
    v_user  VARCHAR2(50) := SEC_OWNER.PKG_SESSION_CTX.GET_APP_USER;
    v_role  VARCHAR2(50) := SEC_OWNER.PKG_SESSION_CTX.GET_ROLE_NAME;
    v_score NUMBER       := SEC_OWNER.PKG_SESSION_CTX.GET_CURRENT_RISK_SCORE;
    v_tier  VARCHAR2(10) := SEC_OWNER.PKG_SESSION_CTX.GET_CURRENT_RISK_TIER;
BEGIN
    IF v_user = 'agent_sarah' AND v_role = 'CUSTOMER_CARE' AND v_score <= 30 THEN
        DBMS_OUTPUT.PUT_LINE('[SUCCESS] Getters returned expected attributes for agent_sarah.');
    ELSE
        DBMS_OUTPUT.PUT_LINE('[ERROR] Getters returned unexpected values!');
    END IF;
END;
/

PROMPT ========================================================================
PROMPT [TEST 2/5] Adversarial Attack: Direct Context Tampering Attempt
PROMPT ========================================================================
PROMPT Attacker attempts to forge context directly via DBMS_SESSION.SET_CONTEXT...
PROMPT (Expected Result: ORA-01031: insufficient privileges)

BEGIN
    DBMS_SESSION.SET_CONTEXT('CTX_SEC_MASK', 'RISK_SCORE', '0');
    DBMS_OUTPUT.PUT_LINE('[CRITICAL FAILURE] Unauthorized context write was allowed!');
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE = -1031 THEN
            DBMS_OUTPUT.PUT_LINE('[PASSED] Kernel blocked direct tampering with ORA-01031: insufficient privileges.');
        ELSE
            DBMS_OUTPUT.PUT_LINE('[PASSED] Blocked with error: ' || SQLERRM);
        END IF;
END;
/

-- Verify that context value was NOT altered by tampering attempt
DECLARE
    v_user VARCHAR2(50) := SYS_CONTEXT('CTX_SEC_MASK', 'APP_USER');
BEGIN
    IF v_user = 'agent_sarah' THEN
        DBMS_OUTPUT.PUT_LINE('[PASSED] Context integrity intact. Value remains: ' || v_user);
    ELSE
        DBMS_OUTPUT.PUT_LINE('[ERROR] Context value was corrupted!');
    END IF;
END;
/

PROMPT ========================================================================
PROMPT [TEST 3/5] Fail-Closed Test: Unregistered / Rogue User
PROMPT ========================================================================
PROMPT Simulating authentication attempt for non-existent user...

EXEC SEC_OWNER.PKG_SESSION_CTX.INITIALIZE_SESSION('hacker_bob', '203.0.113.50');

SELECT SYS_CONTEXT('CTX_SEC_MASK', 'APP_USER') AS user_val,
       SYS_CONTEXT('CTX_SEC_MASK', 'RISK_SCORE') AS score_val,
       SYS_CONTEXT('CTX_SEC_MASK', 'RISK_TIER') AS tier_val,
       SYS_CONTEXT('CTX_SEC_MASK', 'STATUS') AS status_val
FROM dual;

DECLARE
    v_score NUMBER := TO_NUMBER(SYS_CONTEXT('CTX_SEC_MASK', 'RISK_SCORE'));
    v_tier  VARCHAR2(10) := SYS_CONTEXT('CTX_SEC_MASK', 'RISK_TIER');
BEGIN
    IF v_score = 100 AND v_tier = 'HIGH' THEN
        DBMS_OUTPUT.PUT_LINE('[PASSED] Fail-closed enforced: Unknown user assigned Score=100 and Tier=HIGH.');
    ELSE
        DBMS_OUTPUT.PUT_LINE('[ERROR] Fail-closed was NOT enforced for unknown user!');
    END IF;
END;
/

PROMPT ========================================================================
PROMPT [TEST 4/5] Fail-Closed Test: Suspended / Locked User Account
PROMPT ========================================================================
PROMPT Simulating authentication for locked_user...

EXEC SEC_OWNER.PKG_SESSION_CTX.INITIALIZE_SESSION('locked_user', '192.168.1.55');

SELECT SYS_CONTEXT('CTX_SEC_MASK', 'APP_USER') AS user_val,
       SYS_CONTEXT('CTX_SEC_MASK', 'RISK_SCORE') AS score_val,
       SYS_CONTEXT('CTX_SEC_MASK', 'RISK_TIER') AS tier_val,
       SYS_CONTEXT('CTX_SEC_MASK', 'STATUS') AS status_val
FROM dual;

DECLARE
    v_score NUMBER := TO_NUMBER(SYS_CONTEXT('CTX_SEC_MASK', 'RISK_SCORE'));
    v_status VARCHAR2(50) := SYS_CONTEXT('CTX_SEC_MASK', 'STATUS');
BEGIN
    IF v_score = 100 AND v_status = 'ACCOUNT_LOCKED' THEN
        DBMS_OUTPUT.PUT_LINE('[PASSED] Fail-closed enforced: Locked user assigned Score=100 and ACCOUNT_LOCKED.');
    ELSE
        DBMS_OUTPUT.PUT_LINE('[ERROR] Locked user check failed!');
    END IF;
END;
/

PROMPT ========================================================================
PROMPT [TEST 5/5] Dynamic Risk State Modulation & Session Cleanup
PROMPT ========================================================================
PROMPT 1. Testing legitimate session risk update (e.g. from risk engine)...

EXEC SEC_OWNER.PKG_SESSION_CTX.SET_SESSION_RISK(55, 'MEDIUM');

SELECT SYS_CONTEXT('CTX_SEC_MASK', 'RISK_SCORE') AS updated_score,
       SYS_CONTEXT('CTX_SEC_MASK', 'RISK_TIER')  AS updated_tier
FROM dual;

PROMPT 2. Testing session cleanup...
EXEC SEC_OWNER.PKG_SESSION_CTX.CLEAR_SESSION;

SELECT NVL(SYS_CONTEXT('CTX_SEC_MASK', 'APP_USER'), 'CLEARED') AS user_after_clear,
       NVL(SYS_CONTEXT('CTX_SEC_MASK', 'RISK_SCORE'), 'CLEARED') AS score_after_clear
FROM dual;

PROMPT ========================================================================
PROMPT [PHASE 4 VERIFICATION COMPLETED] All context tests evaluated!
PROMPT ========================================================================
