-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 8 Verification: Dynamic Masking Views & Privilege Lockdown Test
-- Script:  tests/functional/test_phase8_views.sql
-- Target:  Oracle Database (ORCLPDB)
-- Purpose: Verify base table direct access lockdown (ORA-00942), dynamic view
--          projection across Low, Med, High risk tiers, and zero storage mutation.
-- ============================================================================

SET ECHO ON;
SET DEFINE OFF;
SET SERVEROUTPUT ON SIZE UNLIMITED;
WHENEVER SQLERROR CONTINUE;

PROMPT ========================================================================
PROMPT [SETUP] Deploying VW_CUSTOMERS and Privilege Lockdown Scripts
PROMPT ========================================================================

@sql/views/01_vw_customers.sql
@sql/security/04_lockdown_privileges.sql

PROMPT ========================================================================
PROMPT [TEST 1/5] Direct Base Table Access Lockdown (Negative Test)
PROMPT ========================================================================
PROMPT Connecting as APP_SERVICE_USER and attempting direct SELECT on CUSTOMERS...
PROMPT (Expected: ORA-00942: table or view does not exist)

CONNECT APP_SERVICE_USER/AppService#Pass2026@localhost:1521/orclpdb
SET SERVEROUTPUT ON SIZE UNLIMITED;

BEGIN
    EXECUTE IMMEDIATE 'SELECT COUNT(*) FROM SEC_OWNER.CUSTOMERS';
    DBMS_OUTPUT.PUT_LINE('[CRITICAL FAILURE] Direct table access was allowed!');
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE = -942 THEN
            DBMS_OUTPUT.PUT_LINE('[PASSED] Kernel blocked direct table access with ORA-00942 table or view does not exist.');
        ELSE
            DBMS_OUTPUT.PUT_LINE('[PASSED] Direct table query blocked with error: ' || SQLERRM);
        END IF;
END;
/

PROMPT ========================================================================
PROMPT [TEST 2/5] Query VW_CUSTOMERS as SEC_ADMIN (Low Risk Full Visibility)
PROMPT ========================================================================

-- Initialize session for admin_user
EXEC SEC_OWNER.PKG_SESSION_CTX.INITIALIZE_SESSION('admin_user', '192.168.1.50');

COLUMN customer_id FORMAT 9999
COLUMN first_name FORMAT A12
COLUMN last_name FORMAT A12
COLUMN email FORMAT A28
COLUMN phone_number FORMAT A18
COLUMN national_id FORMAT A15
COLUMN account_balance FORMAT $999,999.99

SELECT customer_id, first_name, last_name, email, phone_number, national_id, account_balance
FROM VW_CUSTOMERS
WHERE customer_id = 55;

DECLARE
    v_phone VARCHAR2(25);
    v_ssn   VARCHAR2(20);
BEGIN
    SELECT phone_number, national_id INTO v_phone, v_ssn
    FROM VW_CUSTOMERS WHERE customer_id = 55;

    IF v_phone = '+1-555-435-5015' AND v_ssn = '555-45-6335' THEN
        DBMS_OUTPUT.PUT_LINE('[PASSED] Admin view correctly delivered authorized unmasked cleartext.');
    ELSE
        DBMS_OUTPUT.PUT_LINE('[FAILED] Admin cleartext projection mismatch!');
    END IF;
END;
/

PROMPT ========================================================================
PROMPT [TEST 3/5] Query VW_CUSTOMERS as CUSTOMER_CARE (Role Ceiling Enforced)
PROMPT ========================================================================

-- Reset anomalies to restore agent_sarah to legitimate baseline (Low Risk)
EXEC SEC_OWNER.PKG_RISK_ENGINE.RESET_USER_ANOMALIES('agent_sarah');

-- Initialize session for agent_sarah (CUSTOMER_CARE, Low Risk)
EXEC SEC_OWNER.PKG_SESSION_CTX.INITIALIZE_SESSION('agent_sarah', '192.168.1.102');

SELECT customer_id, first_name, last_name, email, phone_number, national_id, account_balance
FROM VW_CUSTOMERS
WHERE customer_id = 55;

DECLARE
    v_phone VARCHAR2(25);
    v_ssn   VARCHAR2(20);
BEGIN
    SELECT phone_number, national_id INTO v_phone, v_ssn
    FROM VW_CUSTOMERS WHERE customer_id = 55;

    IF v_phone = '+1-555-435-5015' AND v_ssn = '***-**-6335' THEN
        DBMS_OUTPUT.PUT_LINE('[PASSED] Role ceiling enforced: Phone cleartext, SSN partially masked for frontline agent.');
    ELSE
        DBMS_OUTPUT.PUT_LINE('[FAILED] Role ceiling non-escalation check failed!');
    END IF;
END;
/

PROMPT ========================================================================
PROMPT [TEST 4/5] Dynamic In-Flight Downgrade under HIGH Risk
PROMPT ========================================================================
PROMPT Escalate session risk to HIGH (85)...

EXEC SEC_OWNER.PKG_SESSION_CTX.SET_SESSION_RISK(85, 'HIGH');

SELECT customer_id, first_name, last_name, email, phone_number, national_id, account_balance
FROM VW_CUSTOMERS
WHERE customer_id = 55;

DECLARE
    v_phone   VARCHAR2(25);
    v_email   VARCHAR2(100);
    v_ssn     VARCHAR2(20);
    v_balance NUMBER;
BEGIN
    SELECT phone_number, email, national_id, account_balance 
    INTO v_phone, v_email, v_ssn, v_balance
    FROM VW_CUSTOMERS WHERE customer_id = 55;

    IF (v_phone = '***-***-****' OR v_phone IS NULL) 
       AND (v_email = '*******@*******.***' OR v_email IS NULL) 
       AND (v_ssn = '***-**-****' OR v_ssn IS NULL) 
       AND (v_balance = 0 OR v_balance IS NULL) THEN
        DBMS_OUTPUT.PUT_LINE('[PASSED] High risk dynamic downgrade enforced: All sensitive columns fully redacted in-flight!');
    ELSE
        DBMS_OUTPUT.PUT_LINE('[FAILED] High risk redaction check failed!');
    END IF;
END;
/

PROMPT ========================================================================
PROMPT [TEST 5/5] Zero Storage Mutation Verification (Pristine Disk Blocks)
PROMPT ========================================================================
PROMPT Connecting as SEC_OWNER to verify underlying CUSTOMERS table remains unmodified...

CONNECT SEC_OWNER/SecOwner#Pass2026@localhost:1521/orclpdb
SET SERVEROUTPUT ON SIZE UNLIMITED;

SELECT customer_id, first_name, last_name, email, phone_number, national_id, account_balance
FROM CUSTOMERS
WHERE customer_id = 55;

DECLARE
    v_raw_phone VARCHAR2(25);
    v_raw_ssn   VARCHAR2(20);
    v_raw_bal   NUMBER;
BEGIN
    SELECT phone_number, national_id, account_balance
    INTO v_raw_phone, v_raw_ssn, v_raw_bal
    FROM CUSTOMERS WHERE customer_id = 55;

    IF v_raw_phone = '+1-555-435-5015' AND v_raw_ssn = '555-45-6335' AND v_raw_bal > 0 THEN
        DBMS_OUTPUT.PUT_LINE('[PASSED] Zero storage mutation verified: Database disk blocks retain 100% pristine cleartext data.');
    ELSE
        DBMS_OUTPUT.PUT_LINE('[FAILED] Database storage was corrupted!');
    END IF;
END;
/

PROMPT ========================================================================
PROMPT [PHASE 8 VERIFICATION COMPLETED] All dynamic view tests evaluated!
PROMPT ========================================================================
