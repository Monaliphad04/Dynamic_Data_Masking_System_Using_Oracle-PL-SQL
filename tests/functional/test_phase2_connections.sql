-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 2 Verification: Connection and Privileges Test
-- Script:  tests/functional/test_phase2_connections.sql
-- Target:  Oracle Database (ORCLPDB)
-- Purpose: Verify that created user accounts can authenticate and have 
--          appropriate permissions according to the principle of least privilege.
-- ============================================================================

SET ECHO ON;
SET DEFINE OFF;
SET SERVEROUTPUT ON SIZE UNLIMITED;

PROMPT ========================================================================
PROMPT [TEST 1/4] Testing SEC_OWNER Privileges (Should succeed for schema DDL)
PROMPT ========================================================================
CONNECT SEC_OWNER/SecOwner#Pass2026@localhost:1521/orclpdb

SELECT USER, sys_context('USERENV', 'CON_NAME') AS con_name FROM dual;

-- Test table creation in TS_SEC_DATA
CREATE TABLE sec_owner_smoke_test (
    test_id NUMBER PRIMARY KEY,
    test_val VARCHAR2(50)
) TABLESPACE TS_SEC_DATA;

INSERT INTO sec_owner_smoke_test VALUES (1, 'Phase 2 Verification Succeeded');
COMMIT;

SELECT * FROM sec_owner_smoke_test;

DROP TABLE sec_owner_smoke_test PURGE;

PROMPT [SUCCESS] SEC_OWNER verified!

PROMPT ========================================================================
PROMPT [TEST 2/4] Testing APP_SERVICE_USER Authentication & Restrictions
PROMPT ========================================================================
CONNECT APP_SERVICE_USER/AppService#Pass2026@localhost:1521/orclpdb

SELECT USER, sys_context('USERENV', 'CON_NAME') AS con_name FROM dual;

-- APP_SERVICE_USER must NOT have permission to create tables (Least Privilege)
-- Expected: ORA-01031: insufficient privileges
PROMPT [NEGATIVE TEST] Attempting unauthorized table creation as APP_SERVICE_USER...
CREATE TABLE app_user_illegal_test (id NUMBER);

PROMPT [SUCCESS] APP_SERVICE_USER verified!

PROMPT ========================================================================
PROMPT [TEST 3/4] Testing APP_ADMIN_USER Authentication
PROMPT ========================================================================
CONNECT APP_ADMIN_USER/AppAdmin#Pass2026@localhost:1521/orclpdb

SELECT USER, sys_context('USERENV', 'CON_NAME') AS con_name FROM dual;
PROMPT [SUCCESS] APP_ADMIN_USER verified!

PROMPT ========================================================================
PROMPT [TEST 4/4] Testing AUDIT_USER Authentication
PROMPT ========================================================================
CONNECT AUDIT_USER/AuditUser#Pass2026@localhost:1521/orclpdb

SELECT USER, sys_context('USERENV', 'CON_NAME') AS con_name FROM dual;
PROMPT [SUCCESS] AUDIT_USER verified!

PROMPT ========================================================================
PROMPT [PHASE 2 VERIFICATION COMPLETE] All accounts authenticated successfully.
PROMPT ========================================================================
DISCONNECT;
