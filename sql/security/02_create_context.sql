-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 4: Trusted Context & Session Management
-- Script:  sql/security/02_create_context.sql
-- Target:  Oracle Database (ORCLPDB) - Schema: SEC_OWNER
-- Purpose: Create the secure application context CTX_SEC_MASK bound strictly
--          to SEC_OWNER.PKG_SESSION_CTX, and grant execution privileges.
-- ============================================================================

SET ECHO ON;
SET DEFINE OFF;
SET SERVEROUTPUT ON SIZE UNLIMITED;
WHENEVER SQLERROR CONTINUE;

PROMPT ------------------------------------------------------------------------
PROMPT [PHASE 4: PART 1] Compiling PKG_SESSION_CTX in SEC_OWNER
PROMPT ------------------------------------------------------------------------

CONNECT SEC_OWNER/SecOwner#Pass2026@localhost:1521/orclpdb

-- Compile Package Specification
@sql/procedures/pkg_session_ctx.pks

-- Compile Package Body
@sql/procedures/pkg_session_ctx.pkb

-- Verify Package Compilation Errors (if any)
SHOW ERRORS PACKAGE SEC_OWNER.PKG_SESSION_CTX;
SHOW ERRORS PACKAGE BODY SEC_OWNER.PKG_SESSION_CTX;

PROMPT ------------------------------------------------------------------------
PROMPT [PHASE 4: PART 2] Creating Secure Application Context CTX_SEC_MASK
PROMPT ------------------------------------------------------------------------

-- Application context bound EXCLUSIVELY to trusted package PKG_SESSION_CTX.
-- Any direct call to DBMS_SESSION.SET_CONTEXT outside this package fails with ORA-01031.
CREATE OR REPLACE CONTEXT ctx_sec_mask USING sec_owner.pkg_session_ctx;

PROMPT ------------------------------------------------------------------------
PROMPT [PHASE 4: PART 3] Granting Execution Privileges to Roles and Users
PROMPT ------------------------------------------------------------------------

-- Allow application clients and roles to invoke session initialization
GRANT EXECUTE ON SEC_OWNER.PKG_SESSION_CTX TO APP_USER_ROLE;
GRANT EXECUTE ON SEC_OWNER.PKG_SESSION_CTX TO APP_ADMIN_ROLE;
GRANT EXECUTE ON SEC_OWNER.PKG_SESSION_CTX TO AUDIT_READER_ROLE;
GRANT EXECUTE ON SEC_OWNER.PKG_SESSION_CTX TO APP_SERVICE_USER;

COMMIT;

PROMPT ------------------------------------------------------------------------
PROMPT [VERIFICATION] Verifying Context Registration in Data Dictionary...
PROMPT ------------------------------------------------------------------------

COLUMN namespace FORMAT A20
COLUMN schema FORMAT A15
COLUMN package FORMAT A20

SELECT namespace, schema, package 
FROM all_context 
WHERE namespace = 'CTX_SEC_MASK';

COLUMN object_name FORMAT A20
COLUMN object_type FORMAT A15
COLUMN status FORMAT A10

SELECT object_name, object_type, status 
FROM user_objects 
WHERE object_name = 'PKG_SESSION_CTX';

PROMPT ------------------------------------------------------------------------
PROMPT [SUCCESS] Application Context and Trusted Package Ready!
PROMPT ------------------------------------------------------------------------
