-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 8: Dynamic Masking Views & Integration
-- Script:  sql/security/04_lockdown_privileges.sql
-- Target:  Oracle Database (ORCLPDB) - Run as SYSDBA or SEC_OWNER
-- Purpose: Harden database security by revoking all direct table access on
--          CUSTOMERS from application users and enforcing access solely via VW_CUSTOMERS.
-- ============================================================================

SET ECHO ON;
SET DEFINE OFF;
SET SERVEROUTPUT ON SIZE UNLIMITED;
WHENEVER SQLERROR CONTINUE;

PROMPT ------------------------------------------------------------------------
PROMPT [PHASE 8: PRIVILEGE HARDENING] Locking Down Direct Base Table Access
PROMPT ------------------------------------------------------------------------

ALTER SESSION SET CONTAINER = ORCLPDB;

-- ----------------------------------------------------------------------------
-- 1. Create Public Synonym for Transparent Client Queries
-- ----------------------------------------------------------------------------
CREATE OR REPLACE PUBLIC SYNONYM VW_CUSTOMERS FOR SEC_OWNER.VW_CUSTOMERS;

-- ----------------------------------------------------------------------------
-- 2. Revoke Direct Access on Sensitive Base Table CUSTOMERS (Graceful Check)
-- ----------------------------------------------------------------------------
BEGIN
    FOR p IN (
        SELECT grantee, privilege 
        FROM dba_tab_privs 
        WHERE owner = 'SEC_OWNER' 
          AND table_name = 'CUSTOMERS' 
          AND grantee IN ('PUBLIC', 'APP_USER_ROLE', 'APP_SERVICE_USER')
    ) LOOP
        EXECUTE IMMEDIATE 'REVOKE ' || p.privilege || ' ON SEC_OWNER.CUSTOMERS FROM ' || p.grantee;
        DBMS_OUTPUT.PUT_LINE('[REVOKED] Revoked ' || p.privilege || ' on CUSTOMERS from ' || p.grantee);
    END LOOP;
END;
/

-- ----------------------------------------------------------------------------
-- 3. Confirm Grants Exclusively on Dynamic Masking View
-- ----------------------------------------------------------------------------
GRANT SELECT ON SEC_OWNER.VW_CUSTOMERS TO APP_USER_ROLE;
GRANT SELECT ON SEC_OWNER.VW_CUSTOMERS TO APP_SERVICE_USER;

COMMIT;

PROMPT ------------------------------------------------------------------------
PROMPT [VERIFICATION] Inspecting Granted Object Privileges on CUSTOMERS & View
PROMPT ------------------------------------------------------------------------

COLUMN grantee FORMAT A20
COLUMN table_name FORMAT A20
COLUMN privilege FORMAT A15

SELECT grantee, table_name, privilege 
FROM dba_tab_privs 
WHERE table_name IN ('CUSTOMERS', 'VW_CUSTOMERS')
  AND grantee IN ('PUBLIC', 'APP_USER_ROLE', 'APP_SERVICE_USER')
ORDER BY table_name, grantee;

PROMPT ------------------------------------------------------------------------
PROMPT [SUCCESS] Base Table Locked Down! Access Restricted Exclusively to View.
PROMPT ------------------------------------------------------------------------
