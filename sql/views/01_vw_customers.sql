-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 8: Dynamic Masking Views & Integration
-- Script:  sql/views/01_vw_customers.sql
-- Target:  Oracle Database (ORCLPDB) - Schema: SEC_OWNER
-- Purpose: Create secure abstraction view VW_CUSTOMERS integrating 
--          PKG_MASK_ENGINE for in-flight column transformations.
-- ============================================================================

SET ECHO ON;
SET DEFINE OFF;
SET SERVEROUTPUT ON SIZE UNLIMITED;
WHENEVER SQLERROR CONTINUE;

PROMPT ------------------------------------------------------------------------
PROMPT [PHASE 8: PART 1] Creating Secure Dynamic Masking View VW_CUSTOMERS
PROMPT ------------------------------------------------------------------------

CONNECT SEC_OWNER/SecOwner#Pass2026@localhost:1521/orclpdb

CREATE OR REPLACE VIEW SEC_OWNER.VW_CUSTOMERS AS
SELECT 
    c.customer_id,
    c.first_name,
    c.last_name,
    SEC_OWNER.PKG_MASK_ENGINE.MASK_EMAIL(c.email)               AS email,
    SEC_OWNER.PKG_MASK_ENGINE.MASK_PHONE(c.phone_number)        AS phone_number,
    SEC_OWNER.PKG_MASK_ENGINE.MASK_NATIONAL_ID(c.national_id)   AS national_id,
    SEC_OWNER.PKG_MASK_ENGINE.MASK_CREDIT_CARD(c.credit_card_num) AS credit_card_num,
    SEC_OWNER.PKG_MASK_ENGINE.MASK_BALANCE(c.account_balance)   AS account_balance,
    c.risk_classification,
    c.branch_code,
    c.created_date
FROM SEC_OWNER.CUSTOMERS c;

PROMPT ------------------------------------------------------------------------
PROMPT [PHASE 8: PART 2] Granting SELECT on VW_CUSTOMERS to Application Roles
PROMPT ------------------------------------------------------------------------

GRANT SELECT ON SEC_OWNER.VW_CUSTOMERS TO APP_USER_ROLE;
GRANT SELECT ON SEC_OWNER.VW_CUSTOMERS TO APP_ADMIN_ROLE;
GRANT SELECT ON SEC_OWNER.VW_CUSTOMERS TO AUDIT_READER_ROLE;
GRANT SELECT ON SEC_OWNER.VW_CUSTOMERS TO APP_SERVICE_USER;

COMMIT;

PROMPT ------------------------------------------------------------------------
PROMPT [VERIFICATION] Verifying VW_CUSTOMERS Compilation
PROMPT ------------------------------------------------------------------------

COLUMN object_name FORMAT A20
COLUMN object_type FORMAT A15
COLUMN status FORMAT A10

SELECT object_name, object_type, status 
FROM user_objects 
WHERE object_name = 'VW_CUSTOMERS';

PROMPT ------------------------------------------------------------------------
PROMPT [SUCCESS] Dynamic Masking View VW_CUSTOMERS Successfully Created!
PROMPT ------------------------------------------------------------------------
