-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 7: Auditing Architecture & Autonomous Logging
-- Script:  sql/security/03_configure_audit_fga.sql
-- Target:  Oracle Database (ORCLPDB) - Schema: SEC_OWNER
-- Purpose: Compile PKG_AUDIT, grant audit access roles, and register Oracle
--          Fine-Grained Auditing (DBMS_FGA) policy on sensitive customer columns.
-- ============================================================================

SET ECHO ON;
SET DEFINE OFF;
SET SERVEROUTPUT ON SIZE UNLIMITED;
WHENEVER SQLERROR CONTINUE;

PROMPT ------------------------------------------------------------------------
PROMPT [PHASE 7: PART 1] Compiling PKG_AUDIT in SEC_OWNER
PROMPT ------------------------------------------------------------------------

CONNECT SEC_OWNER/SecOwner#Pass2026@localhost:1521/orclpdb

@sql/procedures/pkg_audit.pks
@sql/procedures/pkg_audit.pkb

SHOW ERRORS PACKAGE SEC_OWNER.PKG_AUDIT;
SHOW ERRORS PACKAGE BODY SEC_OWNER.PKG_AUDIT;

PROMPT ------------------------------------------------------------------------
PROMPT [PHASE 7: PART 2] Granting Audit Roles and Permissions
PROMPT ------------------------------------------------------------------------

-- Allow application services and users to generate audit logs
GRANT EXECUTE ON SEC_OWNER.PKG_AUDIT TO APP_USER_ROLE;
GRANT EXECUTE ON SEC_OWNER.PKG_AUDIT TO APP_ADMIN_ROLE;
GRANT EXECUTE ON SEC_OWNER.PKG_AUDIT TO AUDIT_READER_ROLE;
GRANT EXECUTE ON SEC_OWNER.PKG_AUDIT TO APP_SERVICE_USER;

-- Grant read-only access on ACCESS_LOGS to auditor roles
GRANT SELECT ON SEC_OWNER.ACCESS_LOGS TO AUDIT_READER_ROLE;
GRANT SELECT ON SEC_OWNER.ACCESS_LOGS TO APP_ADMIN_ROLE;

COMMIT;

PROMPT ------------------------------------------------------------------------
PROMPT [PHASE 7: PART 3] Configuring Oracle Fine-Grained Auditing (DBMS_FGA)
PROMPT ------------------------------------------------------------------------

DECLARE
    v_policy_count NUMBER;
BEGIN
    -- Check if policy exists and drop if re-running (Query user_audit_policies)
    SELECT COUNT(*) INTO v_policy_count
    FROM user_audit_policies
    WHERE object_name = 'CUSTOMERS' AND policy_name = 'FGA_SENSITIVE_CUSTOMERS';

    IF v_policy_count > 0 THEN
        DBMS_FGA.DROP_POLICY(
            object_schema => 'SEC_OWNER',
            object_name   => 'CUSTOMERS',
            policy_name   => 'FGA_SENSITIVE_CUSTOMERS'
        );
        DBMS_OUTPUT.PUT_LINE('[INFO] Existing FGA policy dropped for re-creation.');
    END IF;

    -- Register FGA Policy on Sensitive Columns
    DBMS_FGA.ADD_POLICY(
        object_schema   => 'SEC_OWNER',
        object_name     => 'CUSTOMERS',
        policy_name     => 'FGA_SENSITIVE_CUSTOMERS',
        audit_column    => 'PHONE_NUMBER,EMAIL,NATIONAL_ID,CREDIT_CARD_NUM,ACCOUNT_BALANCE',
        audit_condition => NULL,
        statement_types => 'SELECT',
        enable          => TRUE
    );

    DBMS_OUTPUT.PUT_LINE('[SUCCESS] Oracle FGA Policy FGA_SENSITIVE_CUSTOMERS successfully registered!');
EXCEPTION
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('[WARN] FGA Policy Registration: ' || SQLERRM);
END;
/

PROMPT ------------------------------------------------------------------------
PROMPT [VERIFICATION] Verifying FGA Policies and Audit Objects
PROMPT ------------------------------------------------------------------------

COLUMN object_name FORMAT A20
COLUMN policy_name FORMAT A25
COLUMN policy_column FORMAT A35
COLUMN enabled FORMAT A10

SELECT object_name, policy_name, policy_column, enabled
FROM user_audit_policies
WHERE object_name = 'CUSTOMERS';

COLUMN object_name FORMAT A20
COLUMN object_type FORMAT A15
COLUMN status FORMAT A10

SELECT object_name, object_type, status 
FROM user_objects 
WHERE object_name = 'PKG_AUDIT';

PROMPT ------------------------------------------------------------------------
PROMPT [PHASE 7 SETUP COMPLETED] Auditing Architecture & FGA Ready!
PROMPT ------------------------------------------------------------------------
