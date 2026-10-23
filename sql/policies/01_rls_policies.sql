-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 9: Oracle VPD (DBMS_RLS) Policy Enforcement
-- Script:  sql/policies/01_rls_policies.sql
-- Target:  Oracle Database (ORCLPDB) - Schema: SEC_OWNER
-- Purpose: Register Virtual Private Database (VPD) row-level confinement and
--          column-level data suppression policies via DBMS_RLS.
-- ============================================================================

SET ECHO ON;
SET DEFINE OFF;
SET SERVEROUTPUT ON SIZE UNLIMITED;
WHENEVER SQLERROR CONTINUE;

PROMPT ------------------------------------------------------------------------
PROMPT [PHASE 9: PART 1] Connecting as SEC_OWNER to Register VPD Policies
PROMPT ------------------------------------------------------------------------

CONNECT SEC_OWNER/SecOwner#Pass2026@localhost:1521/orclpdb

-- ----------------------------------------------------------------------------
-- 1. Grant Execution Privileges on Policy Engine Package
-- ----------------------------------------------------------------------------
PROMPT Granting EXECUTE on PKG_VPD_POLICIES...

GRANT EXECUTE ON SEC_OWNER.PKG_VPD_POLICIES TO APP_USER_ROLE;
GRANT EXECUTE ON SEC_OWNER.PKG_VPD_POLICIES TO APP_ADMIN_ROLE;
GRANT EXECUTE ON SEC_OWNER.PKG_VPD_POLICIES TO AUDIT_READER_ROLE;
GRANT EXECUTE ON SEC_OWNER.PKG_VPD_POLICIES TO APP_SERVICE_USER;

-- ----------------------------------------------------------------------------
-- 2. Clean Existing Policies for Idempotent Script Re-Runs
-- ----------------------------------------------------------------------------
PROMPT Dropping existing VPD policies if present...

BEGIN
    BEGIN
        DBMS_RLS.DROP_POLICY(
            object_schema => 'SEC_OWNER',
            object_name   => 'CUSTOMERS',
            policy_name   => 'POL_CUST_BRANCH_ISOLATION'
        );
        DBMS_OUTPUT.PUT_LINE('[DROPPED] Policy POL_CUST_BRANCH_ISOLATION dropped.');
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLCODE = -28102 THEN -- Policy does not exist
                DBMS_OUTPUT.PUT_LINE('[INFO] Policy POL_CUST_BRANCH_ISOLATION did not exist.');
            ELSE
                DBMS_OUTPUT.PUT_LINE('[WARNING] Drop POL_CUST_BRANCH_ISOLATION: ' || SQLERRM);
            END IF;
    END;

    BEGIN
        DBMS_RLS.DROP_POLICY(
            object_schema => 'SEC_OWNER',
            object_name   => 'CUSTOMERS',
            policy_name   => 'POL_CUST_COLUMN_MASK'
        );
        DBMS_OUTPUT.PUT_LINE('[DROPPED] Policy POL_CUST_COLUMN_MASK dropped.');
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLCODE = -28102 THEN
                DBMS_OUTPUT.PUT_LINE('[INFO] Policy POL_CUST_COLUMN_MASK did not exist.');
            ELSE
                DBMS_OUTPUT.PUT_LINE('[WARNING] Drop POL_CUST_COLUMN_MASK: ' || SQLERRM);
            END IF;
    END;
END;
/

-- ----------------------------------------------------------------------------
-- 3. Register Row-Level Confinement Policy (Branch Isolation)
-- ----------------------------------------------------------------------------
PROMPT Registering Row-Level Policy: POL_CUST_BRANCH_ISOLATION...

BEGIN
    DBMS_RLS.ADD_POLICY(
        object_schema   => 'SEC_OWNER',
        object_name     => 'CUSTOMERS',
        policy_name     => 'POL_CUST_BRANCH_ISOLATION',
        function_schema => 'SEC_OWNER',
        policy_function => 'PKG_VPD_POLICIES.GET_BRANCH_PREDICATE',
        statement_types => 'SELECT,INSERT,UPDATE,DELETE',
        update_check    => TRUE,
        enable          => TRUE,
        static_policy   => FALSE,
        policy_type     => DBMS_RLS.DYNAMIC
    );
    DBMS_OUTPUT.PUT_LINE('[SUCCESS] Registered Row-Level Policy: POL_CUST_BRANCH_ISOLATION');
EXCEPTION
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('[ERROR] Registering POL_CUST_BRANCH_ISOLATION: ' || SQLERRM);
        RAISE;
END;
/

-- ----------------------------------------------------------------------------
-- 4. Register Column-Level Suppression Policy (ALL_ROWS Redaction Hook)
-- ----------------------------------------------------------------------------
PROMPT Registering Column-Level Policy: POL_CUST_COLUMN_MASK...

BEGIN
    DBMS_RLS.ADD_POLICY(
        object_schema         => 'SEC_OWNER',
        object_name           => 'CUSTOMERS',
        policy_name           => 'POL_CUST_COLUMN_MASK',
        function_schema       => 'SEC_OWNER',
        policy_function       => 'PKG_VPD_POLICIES.GET_COLUMN_MASK_PREDICATE',
        statement_types       => 'SELECT',
        enable                => TRUE,
        static_policy         => FALSE,
        policy_type           => DBMS_RLS.DYNAMIC,
        sec_relevant_cols     => 'PHONE_NUMBER,EMAIL,NATIONAL_ID,CREDIT_CARD_NUM,ACCOUNT_BALANCE',
        sec_relevant_cols_opt => DBMS_RLS.ALL_ROWS
    );
    DBMS_OUTPUT.PUT_LINE('[SUCCESS] Registered Column-Level Policy: POL_CUST_COLUMN_MASK (ALL_ROWS)');
EXCEPTION
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('[ERROR] Registering POL_CUST_COLUMN_MASK: ' || SQLERRM);
        RAISE;
END;
/

COMMIT;

-- ----------------------------------------------------------------------------
-- 5. Verification: Inspect Registered Policies in USER_POLICIES & Columns
-- ----------------------------------------------------------------------------
PROMPT ------------------------------------------------------------------------
PROMPT [VERIFICATION] Inspecting Active Policies in USER_POLICIES
PROMPT ------------------------------------------------------------------------

COLUMN object_name FORMAT A15
COLUMN policy_name FORMAT A28
COLUMN function FORMAT A36
COLUMN sel FORMAT A4
COLUMN ins FORMAT A4
COLUMN upd FORMAT A4
COLUMN del FORMAT A4
COLUMN enable FORMAT A7
COLUMN policy_type FORMAT A16

SELECT 
    object_name,
    policy_name,
    package || '.' || function AS function,
    sel, ins, upd, del,
    enable,
    policy_type
FROM user_policies
WHERE object_name = 'CUSTOMERS'
ORDER BY policy_name;

PROMPT ------------------------------------------------------------------------
PROMPT [VERIFICATION] Inspecting Column-Level Suppression Bindings
PROMPT ------------------------------------------------------------------------

COLUMN sec_rel_column FORMAT A20
COLUMN column_option FORMAT A15

SELECT 
    policy_name,
    sec_rel_column,
    column_option
FROM user_sec_relevant_cols
WHERE object_name = 'CUSTOMERS'
ORDER BY policy_name, sec_rel_column;

PROMPT ------------------------------------------------------------------------
PROMPT [SUCCESS] Phase 9 VPD Policy Registration Completed!
PROMPT ------------------------------------------------------------------------
