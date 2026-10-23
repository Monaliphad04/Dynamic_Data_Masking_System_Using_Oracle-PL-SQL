-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 9: Oracle VPD (DBMS_RLS) Policy Enforcement
-- Package: SEC_OWNER.PKG_VPD_POLICIES (Body)
-- File:    sql/policies/pkg_vpd_policies.pkb
-- Target:  Oracle Database (ORCLPDB) - Schema: SEC_OWNER
-- Purpose: Implementation of kernel-level row confinement and column suppression.
-- ============================================================================

CREATE OR REPLACE PACKAGE BODY SEC_OWNER.PKG_VPD_POLICIES AS

    -- ========================================================================
    -- GET_BRANCH_PREDICATE
    -- ========================================================================
    FUNCTION GET_BRANCH_PREDICATE(
        p_schema IN VARCHAR2,
        p_object IN VARCHAR2
    ) RETURN VARCHAR2 IS
        v_is_init   VARCHAR2(10);
        v_status    VARCHAR2(50);
        v_role      VARCHAR2(50);
        v_branch    VARCHAR2(10);
        v_session_u VARCHAR2(50);
    BEGIN
        -- 1. Administrative / Maintenance / Schema Owner Exemption
        v_session_u := SYS_CONTEXT('USERENV', 'SESSION_USER');
        IF v_session_u IN ('SYS', 'SYSTEM', p_schema) THEN
            RETURN '1=1';
        END IF;

        -- 2. Validate Session Context Initialization
        v_is_init := SYS_CONTEXT('CTX_SEC_MASK', 'IS_INITIALIZED');
        v_status  := SYS_CONTEXT('CTX_SEC_MASK', 'STATUS');

        IF v_is_init IS NULL OR v_is_init != 'Y' OR v_status != 'ACTIVE' THEN
            -- Unauthenticated or invalid context: Fail-closed with zero rows returned
            RETURN '1=2';
        END IF;

        -- 3. Resolve Role and Assigned Branch
        v_role   := SYS_CONTEXT('CTX_SEC_MASK', 'ROLE_NAME');
        v_branch := SYS_CONTEXT('CTX_SEC_MASK', 'BRANCH_CODE');

        -- 4. Global Oversight Roles: Full Cross-Branch Visibility
        IF v_role IN ('SEC_ADMIN', 'AUDITOR', 'COMPLIANCE_OFFICER') THEN
            IF v_branch IS NOT NULL AND v_branch NOT IN ('ALL', 'NONE') THEN
                -- Explicit branch filtering requested by administrator
                RETURN 'branch_code = ''' || REPLACE(v_branch, '''', '''''') || '''';
            ELSE
                -- Full cross-branch access
                RETURN '1=1';
            END IF;
        END IF;

        -- 5. Operational Staff Roles (CUSTOMER_CARE, ANALYST): Strict Branch Isolation
        IF v_branch IS NULL OR v_branch IN ('NONE', 'UNASSIGNED') THEN
            -- Staff without verified branch assignment fail closed
            RETURN '1=2';
        ELSE
            -- Dynamic row confinement using context namespace variable
            RETURN 'branch_code = SYS_CONTEXT(''CTX_SEC_MASK'', ''BRANCH_CODE'')';
        END IF;

    EXCEPTION
        WHEN OTHERS THEN
            -- Fail-closed guarantee on any unexpected evaluation error
            RETURN '1=2';
    END GET_BRANCH_PREDICATE;

    -- ========================================================================
    -- GET_COLUMN_MASK_PREDICATE
    -- ========================================================================
    FUNCTION GET_COLUMN_MASK_PREDICATE(
        p_schema IN VARCHAR2,
        p_object IN VARCHAR2
    ) RETURN VARCHAR2 IS
        v_is_init   VARCHAR2(10);
        v_status    VARCHAR2(50);
        v_tier      VARCHAR2(10);
        v_score     NUMBER;
        v_session_u VARCHAR2(50);
    BEGIN
        -- 1. Administrative / Maintenance / Schema Owner Exemption
        v_session_u := SYS_CONTEXT('USERENV', 'SESSION_USER');
        IF v_session_u IN ('SYS', 'SYSTEM', p_schema) THEN
            RETURN '1=1';
        END IF;

        -- 2. Validate Session Context Initialization
        v_is_init := SYS_CONTEXT('CTX_SEC_MASK', 'IS_INITIALIZED');
        v_status  := SYS_CONTEXT('CTX_SEC_MASK', 'STATUS');

        IF v_is_init IS NULL OR v_is_init != 'Y' OR v_status != 'ACTIVE' THEN
            -- Unauthenticated caller: Suppress all sensitive column projections
            RETURN '1=2';
        END IF;

        -- 3. Inspect Real-Time Risk State
        v_tier := SYS_CONTEXT('CTX_SEC_MASK', 'RISK_TIER');
        BEGIN
            v_score := TO_NUMBER(SYS_CONTEXT('CTX_SEC_MASK', 'RISK_SCORE'));
        EXCEPTION
            WHEN OTHERS THEN
                v_score := 100;
        END;

        -- 4. Kernel Column Suppression on Elevated Risk
        IF v_tier = 'HIGH' OR NVL(v_score, 100) >= 70 THEN
            -- Returning '1=2' under DBMS_RLS.ALL_ROWS zeroes out protected columns to NULL
            RETURN '1=2';
        ELSE
            -- Low / Medium risk: Allow columns to pass to VW_CUSTOMERS for dynamic masking
            RETURN '1=1';
        END IF;

    EXCEPTION
        WHEN OTHERS THEN
            -- Fail-closed guarantee
            RETURN '1=2';
    END GET_COLUMN_MASK_PREDICATE;

    -- ========================================================================
    -- ENABLE_POLICIES
    -- ========================================================================
    PROCEDURE ENABLE_POLICIES IS
    BEGIN
        BEGIN
            DBMS_RLS.ENABLE_POLICY('SEC_OWNER', 'CUSTOMERS', 'POL_CUST_BRANCH_ISOLATION', TRUE);
        EXCEPTION WHEN OTHERS THEN NULL; END;

        BEGIN
            DBMS_RLS.ENABLE_POLICY('SEC_OWNER', 'CUSTOMERS', 'POL_CUST_COLUMN_MASK', TRUE);
        EXCEPTION WHEN OTHERS THEN NULL; END;
    END ENABLE_POLICIES;

    -- ========================================================================
    -- DISABLE_POLICIES
    -- ========================================================================
    PROCEDURE DISABLE_POLICIES IS
    BEGIN
        BEGIN
            DBMS_RLS.ENABLE_POLICY('SEC_OWNER', 'CUSTOMERS', 'POL_CUST_BRANCH_ISOLATION', FALSE);
        EXCEPTION WHEN OTHERS THEN NULL; END;

        BEGIN
            DBMS_RLS.ENABLE_POLICY('SEC_OWNER', 'CUSTOMERS', 'POL_CUST_COLUMN_MASK', FALSE);
        EXCEPTION WHEN OTHERS THEN NULL; END;
    END DISABLE_POLICIES;

END PKG_VPD_POLICIES;
/
