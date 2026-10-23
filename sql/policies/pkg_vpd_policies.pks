-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 9: Oracle VPD (DBMS_RLS) Policy Enforcement
-- Package: SEC_OWNER.PKG_VPD_POLICIES (Specification)
-- File:    sql/policies/pkg_vpd_policies.pks
-- Target:  Oracle Database (ORCLPDB) - Schema: SEC_OWNER
-- Purpose: Virtual Private Database (VPD / Fine-Grained Access Control) policy
--          functions enforcing kernel-level row filtering and column suppression.
-- ============================================================================

CREATE OR REPLACE PACKAGE SEC_OWNER.PKG_VPD_POLICIES AUTHID DEFINER AS

    /**
     * Row-Level VPD Security Policy Function: Branch Isolation.
     * Evaluates dynamic session context to restrict customer visibility to the
     * user's assigned organizational branch (e.g., BR_NYC_01, BR_LDN_02).
     *
     * Roles with organizational oversight (SEC_ADMIN, AUDITOR, COMPLIANCE_OFFICER)
     * are granted cross-branch visibility ('1=1').
     * Unauthenticated or corrupted sessions fail closed ('1=2').
     *
     * @param p_schema Target schema name (passed automatically by Oracle kernel)
     * @param p_object Target table or view name (passed automatically by Oracle kernel)
     * @return WHERE clause SQL predicate string
     */
    FUNCTION GET_BRANCH_PREDICATE(
        p_schema IN VARCHAR2,
        p_object IN VARCHAR2
    ) RETURN VARCHAR2;

    /**
     * Column-Level VPD Security Policy Function: In-Flight Column Suppression Hook.
     * Attached to sensitive columns via DBMS_RLS.ALL_ROWS.
     *
     * When session risk score is HIGH (>= 70) or unauthenticated, returns '1=2',
     * which causes the Oracle SQL kernel to replace sensitive columns with NULL
     * prior to projection.
     * When session risk score is LOW or MEDIUM, returns '1=1', passing columns to
     * VW_CUSTOMERS for format-preserving masking.
     *
     * @param p_schema Target schema name (passed automatically by Oracle kernel)
     * @param p_object Target table or view name (passed automatically by Oracle kernel)
     * @return WHERE clause SQL predicate string
     */
    FUNCTION GET_COLUMN_MASK_PREDICATE(
        p_schema IN VARCHAR2,
        p_object IN VARCHAR2
    ) RETURN VARCHAR2;

    /**
     * Administrative helper: Re-enables all configured VPD policies on CUSTOMERS.
     */
    PROCEDURE ENABLE_POLICIES;

    /**
     * Administrative helper: Temporarily disables VPD policies on CUSTOMERS for maintenance.
     */
    PROCEDURE DISABLE_POLICIES;

END PKG_VPD_POLICIES;
/
