-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 7: Auditing Architecture & Autonomous Logging
-- Package: SEC_OWNER.PKG_AUDIT (Specification)
-- File:    sql/procedures/pkg_audit.pks
-- Target:  Oracle Database (ORCLPDB) - Schema: SEC_OWNER
-- Purpose: Non-repudiable audit logger capturing read access, evaluated risk,
--          masking tiers, and security anomalies via autonomous transactions.
-- ============================================================================

SET DEFINE OFF;

CREATE OR REPLACE PACKAGE SEC_OWNER.PKG_AUDIT AUTHID DEFINER AS

    /**
     * Autonomously logs a data access event into ACCESS_LOGS.
     * Uses PRAGMA AUTONOMOUS_TRANSACTION to guarantee audit immutability,
     * ensuring forensic traces survive any client transaction rollback.
     *
     * @param p_target_object    Table or View accessed (default 'CUSTOMERS')
     * @param p_records_accessed Number of records returned/projected (default 1)
     * @param p_action_type      Type of operation ('SELECT', 'EXPORT', 'DML')
     * @param p_notes            Optional contextual annotation or override
     */
    PROCEDURE LOG_READ_ACCESS(
        p_target_object    IN VARCHAR2 DEFAULT 'CUSTOMERS',
        p_records_accessed IN NUMBER   DEFAULT 1,
        p_action_type      IN VARCHAR2 DEFAULT 'SELECT',
        p_notes            IN VARCHAR2 DEFAULT NULL
    );

    /**
     * Function wrapper allowing autonomous logging inside SQL SELECT projections
     * or view filter clauses without mutating the parent transaction state.
     *
     * @return Always returns 1 for transparent SQL integration
     */
    FUNCTION AUDIT_READ_EVENT(
        p_target_object    IN VARCHAR2 DEFAULT 'CUSTOMERS',
        p_records_accessed IN NUMBER   DEFAULT 1
    ) RETURN NUMBER;

    /**
     * Administrative purge utility to archive/prune historical audit records.
     * Accessible exclusively to AUDIT_READER_ROLE or SEC_ADMIN.
     *
     * @param p_retention_days Number of days of audit logs to retain (default 90)
     */
    PROCEDURE PURGE_AUDIT_LOGS(
        p_retention_days IN NUMBER DEFAULT 90
    );

END PKG_AUDIT;
/
