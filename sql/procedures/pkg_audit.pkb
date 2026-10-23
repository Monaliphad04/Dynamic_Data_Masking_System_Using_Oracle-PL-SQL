-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 7: Auditing Architecture & Autonomous Logging
-- Package: SEC_OWNER.PKG_AUDIT (Body)
-- File:    sql/procedures/pkg_audit.pkb
-- Target:  Oracle Database (ORCLPDB) - Schema: SEC_OWNER
-- Purpose: Implementation of autonomous audit logging, rollback survivability,
--          and forensic query monitoring.
-- ============================================================================

SET DEFINE OFF;

CREATE OR REPLACE PACKAGE BODY SEC_OWNER.PKG_AUDIT AS

    -- ------------------------------------------------------------------------
    -- LOG_READ_ACCESS (Autonomous Transaction)
    -- Persists event independently of client transaction boundaries.
    -- ------------------------------------------------------------------------
    PROCEDURE LOG_READ_ACCESS(
        p_target_object    IN VARCHAR2 DEFAULT 'CUSTOMERS',
        p_records_accessed IN NUMBER   DEFAULT 1,
        p_action_type      IN VARCHAR2 DEFAULT 'SELECT',
        p_notes            IN VARCHAR2 DEFAULT NULL
    ) IS
        PRAGMA AUTONOMOUS_TRANSACTION;

        v_session_user    VARCHAR2(50);
        v_app_username    VARCHAR2(50);
        v_client_ip       VARCHAR2(50);
        v_risk_score      NUMBER;
        v_applied_tier    VARCHAR2(10);
        v_triggered_rules VARCHAR2(255);
        v_target          VARCHAR2(100);
        v_action          VARCHAR2(20);
    BEGIN
        -- 1. Resolve connection and application session context
        v_session_user := NVL(SYS_CONTEXT('USERENV', 'SESSION_USER'), 'UNKNOWN_DBA');
        v_app_username := SEC_OWNER.PKG_SESSION_CTX.GET_APP_USER;
        v_client_ip    := SEC_OWNER.PKG_SESSION_CTX.GET_CLIENT_IP;
        v_risk_score   := SEC_OWNER.PKG_SESSION_CTX.GET_CURRENT_RISK_SCORE;
        v_applied_tier := SEC_OWNER.PKG_SESSION_CTX.GET_CURRENT_RISK_TIER;

        -- 2. Fetch triggered threat indicators
        IF p_notes IS NOT NULL THEN
            v_triggered_rules := SUBSTR(p_notes, 1, 255);
        ELSE
            v_triggered_rules := SEC_OWNER.PKG_RISK_ENGINE.GET_TRIGGERED_RULES;
        END IF;

        -- 3. Sanitize target and action
        v_target := UPPER(NVL(TRIM(p_target_object), 'CUSTOMERS'));
        v_action := UPPER(NVL(TRIM(p_action_type), 'SELECT'));

        -- 4. Persist forensic audit record
        INSERT INTO SEC_OWNER.ACCESS_LOGS (
            session_user,
            app_username,
            client_ip,
            action_type,
            target_object,
            records_accessed,
            calculated_risk,
            applied_tier,
            triggered_rules,
            access_time
        ) VALUES (
            v_session_user,
            v_app_username,
            v_client_ip,
            v_action,
            v_target,
            GREATEST(0, NVL(p_records_accessed, 1)),
            v_risk_score,
            v_applied_tier,
            v_triggered_rules,
            SYSTIMESTAMP
        );

        -- Autonomous transaction must explicitly commit before return
        COMMIT;
    EXCEPTION
        WHEN OTHERS THEN
            -- In event of audit logger internal failure, rollback autonomous trans
            ROLLBACK;
    END LOG_READ_ACCESS;

    -- ------------------------------------------------------------------------
    -- AUDIT_READ_EVENT
    -- Function hook for inline query / view execution
    -- ------------------------------------------------------------------------
    FUNCTION AUDIT_READ_EVENT(
        p_target_object    IN VARCHAR2 DEFAULT 'CUSTOMERS',
        p_records_accessed IN NUMBER   DEFAULT 1
    ) RETURN NUMBER IS
    BEGIN
        LOG_READ_ACCESS(p_target_object, p_records_accessed, 'SELECT');
        RETURN 1;
    EXCEPTION
        WHEN OTHERS THEN
            RETURN 1;
    END AUDIT_READ_EVENT;

    -- ------------------------------------------------------------------------
    -- PURGE_AUDIT_LOGS (Autonomous Transaction)
    -- Maintenance utility to remove records older than retention threshold
    -- ------------------------------------------------------------------------
    PROCEDURE PURGE_AUDIT_LOGS(
        p_retention_days IN NUMBER DEFAULT 90
    ) IS
        PRAGMA AUTONOMOUS_TRANSACTION;
        v_days NUMBER := NVL(p_retention_days, 90);
    BEGIN
        DELETE FROM SEC_OWNER.ACCESS_LOGS
        WHERE access_time < (SYSTIMESTAMP - NUMTODSINTERVAL(v_days, 'DAY'));

        COMMIT;
    EXCEPTION
        WHEN OTHERS THEN
            ROLLBACK;
    END PURGE_AUDIT_LOGS;

END PKG_AUDIT;
/
