-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 6: Rule-Based Risk Scoring Engine
-- Package: SEC_OWNER.PKG_RISK_ENGINE (Specification)
-- File:    sql/procedures/pkg_risk_engine.pks
-- Target:  Oracle Database (ORCLPDB) - Schema: SEC_OWNER
-- Purpose: Real-time contextual risk scoring engine calculating composite threat
--          scores (0-100) based on temporal, network, velocity, and audit signals.
-- ============================================================================

SET DEFINE OFF;

CREATE OR REPLACE PACKAGE SEC_OWNER.PKG_RISK_ENGINE AUTHID DEFINER AS

    -- Risk Tier Categorization Thresholds
    C_LOW_THRESHOLD    CONSTANT NUMBER := 30; -- Score < 30 = LOW
    C_HIGH_THRESHOLD   CONSTANT NUMBER := 70; -- Score >= 70 = HIGH

    C_TIER_LOW         CONSTANT VARCHAR2(10) := 'LOW';
    C_TIER_MEDIUM      CONSTANT VARCHAR2(10) := 'MEDIUM';
    C_TIER_HIGH        CONSTANT VARCHAR2(10) := 'HIGH';

    /**
     * Evaluates active session context against active RISK_RULES.
     * Computes composite score normalized to [0, 100].
     * Optional override parameters enable simulation and test harnesses.
     *
     * @param p_override_ip   Simulated client IP (optional)
     * @param p_override_hour Simulated hour of day [0-23] (optional)
     * @return Normalized risk score (0 to 100)
     */
    FUNCTION EVALUATE_CURRENT_RISK(
        p_override_ip   IN VARCHAR2 DEFAULT NULL,
        p_override_hour IN NUMBER   DEFAULT NULL
    ) RETURN NUMBER;

    /**
     * Maps a numerical risk score (0-100) to its corresponding risk tier:
     *   0-29:   LOW
     *   30-69:  MEDIUM
     *   70-100: HIGH
     */
    FUNCTION RESOLVE_TIER(p_score IN NUMBER) RETURN VARCHAR2 DETERMINISTIC;

    /**
     * Returns the active session risk tier.
     * If no score provided, dynamically evaluates current session risk.
     */
    FUNCTION GET_CURRENT_RISK_TIER(
        p_override_ip   IN VARCHAR2 DEFAULT NULL,
        p_override_hour IN NUMBER   DEFAULT NULL
    ) RETURN VARCHAR2;

    /**
     * Evaluates risk and synchronizes active session state in CTX_SEC_MASK.
     * Immediately affects downstream in-flight masking projections.
     */
    PROCEDURE EVALUATE_AND_SYNC_SESSION(
        p_override_ip   IN VARCHAR2 DEFAULT NULL,
        p_override_hour IN NUMBER   DEFAULT NULL
    );

    /**
     * Evaluates if a given hour or current system timestamp represents off-hours
     * for the currently active user profile.
     */
    FUNCTION IS_OFF_HOURS(p_hour IN NUMBER DEFAULT NULL) RETURN BOOLEAN;

    /**
     * Evaluates if a client IP matches the user's pre-approved subnet.
     */
    FUNCTION IS_UNTRUSTED_IP(p_ip IN VARCHAR2 DEFAULT NULL) RETURN BOOLEAN;

    /**
     * Returns a comma-separated list of triggered rule codes for audit logs.
     * e.g., 'R_OFF_HOURS, R_UNTRUSTED_IP'
     */
    FUNCTION GET_TRIGGERED_RULES(
        p_override_ip   IN VARCHAR2 DEFAULT NULL,
        p_override_hour IN NUMBER   DEFAULT NULL
    ) RETURN VARCHAR2;

    /**
     * Increments failed authentication count for a user profile.
     */
    PROCEDURE RECORD_FAILED_LOGIN(p_username IN VARCHAR2);

    /**
     * Records query activity to update velocity metrics in USER_RISK.
     */
    PROCEDURE RECORD_QUERY_BURST(p_query_count IN NUMBER);

    /**
     * Administrative utility to reset behavioral anomaly counters.
     */
    PROCEDURE RESET_USER_ANOMALIES(p_username IN VARCHAR2);

END PKG_RISK_ENGINE;
/
