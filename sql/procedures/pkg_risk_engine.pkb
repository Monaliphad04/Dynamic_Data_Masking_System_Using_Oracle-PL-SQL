-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 6: Rule-Based Risk Scoring Engine
-- Package: SEC_OWNER.PKG_RISK_ENGINE (Body)
-- File:    sql/procedures/pkg_risk_engine.pkb
-- Target:  Oracle Database (ORCLPDB) - Schema: SEC_OWNER
-- Purpose: Implementation of multi-signal threat evaluation, weighted scoring,
--          flapping prevention, and dynamic session synchronization.
-- ============================================================================

SET DEFINE OFF;

CREATE OR REPLACE PACKAGE BODY SEC_OWNER.PKG_RISK_ENGINE AS

    -- ------------------------------------------------------------------------
    -- Private Helper: Lookup active rule weight from RISK_RULES table
    -- ------------------------------------------------------------------------
    FUNCTION GET_RULE_WEIGHT(p_rule_code IN VARCHAR2) RETURN NUMBER IS
        v_weight NUMBER := 0;
    BEGIN
        SELECT weight INTO v_weight
        FROM SEC_OWNER.RISK_RULES
        WHERE rule_code = p_rule_code AND is_active = 'Y';
        RETURN NVL(v_weight, 0);
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RETURN 0;
        WHEN OTHERS THEN
            RETURN 0;
    END GET_RULE_WEIGHT;

    -- ------------------------------------------------------------------------
    -- RESOLVE_TIER
    -- Maps numerical score to LOW, MEDIUM, or HIGH
    -- ------------------------------------------------------------------------
    FUNCTION RESOLVE_TIER(p_score IN NUMBER) RETURN VARCHAR2 DETERMINISTIC IS
        v_clamped NUMBER := GREATEST(0, LEAST(100, NVL(p_score, 100)));
    BEGIN
        IF v_clamped < C_LOW_THRESHOLD THEN
            RETURN C_TIER_LOW;
        ELSIF v_clamped < C_HIGH_THRESHOLD THEN
            RETURN C_TIER_MEDIUM;
        ELSE
            RETURN C_TIER_HIGH;
        END IF;
    END RESOLVE_TIER;

    -- ------------------------------------------------------------------------
    -- IS_OFF_HOURS
    -- Checks if given hour / current timestamp is outside user's business hours
    -- ------------------------------------------------------------------------
    FUNCTION IS_OFF_HOURS(p_hour IN NUMBER DEFAULT NULL) RETURN BOOLEAN IS
        v_hour        NUMBER;
        v_day_of_week VARCHAR2(10);
        v_start_hour  NUMBER;
        v_end_hour    NUMBER;
    BEGIN
        -- Resolve effective hour
        IF p_hour IS NOT NULL THEN
            v_hour := p_hour;
        ELSE
            v_hour := TO_NUMBER(TO_CHAR(SYSDATE, 'HH24'));
            v_day_of_week := UPPER(TO_CHAR(SYSDATE, 'DY', 'NLS_DATE_LANGUAGE=ENGLISH'));
            -- Weekend check
            IF v_day_of_week IN ('SAT', 'SUN') THEN
                RETURN TRUE;
            END IF;
        END IF;

        v_start_hour := SEC_OWNER.PKG_SESSION_CTX.GET_WORK_HOUR_START;
        v_end_hour   := SEC_OWNER.PKG_SESSION_CTX.GET_WORK_HOUR_END;

        IF v_hour < v_start_hour OR v_hour >= v_end_hour THEN
            RETURN TRUE;
        END IF;

        RETURN FALSE;
    EXCEPTION
        WHEN OTHERS THEN
            RETURN TRUE; -- Fail-closed
    END IS_OFF_HOURS;

    -- ------------------------------------------------------------------------
    -- IS_UNTRUSTED_IP
    -- Matches client IP against authorized subnet pattern
    -- ------------------------------------------------------------------------
    FUNCTION IS_UNTRUSTED_IP(p_ip IN VARCHAR2 DEFAULT NULL) RETURN BOOLEAN IS
        v_effective_ip   VARCHAR2(50);
        v_trusted_subnet VARCHAR2(50);
    BEGIN
        IF p_ip IS NOT NULL AND TRIM(p_ip) IS NOT NULL THEN
            v_effective_ip := TRIM(p_ip);
        ELSE
            v_effective_ip := SEC_OWNER.PKG_SESSION_CTX.GET_CLIENT_IP;
        END IF;

        v_trusted_subnet := SEC_OWNER.PKG_SESSION_CTX.GET_TRUSTED_IP_SUBNET;

        -- Subnet wildcard evaluation
        IF v_effective_ip LIKE v_trusted_subnet THEN
            RETURN FALSE; -- Trusted IP
        ELSE
            RETURN TRUE;  -- Untrusted IP
        END IF;
    EXCEPTION
        WHEN OTHERS THEN
            RETURN TRUE; -- Fail-closed
    END IS_UNTRUSTED_IP;

    -- ------------------------------------------------------------------------
    -- EVALUATE_CURRENT_RISK
    -- Aggregates weighted contextual signals into normalized composite score
    -- ------------------------------------------------------------------------
    FUNCTION EVALUATE_CURRENT_RISK(
        p_override_ip   IN VARCHAR2 DEFAULT NULL,
        p_override_hour IN NUMBER   DEFAULT NULL
    ) RETURN NUMBER IS
        v_score          NUMBER := 0;
        v_user_id        NUMBER;
        v_failed_logins  NUMBER := 0;
        v_query_count    NUMBER := 0;
        v_override_score NUMBER;
    BEGIN
        -- 1. Ensure session is initialized (fail-closed if anonymous or invalid)
        IF SEC_OWNER.PKG_SESSION_CTX.IS_SESSION_INITIALIZED != 'Y' THEN
            RETURN 100;
        END IF;

        v_user_id := SEC_OWNER.PKG_SESSION_CTX.GET_USER_ID;
        IF v_user_id <= 0 THEN
            RETURN 100;
        END IF;

        -- 2. Inspect USER_RISK historical profile
        BEGIN
            SELECT score_override, failed_logins_24h, query_count_current_window
            INTO v_override_score, v_failed_logins, v_query_count
            FROM SEC_OWNER.USER_RISK
            WHERE user_id = v_user_id;

            -- Administrative manual score override takes highest precedence
            IF v_override_score IS NOT NULL THEN
                RETURN GREATEST(0, LEAST(100, v_override_score));
            END IF;
        EXCEPTION
            WHEN NO_DATA_FOUND THEN
                v_score := 10; -- Default baseline
        END;

        -- 3. Signal Evaluation: Temporal Anomaly (R_OFF_HOURS)
        IF IS_OFF_HOURS(p_override_hour) THEN
            v_score := v_score + GET_RULE_WEIGHT('R_OFF_HOURS');
        END IF;

        -- 4. Signal Evaluation: Network Origin (R_UNTRUSTED_IP)
        IF IS_UNTRUSTED_IP(p_override_ip) THEN
            v_score := v_score + GET_RULE_WEIGHT('R_UNTRUSTED_IP');
        END IF;

        -- 5. Signal Evaluation: Velocity Burst (R_BURST_QUERY)
        IF v_query_count > 30 THEN
            v_score := v_score + GET_RULE_WEIGHT('R_BURST_QUERY');
        END IF;

        -- 6. Signal Evaluation: Authentication History (R_FAILED_AUTH)
        IF v_failed_logins >= 3 THEN
            v_score := v_score + GET_RULE_WEIGHT('R_FAILED_AUTH');
        END IF;

        -- 7. Clamp composite score [0, 100]
        RETURN GREATEST(0, LEAST(100, v_score));
    EXCEPTION
        WHEN OTHERS THEN
            -- Fail-closed default on any unexpected calculation error
            RETURN 100;
    END EVALUATE_CURRENT_RISK;

    -- ------------------------------------------------------------------------
    -- GET_CURRENT_RISK_TIER
    -- ------------------------------------------------------------------------
    FUNCTION GET_CURRENT_RISK_TIER(
        p_override_ip   IN VARCHAR2 DEFAULT NULL,
        p_override_hour IN NUMBER   DEFAULT NULL
    ) RETURN VARCHAR2 IS
    BEGIN
        RETURN RESOLVE_TIER(EVALUATE_CURRENT_RISK(p_override_ip, p_override_hour));
    END GET_CURRENT_RISK_TIER;

    -- ------------------------------------------------------------------------
    -- GET_TRIGGERED_RULES
    -- ------------------------------------------------------------------------
    FUNCTION GET_TRIGGERED_RULES(
        p_override_ip   IN VARCHAR2 DEFAULT NULL,
        p_override_hour IN NUMBER   DEFAULT NULL
    ) RETURN VARCHAR2 IS
        v_rules         VARCHAR2(255) := '';
        v_user_id       NUMBER;
        v_failed_logins NUMBER := 0;
        v_query_count   NUMBER := 0;
    BEGIN
        IF SEC_OWNER.PKG_SESSION_CTX.IS_SESSION_INITIALIZED != 'Y' THEN
            RETURN 'R_UNAUTHENTICATED';
        END IF;

        v_user_id := SEC_OWNER.PKG_SESSION_CTX.GET_USER_ID;
        BEGIN
            SELECT failed_logins_24h, query_count_current_window
            INTO v_failed_logins, v_query_count
            FROM SEC_OWNER.USER_RISK
            WHERE user_id = v_user_id;
        EXCEPTION
            WHEN NO_DATA_FOUND THEN NULL;
        END;

        IF IS_OFF_HOURS(p_override_hour) THEN
            v_rules := v_rules || 'R_OFF_HOURS, ';
        END IF;

        IF IS_UNTRUSTED_IP(p_override_ip) THEN
            v_rules := v_rules || 'R_UNTRUSTED_IP, ';
        END IF;

        IF v_query_count > 30 THEN
            v_rules := v_rules || 'R_BURST_QUERY, ';
        END IF;

        IF v_failed_logins >= 3 THEN
            v_rules := v_rules || 'R_FAILED_AUTH, ';
        END IF;

        -- Trim trailing comma
        IF LENGTH(v_rules) > 2 THEN
            v_rules := SUBSTR(v_rules, 1, LENGTH(v_rules) - 2);
        ELSE
            v_rules := 'NONE';
        END IF;

        RETURN v_rules;
    END GET_TRIGGERED_RULES;

    -- ------------------------------------------------------------------------
    -- EVALUATE_AND_SYNC_SESSION
    -- Computes score and locks into active context and USER_RISK table
    -- ------------------------------------------------------------------------
    PROCEDURE EVALUATE_AND_SYNC_SESSION(
        p_override_ip   IN VARCHAR2 DEFAULT NULL,
        p_override_hour IN NUMBER   DEFAULT NULL
    ) IS
        v_score   NUMBER;
        v_tier    VARCHAR2(10);
        v_user_id NUMBER;
    BEGIN
        v_score   := EVALUATE_CURRENT_RISK(p_override_ip, p_override_hour);
        v_tier    := RESOLVE_TIER(v_score);
        v_user_id := SEC_OWNER.PKG_SESSION_CTX.GET_USER_ID;

        -- 1. Synchronize memory-resident session context
        SEC_OWNER.PKG_SESSION_CTX.SET_SESSION_RISK(v_score, v_tier);

        -- 2. Update persistent user risk state
        IF v_user_id > 0 THEN
            UPDATE SEC_OWNER.USER_RISK
            SET current_score  = v_score,
                risk_tier      = v_tier,
                last_evaluated = SYSTIMESTAMP
            WHERE user_id = v_user_id;
            COMMIT;
        END IF;
    EXCEPTION
        WHEN OTHERS THEN
            SEC_OWNER.PKG_SESSION_CTX.SET_SESSION_RISK(100, C_TIER_HIGH);
    END EVALUATE_AND_SYNC_SESSION;

    -- ------------------------------------------------------------------------
    -- RECORD_FAILED_LOGIN (Autonomous Transaction)
    -- ------------------------------------------------------------------------
    PROCEDURE RECORD_FAILED_LOGIN(p_username IN VARCHAR2) IS
        PRAGMA AUTONOMOUS_TRANSACTION;
        v_uid NUMBER;
    BEGIN
        SELECT user_id INTO v_uid 
        FROM SEC_OWNER.APP_USERS 
        WHERE username = LOWER(TRIM(p_username));

        UPDATE SEC_OWNER.USER_RISK
        SET failed_logins_24h = failed_logins_24h + 1,
            last_evaluated    = SYSTIMESTAMP
        WHERE user_id = v_uid;

        COMMIT;
    EXCEPTION
        WHEN OTHERS THEN
            ROLLBACK;
    END RECORD_FAILED_LOGIN;

    -- ------------------------------------------------------------------------
    -- RECORD_QUERY_BURST (Autonomous Transaction)
    -- ------------------------------------------------------------------------
    PROCEDURE RECORD_QUERY_BURST(p_query_count IN NUMBER) IS
        PRAGMA AUTONOMOUS_TRANSACTION;
        v_uid NUMBER := SEC_OWNER.PKG_SESSION_CTX.GET_USER_ID;
    BEGIN
        IF v_uid > 0 THEN
            UPDATE SEC_OWNER.USER_RISK
            SET query_count_current_window = query_count_current_window + NVL(p_query_count, 1),
                last_evaluated             = SYSTIMESTAMP
            WHERE user_id = v_uid;
            COMMIT;
        END IF;
    EXCEPTION
        WHEN OTHERS THEN
            ROLLBACK;
    END RECORD_QUERY_BURST;

    -- ------------------------------------------------------------------------
    -- RESET_USER_ANOMALIES (Autonomous Transaction)
    -- ------------------------------------------------------------------------
    PROCEDURE RESET_USER_ANOMALIES(p_username IN VARCHAR2) IS
        PRAGMA AUTONOMOUS_TRANSACTION;
        v_uid NUMBER;
    BEGIN
        SELECT user_id INTO v_uid 
        FROM SEC_OWNER.APP_USERS 
        WHERE username = LOWER(TRIM(p_username));

        UPDATE SEC_OWNER.USER_RISK
        SET failed_logins_24h          = 0,
            query_count_current_window = 0,
            current_score              = 10,
            risk_tier                  = C_TIER_LOW,
            score_override             = NULL,
            last_evaluated             = SYSTIMESTAMP
        WHERE user_id = v_uid;

        COMMIT;
    EXCEPTION
        WHEN OTHERS THEN
            ROLLBACK;
    END RESET_USER_ANOMALIES;

END PKG_RISK_ENGINE;
/
