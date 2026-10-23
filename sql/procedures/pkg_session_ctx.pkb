-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 4: Trusted Context & Session Management
-- Package: SEC_OWNER.PKG_SESSION_CTX (Body)
-- File:    sql/procedures/pkg_session_ctx.pkb
-- Target:  Oracle Database (ORCLPDB) - Schema: SEC_OWNER
-- Purpose: Implementation of trusted session management, fail-closed identity
--          validation, and secure namespace population.
-- ============================================================================

CREATE OR REPLACE PACKAGE BODY SEC_OWNER.PKG_SESSION_CTX AS

    -- ------------------------------------------------------------------------
    -- Private Helper: Sets Fail-Closed Default Context on Error / Invalid User
    -- ------------------------------------------------------------------------
    PROCEDURE SET_FAIL_CLOSED_STATE(
        p_username IN VARCHAR2,
        p_reason   IN VARCHAR2
    ) IS
    BEGIN
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'APP_USER',           NVL(p_username, 'UNKNOWN'));
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'USER_ID',            '-1');
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'ROLE_NAME',          'UNAUTHENTICATED');
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'ROLE_ID',            '-1');
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'MAX_PERMITTED_RISK', '0');
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'CLIENT_IP',          C_DEFAULT_IP);
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'TRUSTED_IP_SUBNET',  'NONE');
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'WORK_HOUR_START',    '0');
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'WORK_HOUR_END',      '0');
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'RISK_SCORE',         TO_CHAR(C_MAX_RISK_SCORE));
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'RISK_TIER',          'HIGH');
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'AUTH_TIME',          TO_CHAR(SYSTIMESTAMP, 'YYYY-MM-DD HH24:MI:SS'));
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'IS_INITIALIZED',     'N');
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'STATUS',             p_reason);
    END SET_FAIL_CLOSED_STATE;

    -- ------------------------------------------------------------------------
    -- INITIALIZE_SESSION
    -- ------------------------------------------------------------------------
    PROCEDURE INITIALIZE_SESSION(
        p_username  IN VARCHAR2,
        p_client_ip IN VARCHAR2 DEFAULT NULL
    ) IS
        v_user_rec       SEC_OWNER.APP_USERS%ROWTYPE;
        v_role_name      SEC_OWNER.USER_ROLES.ROLE_NAME%TYPE;
        v_max_risk       SEC_OWNER.USER_ROLES.MAX_PERMITTED_RISK%TYPE;
        v_initial_score  NUMBER;
        v_initial_tier   VARCHAR2(10);
        v_effective_ip   VARCHAR2(50);
    BEGIN
        -- 1. Validate parameter presence
        IF p_username IS NULL OR TRIM(p_username) IS NULL THEN
            SET_FAIL_CLOSED_STATE('ANONYMOUS', 'NULL_USERNAME');
            RETURN;
        END IF;

        -- 2. Query user identity and role specification
        BEGIN
            SELECT u.*, r.role_name, r.max_permitted_risk
            INTO v_user_rec.user_id, v_user_rec.username, v_user_rec.full_name,
                 v_user_rec.email, v_user_rec.role_id, v_user_rec.account_status,
                 v_user_rec.trusted_ip_subnet, v_user_rec.work_hour_start,
                 v_user_rec.work_hour_end, v_user_rec.created_at,
                 v_role_name, v_max_risk
            FROM SEC_OWNER.APP_USERS u
            JOIN SEC_OWNER.USER_ROLES r ON u.role_id = r.role_id
            WHERE u.username = LOWER(TRIM(p_username));
        EXCEPTION
            WHEN NO_DATA_FOUND THEN
                -- User not registered: Fail closed with max risk
                SET_FAIL_CLOSED_STATE(p_username, 'USER_NOT_FOUND');
                RETURN;
        END;

        -- 3. Verify account status
        IF v_user_rec.account_status != 'ACTIVE' THEN
            -- Inactive / Suspended / Locked user: Fail closed with max risk
            SET_FAIL_CLOSED_STATE(p_username, 'ACCOUNT_' || v_user_rec.account_status);
            RETURN;
        END IF;

        -- 4. Resolve client network IP address
        IF p_client_ip IS NOT NULL AND TRIM(p_client_ip) IS NOT NULL THEN
            v_effective_ip := TRIM(p_client_ip);
        ELSE
            v_effective_ip := SYS_CONTEXT('USERENV', 'IP_ADDRESS');
            IF v_effective_ip IS NULL THEN
                v_effective_ip := C_DEFAULT_IP;
            END IF;
        END IF;

        -- 5. Retrieve baseline risk profile
        BEGIN
            SELECT NVL(score_override, current_score), risk_tier
            INTO v_initial_score, v_initial_tier
            FROM SEC_OWNER.USER_RISK
            WHERE user_id = v_user_rec.user_id;
        EXCEPTION
            WHEN NO_DATA_FOUND THEN
                -- Fallback baseline risk
                v_initial_score := 10;
                v_initial_tier  := 'LOW';
        END;

        -- 6. Lock trusted session attributes into CTX_SEC_MASK namespace
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'APP_USER',           v_user_rec.username);
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'USER_ID',            TO_CHAR(v_user_rec.user_id));
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'ROLE_NAME',          v_role_name);
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'ROLE_ID',            TO_CHAR(v_user_rec.role_id));
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'MAX_PERMITTED_RISK', TO_CHAR(v_max_risk));
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'CLIENT_IP',          v_effective_ip);
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'TRUSTED_IP_SUBNET',  NVL(v_user_rec.trusted_ip_subnet, '%'));
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'WORK_HOUR_START',    TO_CHAR(v_user_rec.work_hour_start));
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'WORK_HOUR_END',      TO_CHAR(v_user_rec.work_hour_end));
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'RISK_SCORE',         TO_CHAR(v_initial_score));
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'RISK_TIER',          v_initial_tier);
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'AUTH_TIME',          TO_CHAR(SYSTIMESTAMP, 'YYYY-MM-DD HH24:MI:SS'));
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'IS_INITIALIZED',     'Y');
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'STATUS',             'ACTIVE');

    EXCEPTION
        WHEN OTHERS THEN
            -- Any unexpected runtime failure forces strict fail-closed state
            SET_FAIL_CLOSED_STATE(p_username, 'INTERNAL_ERROR');
    END INITIALIZE_SESSION;

    -- ------------------------------------------------------------------------
    -- SET_SESSION_RISK
    -- ------------------------------------------------------------------------
    PROCEDURE SET_SESSION_RISK(
        p_score IN NUMBER,
        p_tier  IN VARCHAR2
    ) IS
        v_clamped_score NUMBER;
        v_validated_tier VARCHAR2(10);
    BEGIN
        -- Bounded score: 0 to 100
        v_clamped_score := GREATEST(0, LEAST(C_MAX_RISK_SCORE, NVL(p_score, C_MAX_RISK_SCORE)));

        -- Validate tier
        IF UPPER(p_tier) IN ('LOW', 'MEDIUM', 'HIGH') THEN
            v_validated_tier := UPPER(p_tier);
        ELSE
            v_validated_tier := 'HIGH';
        END IF;

        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'RISK_SCORE', TO_CHAR(v_clamped_score));
        DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'RISK_TIER',  v_validated_tier);
    EXCEPTION
        WHEN OTHERS THEN
            -- In event of failure, enforce maximum risk
            DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'RISK_SCORE', TO_CHAR(C_MAX_RISK_SCORE));
            DBMS_SESSION.SET_CONTEXT(C_CONTEXT_NAMESPACE, 'RISK_TIER',  'HIGH');
    END SET_SESSION_RISK;

    -- ------------------------------------------------------------------------
    -- CLEAR_SESSION
    -- ------------------------------------------------------------------------
    PROCEDURE CLEAR_SESSION IS
    BEGIN
        DBMS_SESSION.CLEAR_CONTEXT(C_CONTEXT_NAMESPACE);
    EXCEPTION
        WHEN OTHERS THEN
            NULL;
    END CLEAR_SESSION;

    -- ------------------------------------------------------------------------
    -- Getters for Context Attributes
    -- ------------------------------------------------------------------------
    FUNCTION GET_APP_USER RETURN VARCHAR2 DETERMINISTIC IS
        v_val VARCHAR2(50) := SYS_CONTEXT(C_CONTEXT_NAMESPACE, 'APP_USER');
    BEGIN
        RETURN NVL(v_val, C_DEFAULT_USER);
    END GET_APP_USER;

    FUNCTION GET_USER_ID RETURN NUMBER DETERMINISTIC IS
        v_val VARCHAR2(50) := SYS_CONTEXT(C_CONTEXT_NAMESPACE, 'USER_ID');
    BEGIN
        RETURN TO_NUMBER(NVL(v_val, '-1'));
    EXCEPTION
        WHEN OTHERS THEN
            RETURN -1;
    END GET_USER_ID;

    FUNCTION GET_ROLE_NAME RETURN VARCHAR2 DETERMINISTIC IS
        v_val VARCHAR2(50) := SYS_CONTEXT(C_CONTEXT_NAMESPACE, 'ROLE_NAME');
    BEGIN
        RETURN NVL(v_val, C_DEFAULT_ROLE);
    END GET_ROLE_NAME;

    FUNCTION GET_MAX_PERMITTED_RISK RETURN NUMBER DETERMINISTIC IS
        v_val VARCHAR2(50) := SYS_CONTEXT(C_CONTEXT_NAMESPACE, 'MAX_PERMITTED_RISK');
    BEGIN
        RETURN TO_NUMBER(NVL(v_val, '0'));
    EXCEPTION
        WHEN OTHERS THEN
            RETURN 0;
    END GET_MAX_PERMITTED_RISK;

    FUNCTION GET_CLIENT_IP RETURN VARCHAR2 DETERMINISTIC IS
        v_val VARCHAR2(50) := SYS_CONTEXT(C_CONTEXT_NAMESPACE, 'CLIENT_IP');
    BEGIN
        RETURN NVL(v_val, C_DEFAULT_IP);
    END GET_CLIENT_IP;

    FUNCTION GET_CURRENT_RISK_SCORE RETURN NUMBER DETERMINISTIC IS
        v_val VARCHAR2(50) := SYS_CONTEXT(C_CONTEXT_NAMESPACE, 'RISK_SCORE');
    BEGIN
        RETURN TO_NUMBER(NVL(v_val, TO_CHAR(C_MAX_RISK_SCORE)));
    EXCEPTION
        WHEN OTHERS THEN
            RETURN C_MAX_RISK_SCORE;
    END GET_CURRENT_RISK_SCORE;

    FUNCTION GET_CURRENT_RISK_TIER RETURN VARCHAR2 DETERMINISTIC IS
        v_val VARCHAR2(50) := SYS_CONTEXT(C_CONTEXT_NAMESPACE, 'RISK_TIER');
    BEGIN
        RETURN NVL(v_val, 'HIGH');
    END GET_CURRENT_RISK_TIER;

    FUNCTION GET_WORK_HOUR_START RETURN NUMBER DETERMINISTIC IS
        v_val VARCHAR2(50) := SYS_CONTEXT(C_CONTEXT_NAMESPACE, 'WORK_HOUR_START');
    BEGIN
        RETURN TO_NUMBER(NVL(v_val, '9'));
    EXCEPTION
        WHEN OTHERS THEN
            RETURN 9;
    END GET_WORK_HOUR_START;

    FUNCTION GET_WORK_HOUR_END RETURN NUMBER DETERMINISTIC IS
        v_val VARCHAR2(50) := SYS_CONTEXT(C_CONTEXT_NAMESPACE, 'WORK_HOUR_END');
    BEGIN
        RETURN TO_NUMBER(NVL(v_val, '18'));
    EXCEPTION
        WHEN OTHERS THEN
            RETURN 18;
    END GET_WORK_HOUR_END;

    FUNCTION GET_TRUSTED_IP_SUBNET RETURN VARCHAR2 DETERMINISTIC IS
        v_val VARCHAR2(50) := SYS_CONTEXT(C_CONTEXT_NAMESPACE, 'TRUSTED_IP_SUBNET');
    BEGIN
        RETURN NVL(v_val, '%');
    END GET_TRUSTED_IP_SUBNET;

    FUNCTION IS_SESSION_INITIALIZED RETURN VARCHAR2 DETERMINISTIC IS
        v_val VARCHAR2(10) := SYS_CONTEXT(C_CONTEXT_NAMESPACE, 'IS_INITIALIZED');
    BEGIN
        RETURN NVL(v_val, 'N');
    END IS_SESSION_INITIALIZED;

END PKG_SESSION_CTX;
/
