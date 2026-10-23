-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 5: Core Masking Functions & Algorithms
-- Package: SEC_OWNER.PKG_MASK_ENGINE (Body)
-- File:    sql/functions/pkg_mask_engine.pkb
-- Target:  Oracle Database (ORCLPDB) - Schema: SEC_OWNER
-- Purpose: Implementation of dynamic obfuscation algorithms, non-escalation
--          ceiling checks, and fail-closed security redaction.
-- ============================================================================

SET DEFINE OFF;

CREATE OR REPLACE PACKAGE BODY SEC_OWNER.PKG_MASK_ENGINE AS

    -- ------------------------------------------------------------------------
    -- GET_EFFECTIVE_TIER
    -- Evaluates session risk tier and applies role-based non-escalation limits.
    -- Risk can only downgrade visibility; it can never elevate beyond role clearance.
    -- ------------------------------------------------------------------------
    FUNCTION GET_EFFECTIVE_TIER(
        p_column_name IN VARCHAR2
    ) RETURN VARCHAR2 IS
        v_session_tier VARCHAR2(10);
        v_role_name    VARCHAR2(50);
        v_is_init      VARCHAR2(10);
        v_col_upper    VARCHAR2(50) := UPPER(TRIM(p_column_name));
    BEGIN
        -- 1. Check if session is authenticated and initialized
        v_is_init := SEC_OWNER.PKG_SESSION_CTX.IS_SESSION_INITIALIZED;
        IF v_is_init != 'Y' THEN
            -- Uninitialized session: Fail-closed to HIGH risk
            RETURN 'HIGH';
        END IF;

        -- 2. Fetch active session attributes
        v_session_tier := SEC_OWNER.PKG_SESSION_CTX.GET_CURRENT_RISK_TIER;
        v_role_name    := SEC_OWNER.PKG_SESSION_CTX.GET_ROLE_NAME;

        -- 3. Enforce Role-Based Maximum Clearance Ceilings (Non-Escalation Guarantee)
        IF v_col_upper IN ('NATIONAL_ID', 'CREDIT_CARD_NUM') THEN
            -- Frontline customer care staff can NEVER inspect cleartext National ID or Card,
            -- even if session risk score is 0 (LOW). Minimum tier is MEDIUM.
            IF v_role_name = 'CUSTOMER_CARE' AND v_session_tier = 'LOW' THEN
                RETURN 'MEDIUM';
            END IF;

            -- Analysts cannot view customer identifiers or cards under any circumstance
            IF v_role_name = 'ANALYST' THEN
                RETURN 'HIGH';
            END IF;
        END IF;

        IF v_col_upper = 'ACCOUNT_BALANCE' THEN
            -- Frontline care agents only receive rounded balance at best
            IF v_role_name = 'CUSTOMER_CARE' AND v_session_tier = 'LOW' THEN
                RETURN 'MEDIUM';
            END IF;
        END IF;

        -- If session risk is already HIGH or MEDIUM, it always takes precedence
        RETURN v_session_tier;
    EXCEPTION
        WHEN OTHERS THEN
            -- Fail-closed default on unexpected error
            RETURN 'HIGH';
    END GET_EFFECTIVE_TIER;

    -- ========================================================================
    -- Pure Deterministic Masking Engine Functions
    -- ========================================================================

    -- ------------------------------------------------------------------------
    -- TRANSFORM_PHONE
    -- Low:    Cleartext (+1-555-839-2049)
    -- Medium: Partial Mask (+1-555-***-**49)
    -- High:   Full Redaction (***-***-****)
    -- ------------------------------------------------------------------------
    FUNCTION TRANSFORM_PHONE(
        p_phone IN VARCHAR2,
        p_tier  IN VARCHAR2
    ) RETURN VARCHAR2 DETERMINISTIC IS
        v_tier VARCHAR2(10) := UPPER(NVL(p_tier, 'HIGH'));
        v_len  NUMBER;
    BEGIN
        IF p_phone IS NULL THEN
            RETURN NULL;
        END IF;

        IF v_tier = 'LOW' THEN
            RETURN p_phone;
        ELSIF v_tier = 'MEDIUM' THEN
            v_len := LENGTH(p_phone);
            IF v_len >= 10 THEN
                -- Format with prefix and suffix preservation
                RETURN SUBSTR(p_phone, 1, 4) || '***-**' || SUBSTR(p_phone, -2);
            ELSIF v_len >= 6 THEN
                RETURN SUBSTR(p_phone, 1, 2) || '****' || SUBSTR(p_phone, -2);
            ELSE
                RETURN C_REDACTED_PHONE;
            END IF;
        ELSE
            RETURN C_REDACTED_PHONE;
        END IF;
    EXCEPTION
        WHEN OTHERS THEN
            RETURN C_ERROR_TOKEN;
    END TRANSFORM_PHONE;

    -- ------------------------------------------------------------------------
    -- TRANSFORM_EMAIL
    -- Low:    Cleartext (alexander.hamilton@treasury.gov)
    -- Medium: Partial Mask (a***n@treasury.gov)
    -- High:   Full Redaction (*******@*******.***)
    -- ------------------------------------------------------------------------
    FUNCTION TRANSFORM_EMAIL(
        p_email IN VARCHAR2,
        p_tier  IN VARCHAR2
    ) RETURN VARCHAR2 DETERMINISTIC IS
        v_tier   VARCHAR2(10) := UPPER(NVL(p_tier, 'HIGH'));
        v_at_pos NUMBER;
        v_user   VARCHAR2(100);
        v_domain VARCHAR2(100);
    BEGIN
        IF p_email IS NULL THEN
            RETURN NULL;
        END IF;

        IF v_tier = 'LOW' THEN
            RETURN p_email;
        ELSIF v_tier = 'MEDIUM' THEN
            v_at_pos := INSTR(p_email, '@');
            IF v_at_pos > 1 THEN
                v_user   := SUBSTR(p_email, 1, v_at_pos - 1);
                v_domain := SUBSTR(p_email, v_at_pos); -- includes '@'
                
                IF LENGTH(v_user) <= 2 THEN
                    RETURN SUBSTR(v_user, 1, 1) || '***' || v_domain;
                ELSE
                    RETURN SUBSTR(v_user, 1, 1) || '***' || SUBSTR(v_user, -1, 1) || v_domain;
                END IF;
            ELSE
                RETURN C_REDACTED_EMAIL;
            END IF;
        ELSE
            RETURN C_REDACTED_EMAIL;
        END IF;
    EXCEPTION
        WHEN OTHERS THEN
            RETURN C_ERROR_TOKEN;
    END TRANSFORM_EMAIL;

    -- ------------------------------------------------------------------------
    -- TRANSFORM_NATIONAL_ID
    -- Low:    Cleartext (555-45-6335)
    -- Medium: Partial Mask (***-**-6335)
    -- High:   Full Redaction (***-**-****)
    -- ------------------------------------------------------------------------
    FUNCTION TRANSFORM_NATIONAL_ID(
        p_national_id IN VARCHAR2,
        p_tier        IN VARCHAR2
    ) RETURN VARCHAR2 DETERMINISTIC IS
        v_tier VARCHAR2(10) := UPPER(NVL(p_tier, 'HIGH'));
    BEGIN
        IF p_national_id IS NULL THEN
            RETURN NULL;
        END IF;

        IF v_tier = 'LOW' THEN
            RETURN p_national_id;
        ELSIF v_tier = 'MEDIUM' THEN
            IF LENGTH(p_national_id) >= 4 THEN
                RETURN '***-**-' || SUBSTR(p_national_id, -4);
            ELSE
                RETURN C_REDACTED_NAT_ID;
            END IF;
        ELSE
            RETURN C_REDACTED_NAT_ID;
        END IF;
    EXCEPTION
        WHEN OTHERS THEN
            RETURN C_ERROR_TOKEN;
    END TRANSFORM_NATIONAL_ID;

    -- ------------------------------------------------------------------------
    -- TRANSFORM_CREDIT_CARD
    -- Low:    PCI Formatted (4111-****-****-1234)
    -- Medium: Masked Prefix (****-****-****-1234)
    -- High:   Full Redaction (****-****-****-****)
    -- ------------------------------------------------------------------------
    FUNCTION TRANSFORM_CREDIT_CARD(
        p_card IN VARCHAR2,
        p_tier IN VARCHAR2
    ) RETURN VARCHAR2 DETERMINISTIC IS
        v_tier VARCHAR2(10) := UPPER(NVL(p_tier, 'HIGH'));
    BEGIN
        IF p_card IS NULL THEN
            RETURN NULL;
        END IF;

        IF v_tier = 'LOW' THEN
            IF LENGTH(p_card) >= 16 THEN
                RETURN SUBSTR(p_card, 1, 4) || '-****-****-' || SUBSTR(p_card, -4);
            ELSE
                RETURN '****-****-****-' || SUBSTR(p_card, -4);
            END IF;
        ELSIF v_tier = 'MEDIUM' THEN
            IF LENGTH(p_card) >= 4 THEN
                RETURN '****-****-****-' || SUBSTR(p_card, -4);
            ELSE
                RETURN C_REDACTED_CARD;
            END IF;
        ELSE
            RETURN C_REDACTED_CARD;
        END IF;
    EXCEPTION
        WHEN OTHERS THEN
            RETURN C_ERROR_TOKEN;
    END TRANSFORM_CREDIT_CARD;

    -- ------------------------------------------------------------------------
    -- TRANSFORM_BALANCE
    -- Low:    Cleartext ($142,500.75)
    -- Medium: Rounded to Thousands ($143,000.00)
    -- High:   Restricted (0.00)
    -- ------------------------------------------------------------------------
    FUNCTION TRANSFORM_BALANCE(
        p_balance IN NUMBER,
        p_tier    IN VARCHAR2
    ) RETURN NUMBER DETERMINISTIC IS
        v_tier VARCHAR2(10) := UPPER(NVL(p_tier, 'HIGH'));
    BEGIN
        IF p_balance IS NULL THEN
            RETURN NULL;
        END IF;

        IF v_tier = 'LOW' THEN
            RETURN p_balance;
        ELSIF v_tier = 'MEDIUM' THEN
            -- Round to nearest 1,000
            RETURN ROUND(p_balance, -3);
        ELSE
            -- High risk: complete financial redaction
            RETURN 0.00;
        END IF;
    EXCEPTION
        WHEN OTHERS THEN
            RETURN 0.00;
    END TRANSFORM_BALANCE;

    -- ========================================================================
    -- Context-Aware Wrapper Functions (Dynamically Bind to Session Context)
    -- ========================================================================

    FUNCTION MASK_PHONE(p_phone IN VARCHAR2) RETURN VARCHAR2 IS
    BEGIN
        RETURN TRANSFORM_PHONE(p_phone, GET_EFFECTIVE_TIER('PHONE_NUMBER'));
    END MASK_PHONE;

    FUNCTION MASK_EMAIL(p_email IN VARCHAR2) RETURN VARCHAR2 IS
    BEGIN
        RETURN TRANSFORM_EMAIL(p_email, GET_EFFECTIVE_TIER('EMAIL'));
    END MASK_EMAIL;

    FUNCTION MASK_NATIONAL_ID(p_national_id IN VARCHAR2) RETURN VARCHAR2 IS
    BEGIN
        RETURN TRANSFORM_NATIONAL_ID(p_national_id, GET_EFFECTIVE_TIER('NATIONAL_ID'));
    END MASK_NATIONAL_ID;

    FUNCTION MASK_CREDIT_CARD(p_card IN VARCHAR2) RETURN VARCHAR2 IS
    BEGIN
        RETURN TRANSFORM_CREDIT_CARD(p_card, GET_EFFECTIVE_TIER('CREDIT_CARD_NUM'));
    END MASK_CREDIT_CARD;

    FUNCTION MASK_BALANCE(p_balance IN NUMBER) RETURN NUMBER IS
    BEGIN
        RETURN TRANSFORM_BALANCE(p_balance, GET_EFFECTIVE_TIER('ACCOUNT_BALANCE'));
    END MASK_BALANCE;

END PKG_MASK_ENGINE;
/
