-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 5: Core Masking Functions & Algorithms
-- Package: SEC_OWNER.PKG_MASK_ENGINE (Specification)
-- File:    sql/functions/pkg_mask_engine.pks
-- Target:  Oracle Database (ORCLPDB) - Schema: SEC_OWNER
-- Purpose: Dynamic data masking algorithms for PII, financial, and national
--          identity attributes with deterministic transforms and fail-closed safety.
-- ============================================================================

SET DEFINE OFF;

CREATE OR REPLACE PACKAGE SEC_OWNER.PKG_MASK_ENGINE AUTHID DEFINER AS

    -- Static Redaction Tokens
    C_REDACTED_TEXT        CONSTANT VARCHAR2(20) := '[REDACTED]';
    C_REDACTED_PHONE       CONSTANT VARCHAR2(20) := '***-***-****';
    C_REDACTED_EMAIL       CONSTANT VARCHAR2(30) := '*******@*******.***';
    C_REDACTED_NAT_ID      CONSTANT VARCHAR2(20) := '***-**-****';
    C_REDACTED_CARD        CONSTANT VARCHAR2(25) := '****-****-****-****';
    C_ERROR_TOKEN          CONSTANT VARCHAR2(30) := '[SECURITY: REDACTED]';

    -- ========================================================================
    -- 1. Context-Aware In-Flight Masking Functions (Called by Views & VPD)
    --    Automatically resolves active risk tier and role limits from CTX_SEC_MASK.
    -- ========================================================================

    FUNCTION MASK_PHONE(p_phone IN VARCHAR2) RETURN VARCHAR2;
    FUNCTION MASK_EMAIL(p_email IN VARCHAR2) RETURN VARCHAR2;
    FUNCTION MASK_NATIONAL_ID(p_national_id IN VARCHAR2) RETURN VARCHAR2;
    FUNCTION MASK_CREDIT_CARD(p_card IN VARCHAR2) RETURN VARCHAR2;
    FUNCTION MASK_BALANCE(p_balance IN NUMBER) RETURN NUMBER;

    -- ========================================================================
    -- 2. Pure Deterministic Masking Engine Functions
    --    Explicitly parameter-driven for unit testing, batch jobs, and caching.
    -- ========================================================================

    FUNCTION TRANSFORM_PHONE(
        p_phone IN VARCHAR2,
        p_tier  IN VARCHAR2
    ) RETURN VARCHAR2 DETERMINISTIC;

    FUNCTION TRANSFORM_EMAIL(
        p_email IN VARCHAR2,
        p_tier  IN VARCHAR2
    ) RETURN VARCHAR2 DETERMINISTIC;

    FUNCTION TRANSFORM_NATIONAL_ID(
        p_national_id IN VARCHAR2,
        p_tier        IN VARCHAR2
    ) RETURN VARCHAR2 DETERMINISTIC;

    FUNCTION TRANSFORM_CREDIT_CARD(
        p_card IN VARCHAR2,
        p_tier IN VARCHAR2
    ) RETURN VARCHAR2 DETERMINISTIC;

    FUNCTION TRANSFORM_BALANCE(
        p_balance IN NUMBER,
        p_tier    IN VARCHAR2
    ) RETURN NUMBER DETERMINISTIC;

    -- ========================================================================
    -- 3. Effective Tier Evaluator (Enforces Role Upper Bound Ceiling)
    -- ========================================================================
    FUNCTION GET_EFFECTIVE_TIER(
        p_column_name IN VARCHAR2
    ) RETURN VARCHAR2;

END PKG_MASK_ENGINE;
/
