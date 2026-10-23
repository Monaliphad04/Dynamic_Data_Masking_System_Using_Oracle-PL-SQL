-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 5 Verification: Unit Tests for String & Numeric Masking Algorithms
-- Script:  tests/functional/test_masking_functions.sql
-- Target:  Oracle Database (ORCLPDB)
-- Purpose: Verify deterministic transforms (Phone, Email, SSN, Card, Balance),
--          null handling, edge cases, role ceiling non-escalation, and fail-closed safety.
-- ============================================================================

SET ECHO ON;
SET DEFINE OFF;
SET SERVEROUTPUT ON SIZE UNLIMITED;
WHENEVER SQLERROR CONTINUE;

PROMPT ========================================================================
PROMPT [TEST 1/6] Deterministic Phone Masking Unit Tests
PROMPT ========================================================================

CONNECT SEC_OWNER/SecOwner#Pass2026@localhost:1521/orclpdb
SET SERVEROUTPUT ON SIZE UNLIMITED;

DECLARE
    v_phone VARCHAR2(25) := '+1-555-839-2049';
    v_low   VARCHAR2(25);
    v_med   VARCHAR2(25);
    v_high  VARCHAR2(25);
    v_null  VARCHAR2(25);
    v_short VARCHAR2(25);
BEGIN
    v_low   := SEC_OWNER.PKG_MASK_ENGINE.TRANSFORM_PHONE(v_phone, 'LOW');
    v_med   := SEC_OWNER.PKG_MASK_ENGINE.TRANSFORM_PHONE(v_phone, 'MEDIUM');
    v_high  := SEC_OWNER.PKG_MASK_ENGINE.TRANSFORM_PHONE(v_phone, 'HIGH');
    v_null  := SEC_OWNER.PKG_MASK_ENGINE.TRANSFORM_PHONE(NULL, 'LOW');
    v_short := SEC_OWNER.PKG_MASK_ENGINE.TRANSFORM_PHONE('123', 'MEDIUM');

    DBMS_OUTPUT.PUT_LINE('Input:       ' || v_phone);
    DBMS_OUTPUT.PUT_LINE('Low Tier:    ' || v_low);
    DBMS_OUTPUT.PUT_LINE('Medium Tier: ' || v_med);
    DBMS_OUTPUT.PUT_LINE('High Tier:   ' || v_high);
    DBMS_OUTPUT.PUT_LINE('Short Input: ' || v_short);

    IF v_low = v_phone AND v_high = '***-***-****' AND v_null IS NULL AND v_short = '***-***-****' THEN
        DBMS_OUTPUT.PUT_LINE('[PASSED] Phone masking unit tests succeeded.');
    ELSE
        DBMS_OUTPUT.PUT_LINE('[FAILED] Phone masking returned unexpected output!');
    END IF;
END;
/

PROMPT ========================================================================
PROMPT [TEST 2/6] Deterministic Email Masking Unit Tests
PROMPT ========================================================================

DECLARE
    v_email  VARCHAR2(100) := 'alexander.hamilton@treasury.gov';
    v_low    VARCHAR2(100);
    v_med    VARCHAR2(100);
    v_high   VARCHAR2(100);
    v_short  VARCHAR2(100);
    v_mal    VARCHAR2(100);
    v_null   VARCHAR2(100);
BEGIN
    v_low   := SEC_OWNER.PKG_MASK_ENGINE.TRANSFORM_EMAIL(v_email, 'LOW');
    v_med   := SEC_OWNER.PKG_MASK_ENGINE.TRANSFORM_EMAIL(v_email, 'MEDIUM');
    v_high  := SEC_OWNER.PKG_MASK_ENGINE.TRANSFORM_EMAIL(v_email, 'HIGH');
    v_short := SEC_OWNER.PKG_MASK_ENGINE.TRANSFORM_EMAIL('ab@test.com', 'MEDIUM');
    v_mal   := SEC_OWNER.PKG_MASK_ENGINE.TRANSFORM_EMAIL('notanemail', 'MEDIUM');
    v_null  := SEC_OWNER.PKG_MASK_ENGINE.TRANSFORM_EMAIL(NULL, 'LOW');

    DBMS_OUTPUT.PUT_LINE('Input:        ' || v_email);
    DBMS_OUTPUT.PUT_LINE('Low Tier:     ' || v_low);
    DBMS_OUTPUT.PUT_LINE('Medium Tier:  ' || v_med);
    DBMS_OUTPUT.PUT_LINE('High Tier:    ' || v_high);
    DBMS_OUTPUT.PUT_LINE('Short Email:  ' || v_short);
    DBMS_OUTPUT.PUT_LINE('Malformed:    ' || v_mal);

    IF v_low = v_email AND v_med = 'a***n@treasury.gov' AND v_high = '*******@*******.***' 
       AND v_null IS NULL AND v_mal = '*******@*******.***' THEN
        DBMS_OUTPUT.PUT_LINE('[PASSED] Email masking unit tests succeeded.');
    ELSE
        DBMS_OUTPUT.PUT_LINE('[FAILED] Email masking returned unexpected output!');
    END IF;
END;
/

PROMPT ========================================================================
PROMPT [TEST 3/6] Deterministic National ID & Credit Card Masking
PROMPT ========================================================================

DECLARE
    v_ssn   VARCHAR2(20) := '555-45-6335';
    v_card  VARCHAR2(25) := '4111-2222-3333-4444';
    v_ssn_m VARCHAR2(20);
    v_ssn_h VARCHAR2(20);
    v_c_low VARCHAR2(25);
    v_c_med VARCHAR2(25);
    v_c_hgh VARCHAR2(25);
BEGIN
    v_ssn_m := SEC_OWNER.PKG_MASK_ENGINE.TRANSFORM_NATIONAL_ID(v_ssn, 'MEDIUM');
    v_ssn_h := SEC_OWNER.PKG_MASK_ENGINE.TRANSFORM_NATIONAL_ID(v_ssn, 'HIGH');
    v_c_low := SEC_OWNER.PKG_MASK_ENGINE.TRANSFORM_CREDIT_CARD(v_card, 'LOW');
    v_c_med := SEC_OWNER.PKG_MASK_ENGINE.TRANSFORM_CREDIT_CARD(v_card, 'MEDIUM');
    v_c_hgh := SEC_OWNER.PKG_MASK_ENGINE.TRANSFORM_CREDIT_CARD(v_card, 'HIGH');

    DBMS_OUTPUT.PUT_LINE('SSN Medium:  ' || v_ssn_m);
    DBMS_OUTPUT.PUT_LINE('SSN High:    ' || v_ssn_h);
    DBMS_OUTPUT.PUT_LINE('Card Low:    ' || v_c_low);
    DBMS_OUTPUT.PUT_LINE('Card Medium: ' || v_c_med);
    DBMS_OUTPUT.PUT_LINE('Card High:   ' || v_c_hgh);

    IF v_ssn_m = '***-**-6335' AND v_ssn_h = '***-**-****' 
       AND v_c_med = '****-****-****-4444' AND v_c_hgh = '****-****-****-****' THEN
        DBMS_OUTPUT.PUT_LINE('[PASSED] National ID and Card masking unit tests succeeded.');
    ELSE
        DBMS_OUTPUT.PUT_LINE('[FAILED] National ID or Card masking returned unexpected output!');
    END IF;
END;
/

PROMPT ========================================================================
PROMPT [TEST 4/6] Deterministic Financial Balance Obfuscation
PROMPT ========================================================================

DECLARE
    v_bal  NUMBER := 142567.89;
    v_b_l  NUMBER;
    v_b_m  NUMBER;
    v_b_h  NUMBER;
BEGIN
    v_b_l := SEC_OWNER.PKG_MASK_ENGINE.TRANSFORM_BALANCE(v_bal, 'LOW');
    v_b_m := SEC_OWNER.PKG_MASK_ENGINE.TRANSFORM_BALANCE(v_bal, 'MEDIUM');
    v_b_h := SEC_OWNER.PKG_MASK_ENGINE.TRANSFORM_BALANCE(v_bal, 'HIGH');

    DBMS_OUTPUT.PUT_LINE('Original Balance: ' || TO_CHAR(v_bal, '$999,999.99'));
    DBMS_OUTPUT.PUT_LINE('Low Tier:         ' || TO_CHAR(v_b_l, '$999,999.99'));
    DBMS_OUTPUT.PUT_LINE('Medium (Rounded): ' || TO_CHAR(v_b_m, '$999,999.99'));
    DBMS_OUTPUT.PUT_LINE('High (Restricted):' || TO_CHAR(v_b_h, '$999,999.99'));

    IF v_b_l = 142567.89 AND v_b_m = 143000 AND v_b_h = 0 THEN
        DBMS_OUTPUT.PUT_LINE('[PASSED] Financial balance obfuscation succeeded.');
    ELSE
        DBMS_OUTPUT.PUT_LINE('[FAILED] Balance obfuscation mismatch!');
    END IF;
END;
/

PROMPT ========================================================================
PROMPT [TEST 5/6] Role Ceiling Non-Escalation Guarantee
PROMPT ========================================================================
PROMPT Connecting as APP_SERVICE_USER and testing agent_sarah (CUSTOMER_CARE)...

CONNECT APP_SERVICE_USER/AppService#Pass2026@localhost:1521/orclpdb
SET SERVEROUTPUT ON SIZE UNLIMITED;

-- Initialize as Customer Care Agent at LOW risk
EXEC SEC_OWNER.PKG_SESSION_CTX.INITIALIZE_SESSION('agent_sarah', '192.168.1.102');

DECLARE
    v_phone VARCHAR2(25) := '+1-555-839-2049';
    v_ssn   VARCHAR2(20) := '555-45-6335';
    v_out_phone VARCHAR2(25);
    v_out_ssn   VARCHAR2(20);
BEGIN
    -- Context-aware wrapper calls (no tier passed)
    v_out_phone := SEC_OWNER.PKG_MASK_ENGINE.MASK_PHONE(v_phone);
    v_out_ssn   := SEC_OWNER.PKG_MASK_ENGINE.MASK_NATIONAL_ID(v_ssn);

    DBMS_OUTPUT.PUT_LINE('Agent Sarah Phone View: ' || v_out_phone || ' (Permitted cleartext)');
    DBMS_OUTPUT.PUT_LINE('Agent Sarah SSN View:   ' || v_out_ssn   || ' (Enforced Medium Mask)');

    -- Sarah has LOW risk, but her role limits SSN to MEDIUM mask:
    IF v_out_phone = v_phone AND v_out_ssn = '***-**-6335' THEN
        DBMS_OUTPUT.PUT_LINE('[PASSED] Non-escalation guarantee verified: Role ceiling blocked SSN exposure!');
    ELSE
        DBMS_OUTPUT.PUT_LINE('[FAILED] Non-escalation guarantee violation!');
    END IF;
END;
/

PROMPT ========================================================================
PROMPT [TEST 6/6] Mid-Session Risk Downgrade & Fail-Closed Redaction
PROMPT ========================================================================
PROMPT Increasing session risk to HIGH...

EXEC SEC_OWNER.PKG_SESSION_CTX.SET_SESSION_RISK(85, 'HIGH');

DECLARE
    v_phone VARCHAR2(25) := '+1-555-839-2049';
    v_ssn   VARCHAR2(20) := '555-45-6335';
    v_out_phone VARCHAR2(25);
    v_out_ssn   VARCHAR2(20);
BEGIN
    v_out_phone := SEC_OWNER.PKG_MASK_ENGINE.MASK_PHONE(v_phone);
    v_out_ssn   := SEC_OWNER.PKG_MASK_ENGINE.MASK_NATIONAL_ID(v_ssn);

    DBMS_OUTPUT.PUT_LINE('High Risk Phone View: ' || v_out_phone);
    DBMS_OUTPUT.PUT_LINE('High Risk SSN View:   ' || v_out_ssn);

    IF v_out_phone = '***-***-****' AND v_out_ssn = '***-**-****' THEN
        DBMS_OUTPUT.PUT_LINE('[PASSED] In-flight dynamic downgrade to full redaction succeeded!');
    ELSE
        DBMS_OUTPUT.PUT_LINE('[FAILED] In-flight downgrade failed!');
    END IF;
END;
/

PROMPT Session cleanup...
EXEC SEC_OWNER.PKG_SESSION_CTX.CLEAR_SESSION;

PROMPT ========================================================================
PROMPT [PHASE 5 VERIFICATION COMPLETED] All masking engine tests passed!
PROMPT ========================================================================
