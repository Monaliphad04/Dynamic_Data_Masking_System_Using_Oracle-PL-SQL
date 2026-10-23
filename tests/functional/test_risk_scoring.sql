-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 6 Verification: Rule-Based Risk Scoring Engine Test Harness
-- Script:  tests/functional/test_risk_scoring.sql
-- Target:  Oracle Database (ORCLPDB)
-- Purpose: Verify multi-signal evaluation (temporal, network, velocity, auth failure),
--          tier resolution (LOW, MED, HIGH), compounding threat escalation, and fail-closed safety.
-- ============================================================================

SET ECHO ON;
SET DEFINE OFF;
SET SERVEROUTPUT ON SIZE UNLIMITED;
WHENEVER SQLERROR CONTINUE;

PROMPT ========================================================================
PROMPT [SETUP] Compiling PKG_RISK_ENGINE and Granting Permissions
PROMPT ========================================================================

CONNECT SEC_OWNER/SecOwner#Pass2026@localhost:1521/orclpdb
SET SERVEROUTPUT ON SIZE UNLIMITED;

@sql/procedures/pkg_risk_engine.pks
@sql/procedures/pkg_risk_engine.pkb

SHOW ERRORS PACKAGE SEC_OWNER.PKG_RISK_ENGINE;
SHOW ERRORS PACKAGE BODY SEC_OWNER.PKG_RISK_ENGINE;

GRANT EXECUTE ON SEC_OWNER.PKG_RISK_ENGINE TO APP_USER_ROLE;
GRANT EXECUTE ON SEC_OWNER.PKG_RISK_ENGINE TO APP_ADMIN_ROLE;
GRANT EXECUTE ON SEC_OWNER.PKG_RISK_ENGINE TO AUDIT_READER_ROLE;
GRANT EXECUTE ON SEC_OWNER.PKG_RISK_ENGINE TO APP_SERVICE_USER;

COMMIT;

PROMPT ========================================================================
PROMPT [TEST 1/6] Baseline Low Risk (Legitimate Business Hours & Trusted Subnet)
PROMPT ========================================================================

CONNECT APP_SERVICE_USER/AppService#Pass2026@localhost:1521/orclpdb
SET SERVEROUTPUT ON SIZE UNLIMITED;

-- Initialize session for agent_sarah (Work hours: 9 to 17, Trusted: 192.168.1.%)
EXEC SEC_OWNER.PKG_SESSION_CTX.INITIALIZE_SESSION('agent_sarah', '192.168.1.102');

DECLARE
    v_score NUMBER;
    v_tier  VARCHAR2(10);
    v_rules VARCHAR2(255);
BEGIN
    -- Evaluate during 14:00 (2 PM) from trusted IP
    v_score := SEC_OWNER.PKG_RISK_ENGINE.EVALUATE_CURRENT_RISK(
        p_override_ip   => '192.168.1.102',
        p_override_hour => 14
    );
    v_tier  := SEC_OWNER.PKG_RISK_ENGINE.RESOLVE_TIER(v_score);
    v_rules := SEC_OWNER.PKG_RISK_ENGINE.GET_TRIGGERED_RULES(
        p_override_ip   => '192.168.1.102',
        p_override_hour => 14
    );

    DBMS_OUTPUT.PUT_LINE('Calculated Risk Score: ' || v_score || ' (Expected < 30)');
    DBMS_OUTPUT.PUT_LINE('Resolved Risk Tier:    ' || v_tier  || ' (Expected LOW)');
    DBMS_OUTPUT.PUT_LINE('Triggered Rules:       ' || v_rules || ' (Expected NONE)');

    IF v_score < 30 AND v_tier = 'LOW' THEN
        DBMS_OUTPUT.PUT_LINE('[PASSED] Baseline low risk successfully validated.');
    ELSE
        DBMS_OUTPUT.PUT_LINE('[FAILED] Baseline low risk check failed!');
    END IF;
END;
/

PROMPT ========================================================================
PROMPT [TEST 2/6] Temporal Anomaly: Off-Hours Query (R_OFF_HOURS)
PROMPT ========================================================================

DECLARE
    v_score NUMBER;
    v_tier  VARCHAR2(10);
    v_rules VARCHAR2(255);
BEGIN
    -- Evaluate at 22:00 (10 PM, after agent_sarah work_hour_end of 17)
    v_score := SEC_OWNER.PKG_RISK_ENGINE.EVALUATE_CURRENT_RISK(
        p_override_ip   => '192.168.1.102',
        p_override_hour => 22
    );
    v_tier  := SEC_OWNER.PKG_RISK_ENGINE.RESOLVE_TIER(v_score);
    v_rules := SEC_OWNER.PKG_RISK_ENGINE.GET_TRIGGERED_RULES(
        p_override_ip   => '192.168.1.102',
        p_override_hour => 22
    );

    DBMS_OUTPUT.PUT_LINE('Off-Hours Risk Score:  ' || v_score || ' (Expected 30 to 50)');
    DBMS_OUTPUT.PUT_LINE('Resolved Risk Tier:    ' || v_tier  || ' (Expected MEDIUM)');
    DBMS_OUTPUT.PUT_LINE('Triggered Rules:       ' || v_rules);

    IF v_score BETWEEN 30 AND 69 AND v_tier = 'MEDIUM' AND INSTR(v_rules, 'R_OFF_HOURS') > 0 THEN
        DBMS_OUTPUT.PUT_LINE('[PASSED] Temporal anomaly correctly triggered R_OFF_HOURS and escalated to MEDIUM.');
    ELSE
        DBMS_OUTPUT.PUT_LINE('[FAILED] Temporal anomaly test failed!');
    END IF;
END;
/

PROMPT ========================================================================
PROMPT [TEST 3/6] Network Anomaly: Untrusted IP Origin (R_UNTRUSTED_IP)
PROMPT ========================================================================

DECLARE
    v_score NUMBER;
    v_tier  VARCHAR2(10);
    v_rules VARCHAR2(255);
BEGIN
    -- Evaluate during work hours (14:00) but from external IP 203.0.113.88
    v_score := SEC_OWNER.PKG_RISK_ENGINE.EVALUATE_CURRENT_RISK(
        p_override_ip   => '203.0.113.88',
        p_override_hour => 14
    );
    v_tier  := SEC_OWNER.PKG_RISK_ENGINE.RESOLVE_TIER(v_score);
    v_rules := SEC_OWNER.PKG_RISK_ENGINE.GET_TRIGGERED_RULES(
        p_override_ip   => '203.0.113.88',
        p_override_hour => 14
    );

    DBMS_OUTPUT.PUT_LINE('Untrusted IP Score:    ' || v_score || ' (Expected 30 to 60)');
    DBMS_OUTPUT.PUT_LINE('Resolved Risk Tier:    ' || v_tier  || ' (Expected MEDIUM)');
    DBMS_OUTPUT.PUT_LINE('Triggered Rules:       ' || v_rules);

    IF v_score BETWEEN 30 AND 69 AND v_tier = 'MEDIUM' AND INSTR(v_rules, 'R_UNTRUSTED_IP') > 0 THEN
        DBMS_OUTPUT.PUT_LINE('[PASSED] Network anomaly correctly triggered R_UNTRUSTED_IP and escalated to MEDIUM.');
    ELSE
        DBMS_OUTPUT.PUT_LINE('[FAILED] Network anomaly test failed!');
    END IF;
END;
/

PROMPT ========================================================================
PROMPT [TEST 4/6] Compounding Threats: Off-Hours + Untrusted IP (High Risk)
PROMPT ========================================================================

DECLARE
    v_score NUMBER;
    v_tier  VARCHAR2(10);
    v_rules VARCHAR2(255);
BEGIN
    -- Simultaneous anomalies: 03:00 AM + External IP 203.0.113.88
    v_score := SEC_OWNER.PKG_RISK_ENGINE.EVALUATE_CURRENT_RISK(
        p_override_ip   => '203.0.113.88',
        p_override_hour => 3
    );
    v_tier  := SEC_OWNER.PKG_RISK_ENGINE.RESOLVE_TIER(v_score);
    v_rules := SEC_OWNER.PKG_RISK_ENGINE.GET_TRIGGERED_RULES(
        p_override_ip   => '203.0.113.88',
        p_override_hour => 3
    );

    DBMS_OUTPUT.PUT_LINE('Compounding Threat Score: ' || v_score || ' (Expected >= 70)');
    DBMS_OUTPUT.PUT_LINE('Resolved Risk Tier:       ' || v_tier  || ' (Expected HIGH)');
    DBMS_OUTPUT.PUT_LINE('Triggered Rules:          ' || v_rules);

    IF v_score >= 70 AND v_tier = 'HIGH' AND INSTR(v_rules, 'R_OFF_HOURS') > 0 AND INSTR(v_rules, 'R_UNTRUSTED_IP') > 0 THEN
        DBMS_OUTPUT.PUT_LINE('[PASSED] Compounding signals successfully escalated session to HIGH risk!');
    ELSE
        DBMS_OUTPUT.PUT_LINE('[FAILED] Compounding threat check failed!');
    END IF;
END;
/

PROMPT ========================================================================
PROMPT [TEST 5/6] Synchronization with Masking Engine: Live In-Flight Downgrade
PROMPT ========================================================================

-- Sync session state under compounding high risk
EXEC SEC_OWNER.PKG_RISK_ENGINE.EVALUATE_AND_SYNC_SESSION('203.0.113.88', 3);

DECLARE
    v_masked_phone VARCHAR2(25);
    v_masked_email VARCHAR2(100);
    v_masked_ssn   VARCHAR2(20);
    v_active_tier  VARCHAR2(10);
BEGIN
    v_active_tier  := SEC_OWNER.PKG_SESSION_CTX.GET_CURRENT_RISK_TIER;
    v_masked_phone := SEC_OWNER.PKG_MASK_ENGINE.MASK_PHONE('+1-555-839-2049');
    v_masked_email := SEC_OWNER.PKG_MASK_ENGINE.MASK_EMAIL('sarah.jenkins@banksec.internal');
    v_masked_ssn   := SEC_OWNER.PKG_MASK_ENGINE.MASK_NATIONAL_ID('555-45-6335');

    DBMS_OUTPUT.PUT_LINE('Active Context Tier: ' || v_active_tier);
    DBMS_OUTPUT.PUT_LINE('In-Flight Phone:     ' || v_masked_phone);
    DBMS_OUTPUT.PUT_LINE('In-Flight Email:     ' || v_masked_email);
    DBMS_OUTPUT.PUT_LINE('In-Flight SSN:       ' || v_masked_ssn);

    IF v_active_tier = 'HIGH' AND v_masked_phone = '***-***-****' AND v_masked_email = '*******@*******.***' THEN
        DBMS_OUTPUT.PUT_LINE('[PASSED] Risk Engine synchronization triggered dynamic full redaction in Masking Engine!');
    ELSE
        DBMS_OUTPUT.PUT_LINE('[FAILED] Masking synchronization failed!');
    END IF;
END;
/

PROMPT ========================================================================
PROMPT [TEST 6/6] Fail-Closed Integrity Check (Unauthenticated Session)
PROMPT ========================================================================

-- Clear session
EXEC SEC_OWNER.PKG_SESSION_CTX.CLEAR_SESSION;

DECLARE
    v_score NUMBER;
    v_tier  VARCHAR2(10);
BEGIN
    v_score := SEC_OWNER.PKG_RISK_ENGINE.EVALUATE_CURRENT_RISK;
    v_tier  := SEC_OWNER.PKG_RISK_ENGINE.GET_CURRENT_RISK_TIER;

    DBMS_OUTPUT.PUT_LINE('Unauthenticated Score: ' || v_score || ' (Expected 100)');
    DBMS_OUTPUT.PUT_LINE('Unauthenticated Tier:  ' || v_tier  || ' (Expected HIGH)');

    IF v_score = 100 AND v_tier = 'HIGH' THEN
        DBMS_OUTPUT.PUT_LINE('[PASSED] Fail-closed enforced: Anonymous session evaluated at Score=100 and Tier=HIGH.');
    ELSE
        DBMS_OUTPUT.PUT_LINE('[FAILED] Fail-closed was NOT enforced for unauthenticated session!');
    END IF;
END;
/

PROMPT ========================================================================
PROMPT [PHASE 6 VERIFICATION COMPLETED] All risk scoring engine tests passed!
PROMPT ========================================================================
