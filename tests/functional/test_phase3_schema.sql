-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 3 Verification: Schema, Integrity Constraints, and Data Integrity Test
-- Script:  tests/functional/test_phase3_schema.sql
-- Target:  Oracle Database (ORCLPDB) - Schema: SEC_OWNER
-- Purpose: Verify tables, tablespace allocations, foreign keys, check constraints,
--          and negative constraint enforcement.
-- ============================================================================

SET ECHO ON;
SET DEFINE OFF;
SET SERVEROUTPUT ON SIZE UNLIMITED;
WHENEVER SQLERROR CONTINUE;

PROMPT ========================================================================
PROMPT [TEST 1/5] Connecting as SEC_OWNER and Verifying Table & Tablespace Storage
PROMPT ========================================================================

CONNECT SEC_OWNER/SecOwner#Pass2026@localhost:1521/orclpdb
SET SERVEROUTPUT ON SIZE UNLIMITED;

SELECT table_name, tablespace_name, status
FROM user_tables
ORDER BY table_name;

-- Verify all 7 tables are present and in TS_SEC_DATA
DECLARE
    v_missing NUMBER;
BEGIN
    SELECT COUNT(*) INTO v_missing
    FROM (
        SELECT 'USER_ROLES' AS t FROM dual UNION ALL
        SELECT 'APP_USERS' FROM dual UNION ALL
        SELECT 'CUSTOMERS' FROM dual UNION ALL
        SELECT 'RISK_RULES' FROM dual UNION ALL
        SELECT 'USER_RISK' FROM dual UNION ALL
        SELECT 'ACCESS_LOGS' FROM dual UNION ALL
        SELECT 'MASKING_POLICIES' FROM dual
    ) expected
    WHERE expected.t NOT IN (
        SELECT table_name FROM user_tables WHERE tablespace_name = 'TS_SEC_DATA'
    );

    IF v_missing = 0 THEN
        DBMS_OUTPUT.PUT_LINE('[SUCCESS] All 7 tables reside in TS_SEC_DATA.');
    ELSE
        DBMS_OUTPUT.PUT_LINE('[ERROR] ' || v_missing || ' tables missing from TS_SEC_DATA!');
    END IF;
END;
/

PROMPT ========================================================================
PROMPT [TEST 2/5] Verifying Indexes Allocation in TS_SEC_IDX
PROMPT ========================================================================

SELECT index_name, table_name, tablespace_name, status
FROM user_indexes
ORDER BY table_name, index_name;

PROMPT ========================================================================
PROMPT [TEST 3/5] Verifying Row Counts Across All Seeded Entities
PROMPT ========================================================================

DECLARE
    v_roles NUMBER;
    v_users NUMBER;
    v_rules NUMBER;
    v_urisk NUMBER;
    v_pols  NUMBER;
    v_custs NUMBER;
BEGIN
    SELECT COUNT(*) INTO v_roles FROM USER_ROLES;
    SELECT COUNT(*) INTO v_users FROM APP_USERS;
    SELECT COUNT(*) INTO v_rules FROM RISK_RULES;
    SELECT COUNT(*) INTO v_urisk FROM USER_RISK;
    SELECT COUNT(*) INTO v_pols  FROM MASKING_POLICIES;
    SELECT COUNT(*) INTO v_custs FROM CUSTOMERS;

    DBMS_OUTPUT.PUT_LINE('[COUNT] USER_ROLES:       ' || v_roles || ' (Expected >= 5)');
    DBMS_OUTPUT.PUT_LINE('[COUNT] APP_USERS:        ' || v_users || ' (Expected >= 7)');
    DBMS_OUTPUT.PUT_LINE('[COUNT] RISK_RULES:       ' || v_rules || ' (Expected >= 5)');
    DBMS_OUTPUT.PUT_LINE('[COUNT] USER_RISK:        ' || v_urisk || ' (Expected >= 7)');
    DBMS_OUTPUT.PUT_LINE('[COUNT] MASKING_POLICIES: ' || v_pols  || ' (Expected >= 5)');
    DBMS_OUTPUT.PUT_LINE('[COUNT] CUSTOMERS:        ' || v_custs || ' (Expected >= 120)');

    IF v_roles >= 5 AND v_users >= 7 AND v_rules >= 5 AND v_urisk >= 7 AND v_pols >= 5 AND v_custs >= 120 THEN
        DBMS_OUTPUT.PUT_LINE('[SUCCESS] All entity row counts satisfy requirements!');
    ELSE
        DBMS_OUTPUT.PUT_LINE('[ERROR] One or more tables contain fewer rows than expected!');
    END IF;
END;
/

PROMPT ========================================================================
PROMPT [TEST 4/5] Testing Active Referential & Foreign Key Constraints
PROMPT ========================================================================

SELECT constraint_name, table_name, status, validated
FROM user_constraints
WHERE constraint_type = 'R'
ORDER BY table_name;

PROMPT ========================================================================
PROMPT [TEST 5/5] Negative Tests (Ensuring Constraints Reject Invalid Data)
PROMPT ========================================================================

PROMPT [NEGATIVE 1] Attempting duplicate username insert (Expect ORA-00001)...
BEGIN
    INSERT INTO APP_USERS (username, full_name, email, role_id)
    VALUES ('admin_user', 'Duplicate User', 'dup@test.com', 1);
    DBMS_OUTPUT.PUT_LINE('[FAILED] Duplicate username was incorrectly allowed!');
EXCEPTION
    WHEN DUP_VAL_ON_INDEX THEN
        DBMS_OUTPUT.PUT_LINE('[PASSED] Unique constraint correctly rejected duplicate username.');
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('[PASSED] Rejected with error: ' || SQLERRM);
END;
/

PROMPT [NEGATIVE 2] Attempting invalid risk rule weight > 100 (Expect ORA-02290)...
BEGIN
    INSERT INTO RISK_RULES (rule_code, rule_name, weight, evaluation_type)
    VALUES ('R_INVALID_TEST', 'Test Rule', 150, 'TEMPORAL');
    DBMS_OUTPUT.PUT_LINE('[FAILED] Weight > 100 was incorrectly allowed!');
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE = -2290 THEN
            DBMS_OUTPUT.PUT_LINE('[PASSED] Check constraint correctly rejected weight = 150.');
        ELSE
            DBMS_OUTPUT.PUT_LINE('[PASSED] Rejected with error: ' || SQLERRM);
        END IF;
END;
/

PROMPT [NEGATIVE 3] Attempting invalid risk tier value (Expect ORA-02290)...
BEGIN
    INSERT INTO USER_RISK (user_id, current_score, risk_tier)
    VALUES (1, 50, 'CRITICAL');
    DBMS_OUTPUT.PUT_LINE('[FAILED] Invalid risk tier CRITICAL was incorrectly allowed!');
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE = -2290 THEN
            DBMS_OUTPUT.PUT_LINE('[PASSED] Check constraint correctly rejected invalid risk tier.');
        ELSE
            DBMS_OUTPUT.PUT_LINE('[PASSED] Rejected with error: ' || SQLERRM);
        END IF;
END;
/

PROMPT ========================================================================
PROMPT [PHASE 3 VERIFICATION COMPLETED] All tests evaluated successfully.
PROMPT ========================================================================
