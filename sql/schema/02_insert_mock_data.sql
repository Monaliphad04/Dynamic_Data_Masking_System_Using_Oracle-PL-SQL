-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 3: Schema Creation & Synthetic Data Population
-- Script:  sql/schema/02_insert_mock_data.sql
-- Target:  Oracle Database (ORCLPDB) - Schema: SEC_OWNER
-- Purpose: Insert baseline configuration and realistic synthetic mock data
--          for roles, users, risk rules, policies, and 120+ fictional customers.
-- ============================================================================

SET ECHO ON;
SET DEFINE OFF;
SET SERVEROUTPUT ON SIZE UNLIMITED;
WHENEVER SQLERROR CONTINUE;

PROMPT ------------------------------------------------------------------------
PROMPT [PHASE 3: PART 2] Connecting as SEC_OWNER to insert synthetic seed data
PROMPT ------------------------------------------------------------------------

CONNECT SEC_OWNER/SecOwner#Pass2026@localhost:1521/orclpdb

-- ----------------------------------------------------------------------------
-- 1. Seed Table: USER_ROLES
-- ----------------------------------------------------------------------------
PROMPT Seeding USER_ROLES...

DELETE FROM USER_ROLES;

INSERT INTO USER_ROLES (role_name, description, max_permitted_risk)
VALUES ('SEC_ADMIN', 'Database Security Administrator with unrestricted policy management', 100);

INSERT INTO USER_ROLES (role_name, description, max_permitted_risk)
VALUES ('COMPLIANCE_OFFICER', 'Senior Compliance Officer auditing sensitive PII flows', 90);

INSERT INTO USER_ROLES (role_name, description, max_permitted_risk)
VALUES ('AUDITOR', 'Internal and external regulatory audit staff', 80);

INSERT INTO USER_ROLES (role_name, description, max_permitted_risk)
VALUES ('CUSTOMER_CARE', 'Frontline support agents handling verified customer inquiries', 60);

INSERT INTO USER_ROLES (role_name, description, max_permitted_risk)
VALUES ('ANALYST', 'Business and risk intelligence reporting analysts', 50);

COMMIT;

-- ----------------------------------------------------------------------------
-- 2. Seed Table: APP_USERS
-- ----------------------------------------------------------------------------
PROMPT Seeding APP_USERS...

DELETE FROM APP_USERS;

DECLARE
    v_admin_rid   NUMBER;
    v_comp_rid    NUMBER;
    v_audit_rid   NUMBER;
    v_care_rid    NUMBER;
    v_analyst_rid NUMBER;
BEGIN
    SELECT role_id INTO v_admin_rid   FROM USER_ROLES WHERE role_name = 'SEC_ADMIN';
    SELECT role_id INTO v_comp_rid    FROM USER_ROLES WHERE role_name = 'COMPLIANCE_OFFICER';
    SELECT role_id INTO v_audit_rid   FROM USER_ROLES WHERE role_name = 'AUDITOR';
    SELECT role_id INTO v_care_rid    FROM USER_ROLES WHERE role_name = 'CUSTOMER_CARE';
    SELECT role_id INTO v_analyst_rid FROM USER_ROLES WHERE role_name = 'ANALYST';

    INSERT INTO APP_USERS (username, full_name, email, role_id, account_status, trusted_ip_subnet, branch_code, work_hour_start, work_hour_end)
    VALUES ('admin_user', 'Eleanor Vance', 'eleanor.vance@banksec.internal', v_admin_rid, 'ACTIVE', '192.168.1.%', 'ALL', 8, 20);

    INSERT INTO APP_USERS (username, full_name, email, role_id, account_status, trusted_ip_subnet, branch_code, work_hour_start, work_hour_end)
    VALUES ('agent_sarah', 'Sarah Jenkins', 'sarah.jenkins@banksec.internal', v_care_rid, 'ACTIVE', '192.168.1.%', 'BR_NYC_01', 9, 17);

    INSERT INTO APP_USERS (username, full_name, email, role_id, account_status, trusted_ip_subnet, branch_code, work_hour_start, work_hour_end)
    VALUES ('agent_mike', 'Michael Torres', 'michael.torres@banksec.internal', v_care_rid, 'ACTIVE', '192.168.1.%', 'BR_LDN_02', 9, 17);

    INSERT INTO APP_USERS (username, full_name, email, role_id, account_status, trusted_ip_subnet, branch_code, work_hour_start, work_hour_end)
    VALUES ('analyst_bob', 'Robert Chen', 'robert.chen@banksec.internal', v_analyst_rid, 'ACTIVE', '10.0.1.%', 'BR_SGP_03', 8, 19);

    INSERT INTO APP_USERS (username, full_name, email, role_id, account_status, trusted_ip_subnet, branch_code, work_hour_start, work_hour_end)
    VALUES ('auditor_carol', 'Carol Danvers', 'carol.danvers@banksec.internal', v_audit_rid, 'ACTIVE', '192.168.1.%', 'ALL', 9, 18);

    INSERT INTO APP_USERS (username, full_name, email, role_id, account_status, trusted_ip_subnet, branch_code, work_hour_start, work_hour_end)
    VALUES ('external_guest', 'Guest Contractor', 'contractor@thirdparty.org', v_care_rid, 'ACTIVE', '172.16.%.%', 'BR_MUM_04', 10, 16);

    INSERT INTO APP_USERS (username, full_name, email, role_id, account_status, trusted_ip_subnet, branch_code, work_hour_start, work_hour_end)
    VALUES ('locked_user', 'Marcus Aurelius', 'm.aurelius@banksec.internal', v_care_rid, 'LOCKED', '192.168.1.%', 'BR_NYC_01', 9, 17);
    
    COMMIT;
END;
/

-- ----------------------------------------------------------------------------
-- 3. Seed Table: RISK_RULES
-- ----------------------------------------------------------------------------
PROMPT Seeding RISK_RULES...

DELETE FROM RISK_RULES;

INSERT INTO RISK_RULES (rule_code, rule_name, weight, evaluation_type, is_active, description)
VALUES ('R_OFF_HOURS', 'Off-Hours Temporal Access', 35, 'TEMPORAL', 'Y', 
        'Triggers when request timestamp falls outside users assigned work hours or occurs on weekends');

INSERT INTO RISK_RULES (rule_code, rule_name, weight, evaluation_type, is_active, description)
VALUES ('R_UNTRUSTED_IP', 'Untrusted Network Origin', 40, 'NETWORK', 'Y', 
        'Triggers when client IP fails to match users pre-approved corporate subnet');

INSERT INTO RISK_RULES (rule_code, rule_name, weight, evaluation_type, is_active, description)
VALUES ('R_BURST_QUERY', 'High Velocity Query Burst', 35, 'VELOCITY', 'Y', 
        'Triggers when query count exceeds 50 reads in rolling 5-minute sliding window');

INSERT INTO RISK_RULES (rule_code, rule_name, weight, evaluation_type, is_active, description)
VALUES ('R_FAILED_AUTH', 'Authentication Anomaly History', 20, 'SECURITY', 'Y', 
        'Triggers when more than 3 failed login attempts are logged for identity within past 24 hours');

INSERT INTO RISK_RULES (rule_code, rule_name, weight, evaluation_type, is_active, description)
VALUES ('R_BULK_FETCH', 'High Volume Record Scan', 25, 'VOLUME', 'Y', 
        'Triggers when client query scans or requests pagination beyond 500 records');

COMMIT;

-- ----------------------------------------------------------------------------
-- 4. Seed Table: USER_RISK
-- ----------------------------------------------------------------------------
PROMPT Seeding USER_RISK Initial Profiles...

DELETE FROM USER_RISK;

DECLARE
    v_uid NUMBER;
BEGIN
    -- 1. admin_user (Baseline Low Risk)
    SELECT user_id INTO v_uid FROM APP_USERS WHERE username = 'admin_user';
    INSERT INTO USER_RISK (user_id, current_score, risk_tier, failed_logins_24h, query_count_current_window)
    VALUES (v_uid, 5, 'LOW', 0, 4);

    -- 2. agent_sarah (Baseline Low Risk)
    SELECT user_id INTO v_uid FROM APP_USERS WHERE username = 'agent_sarah';
    INSERT INTO USER_RISK (user_id, current_score, risk_tier, failed_logins_24h, query_count_current_window)
    VALUES (v_uid, 10, 'LOW', 0, 12);

    -- 3. agent_mike (Baseline Low Risk)
    SELECT user_id INTO v_uid FROM APP_USERS WHERE username = 'agent_mike';
    INSERT INTO USER_RISK (user_id, current_score, risk_tier, failed_logins_24h, query_count_current_window)
    VALUES (v_uid, 15, 'LOW', 1, 8);

    -- 4. analyst_bob (Medium Risk due to moderate query velocity)
    SELECT user_id INTO v_uid FROM APP_USERS WHERE username = 'analyst_bob';
    INSERT INTO USER_RISK (user_id, current_score, risk_tier, failed_logins_24h, query_count_current_window)
    VALUES (v_uid, 35, 'MEDIUM', 0, 38);

    -- 5. auditor_carol (Baseline Low Risk)
    SELECT user_id INTO v_uid FROM APP_USERS WHERE username = 'auditor_carol';
    INSERT INTO USER_RISK (user_id, current_score, risk_tier, failed_logins_24h, query_count_current_window)
    VALUES (v_uid, 0, 'LOW', 0, 2);

    -- 6. external_guest (Medium Risk due to network domain)
    SELECT user_id INTO v_uid FROM APP_USERS WHERE username = 'external_guest';
    INSERT INTO USER_RISK (user_id, current_score, risk_tier, failed_logins_24h, query_count_current_window)
    VALUES (v_uid, 45, 'MEDIUM', 2, 19);

    -- 7. locked_user (High Risk / Locked)
    SELECT user_id INTO v_uid FROM APP_USERS WHERE username = 'locked_user';
    INSERT INTO USER_RISK (user_id, current_score, risk_tier, failed_logins_24h, query_count_current_window)
    VALUES (v_uid, 85, 'HIGH', 6, 0);

    COMMIT;
END;
/

-- ----------------------------------------------------------------------------
-- 5. Seed Table: MASKING_POLICIES
-- ----------------------------------------------------------------------------
PROMPT Seeding MASKING_POLICIES...

DELETE FROM MASKING_POLICIES;

INSERT INTO MASKING_POLICIES (table_name, column_name, low_risk_strategy, medium_risk_strategy, high_risk_strategy)
VALUES ('CUSTOMERS', 'PHONE_NUMBER', 'CLEARTEXT', 'PARTIAL_MASK', 'FULL_REDACT');

INSERT INTO MASKING_POLICIES (table_name, column_name, low_risk_strategy, medium_risk_strategy, high_risk_strategy)
VALUES ('CUSTOMERS', 'EMAIL', 'CLEARTEXT', 'PARTIAL_MASK', 'FULL_REDACT');

INSERT INTO MASKING_POLICIES (table_name, column_name, low_risk_strategy, medium_risk_strategy, high_risk_strategy)
VALUES ('CUSTOMERS', 'NATIONAL_ID', 'CLEARTEXT', 'PARTIAL_MASK', 'FULL_REDACT');

INSERT INTO MASKING_POLICIES (table_name, column_name, low_risk_strategy, medium_risk_strategy, high_risk_strategy)
VALUES ('CUSTOMERS', 'CREDIT_CARD_NUM', 'PCI_LAST4', 'PARTIAL_MASK', 'FULL_REDACT');

INSERT INTO MASKING_POLICIES (table_name, column_name, low_risk_strategy, medium_risk_strategy, high_risk_strategy)
VALUES ('CUSTOMERS', 'ACCOUNT_BALANCE', 'CLEARTEXT', 'ROUNDED_THOUSAND', 'ZERO_REDACT');

COMMIT;

-- ----------------------------------------------------------------------------
-- 6. Seed Table: CUSTOMERS (120 Synthetic Fictional Profiles)
--    Contains zero real PII. High variance in branch, balance, and formats.
-- ----------------------------------------------------------------------------
PROMPT Seeding 120 Synthetic Customer Profiles into CUSTOMERS...

DELETE FROM CUSTOMERS;

DECLARE
    TYPE t_names IS TABLE OF VARCHAR2(50);
    v_first_names t_names := t_names(
        'James', 'Mary', 'John', 'Patricia', 'Robert', 'Jennifer', 'Michael', 'Linda',
        'William', 'Elizabeth', 'David', 'Barbara', 'Richard', 'Susan', 'Joseph', 'Jessica',
        'Thomas', 'Sarah', 'Charles', 'Karen', 'Christopher', 'Nancy', 'Daniel', 'Lisa',
        'Matthew', 'Margaret', 'Anthony', 'Betty', 'Donald', 'Sandra', 'Mark', 'Ashley'
    );
    v_last_names t_names := t_names(
        'Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis',
        'Rodriguez', 'Martinez', 'Hernandez', 'Lopez', 'Gonzalez', 'Wilson', 'Anderson', 'Thomas',
        'Taylor', 'Moore', 'Jackson', 'Martin', 'Lee', 'Perez', 'Thompson', 'White',
        'Harris', 'Sanchez', 'Clark', 'Ramirez', 'Lewis', 'Robinson', 'Walker', 'Young'
    );
    v_branches t_names := t_names('BR_NYC_01', 'BR_LDN_02', 'BR_SGP_03', 'BR_MUM_04', 'BR_TOK_05');
    v_risk_classes t_names := t_names('STANDARD', 'STANDARD', 'STANDARD', 'VIP', 'HIGH_NET_WORTH', 'WATCHLIST');

    v_first      VARCHAR2(50);
    v_last       VARCHAR2(50);
    v_email      VARCHAR2(100);
    v_phone      VARCHAR2(25);
    v_nat_id     VARCHAR2(20);
    v_card       VARCHAR2(25);
    v_balance    NUMBER(12,2);
    v_branch     VARCHAR2(10);
    v_class      VARCHAR2(20);
BEGIN
    FOR i IN 1..120 LOOP
        v_first   := v_first_names(MOD(i * 7, v_first_names.COUNT) + 1);
        v_last    := v_last_names(MOD(i * 11, v_last_names.COUNT) + 1);
        v_email   := LOWER(v_first) || '.' || LOWER(v_last) || LPAD(TO_CHAR(i), 3, '0') || '@fictional-domain.com';
        v_phone   := '+1-555-' || LPAD(TO_CHAR(MOD(i * 137, 900) + 100), 3, '0') || '-' || LPAD(TO_CHAR(MOD(i * 73, 9000) + 1000), 4, '0');
        v_nat_id  := LPAD(TO_CHAR(MOD(i * 41, 900) + 100), 3, '0') || '-' || 
                     LPAD(TO_CHAR(MOD(i * 17, 90) + 10), 2, '0') || '-' || 
                     LPAD(TO_CHAR(MOD(i * 97, 9000) + 1000), 4, '0');
        v_card    := '4' || LPAD(TO_CHAR(MOD(i * 89, 900) + 100), 3, '0') || '-' ||
                     LPAD(TO_CHAR(MOD(i * 233, 9000) + 1000), 4, '0') || '-' ||
                     LPAD(TO_CHAR(MOD(i * 359, 9000) + 1000), 4, '0') || '-' ||
                     LPAD(TO_CHAR(MOD(i * 61, 9000) + 1000), 4, '0');
        v_balance := ROUND(DBMS_RANDOM.VALUE(1200, 185000), 2);
        v_branch  := v_branches(MOD(i, v_branches.COUNT) + 1);
        v_class   := v_risk_classes(MOD(i, v_risk_classes.COUNT) + 1);

        INSERT INTO CUSTOMERS (
            first_name, last_name, email, phone_number, national_id,
            credit_card_num, account_balance, risk_classification, branch_code, created_date
        ) VALUES (
            v_first, v_last, v_email, v_phone, v_nat_id,
            v_card, v_balance, v_class, v_branch, SYSDATE - MOD(i, 365)
        );
    END LOOP;

    COMMIT;
    DBMS_OUTPUT.PUT_LINE('[SUCCESS] Successfully seeded 120 synthetic customer records.');
END;
/

PROMPT ------------------------------------------------------------------------
PROMPT [SYNTHETIC DATA VERIFICATION] Counting rows in SEC_OWNER tables...
PROMPT ------------------------------------------------------------------------

COLUMN table_name FORMAT A25
COLUMN total_records FORMAT 999,999

SELECT 'USER_ROLES' AS table_name, COUNT(*) AS total_records FROM USER_ROLES
UNION ALL
SELECT 'APP_USERS', COUNT(*) FROM APP_USERS
UNION ALL
SELECT 'RISK_RULES', COUNT(*) FROM RISK_RULES
UNION ALL
SELECT 'USER_RISK', COUNT(*) FROM USER_RISK
UNION ALL
SELECT 'MASKING_POLICIES', COUNT(*) FROM MASKING_POLICIES
UNION ALL
SELECT 'CUSTOMERS', COUNT(*) FROM CUSTOMERS
UNION ALL
SELECT 'ACCESS_LOGS', COUNT(*) FROM ACCESS_LOGS;

PROMPT ------------------------------------------------------------------------
PROMPT Sample 5 Customer Rows (Base Data Unmasked in Raw Storage):
PROMPT ------------------------------------------------------------------------

COLUMN customer_id FORMAT 9999
COLUMN full_name FORMAT A20
COLUMN email FORMAT A30
COLUMN phone_number FORMAT A18
COLUMN national_id FORMAT A15
COLUMN account_balance FORMAT $999,999.99
COLUMN branch_code FORMAT A12

SELECT customer_id, 
       first_name || ' ' || last_name AS full_name,
       email, 
       phone_number, 
       national_id, 
       account_balance, 
       branch_code
FROM CUSTOMERS
WHERE ROWNUM <= 5;

PROMPT ------------------------------------------------------------------------
PROMPT [PHASE 3 COMPLETED] Schema & Synthetic Data Population Successfully Executed!
PROMPT ------------------------------------------------------------------------
