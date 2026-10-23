-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 3: Schema Creation & Synthetic Data Population
-- Script:  sql/schema/01_create_tables.sql
-- Target:  Oracle Database (ORCLPDB) - Schema: SEC_OWNER
-- Purpose: Create relational tables, primary/foreign key constraints, check
--          constraints, and performance indexes for the masking engine.
-- ============================================================================

SET ECHO ON;
SET DEFINE OFF;
SET SERVEROUTPUT ON SIZE UNLIMITED;
WHENEVER SQLERROR CONTINUE;

PROMPT ------------------------------------------------------------------------
PROMPT [PHASE 3: PART 1] Connecting as SEC_OWNER to create schema tables
PROMPT ------------------------------------------------------------------------

CONNECT SEC_OWNER/SecOwner#Pass2026@localhost:1521/orclpdb

SELECT USER, sys_context('USERENV', 'CON_NAME') AS con_name FROM dual;

-- ----------------------------------------------------------------------------
-- 1. Clean Re-runnable Teardown (Drops child tables before parents)
-- ----------------------------------------------------------------------------
PROMPT Dropping existing tables if present...

BEGIN
    FOR t IN (
        SELECT table_name FROM user_tables 
        WHERE table_name IN (
            'ACCESS_LOGS', 'USER_RISK', 'APP_USERS', 'USER_ROLES',
            'CUSTOMERS', 'RISK_RULES', 'MASKING_POLICIES'
        )
    ) LOOP
        EXECUTE IMMEDIATE 'DROP TABLE ' || t.table_name || ' CASCADE CONSTRAINTS PURGE';
        DBMS_OUTPUT.PUT_LINE('[INFO] Dropped table ' || t.table_name);
    END LOOP;
END;
/

-- ----------------------------------------------------------------------------
-- 2. Table: USER_ROLES
--    Defines functional application roles and their risk ceiling
-- ----------------------------------------------------------------------------
PROMPT Creating Table: USER_ROLES...

CREATE TABLE USER_ROLES (
    role_id             NUMBER GENERATED ALWAYS AS IDENTITY
                        CONSTRAINT pk_user_roles PRIMARY KEY
                        USING INDEX TABLESPACE TS_SEC_IDX,
    role_name           VARCHAR2(50) NOT NULL
                        CONSTRAINT uq_user_roles_name UNIQUE
                        USING INDEX TABLESPACE TS_SEC_IDX,
    description         VARCHAR2(255),
    max_permitted_risk  NUMBER(3) DEFAULT 70 NOT NULL,
    created_at          TIMESTAMP DEFAULT SYSTIMESTAMP NOT NULL,
    CONSTRAINT ck_role_max_risk CHECK (max_permitted_risk BETWEEN 1 AND 100)
) TABLESPACE TS_SEC_DATA;

-- ----------------------------------------------------------------------------
-- 3. Table: APP_USERS
--    Stores enterprise application identities, credentials context, and profiles
-- ----------------------------------------------------------------------------
PROMPT Creating Table: APP_USERS...

CREATE TABLE APP_USERS (
    user_id             NUMBER GENERATED ALWAYS AS IDENTITY
                        CONSTRAINT pk_app_users PRIMARY KEY
                        USING INDEX TABLESPACE TS_SEC_IDX,
    username            VARCHAR2(50) NOT NULL
                        CONSTRAINT uq_app_users_username UNIQUE
                        USING INDEX TABLESPACE TS_SEC_IDX,
    full_name           VARCHAR2(100) NOT NULL,
    email               VARCHAR2(100) NOT NULL
                        CONSTRAINT uq_app_users_email UNIQUE
                        USING INDEX TABLESPACE TS_SEC_IDX,
    role_id             NUMBER NOT NULL,
    account_status      VARCHAR2(20) DEFAULT 'ACTIVE' NOT NULL,
    trusted_ip_subnet   VARCHAR2(50) DEFAULT '192.168.1.%',
    branch_code         VARCHAR2(10) DEFAULT 'BR_NYC_01' NOT NULL,
    work_hour_start     NUMBER(2) DEFAULT 9 NOT NULL,
    work_hour_end       NUMBER(2) DEFAULT 18 NOT NULL,
    created_at          TIMESTAMP DEFAULT SYSTIMESTAMP NOT NULL,
    CONSTRAINT fk_app_users_role FOREIGN KEY (role_id) 
        REFERENCES USER_ROLES(role_id),
    CONSTRAINT ck_app_user_status CHECK (account_status IN ('ACTIVE', 'LOCKED', 'SUSPENDED')),
    CONSTRAINT ck_app_user_hours CHECK (work_hour_start BETWEEN 0 AND 23 AND work_hour_end BETWEEN 0 AND 23)
) TABLESPACE TS_SEC_DATA;

CREATE INDEX idx_app_users_role ON APP_USERS(role_id) TABLESPACE TS_SEC_IDX;

-- ----------------------------------------------------------------------------
-- 4. Table: CUSTOMERS
--    Core domain table holding sensitive customer PII and financials.
--    Storage is always clean; masking is strictly projected at runtime.
-- ----------------------------------------------------------------------------
PROMPT Creating Table: CUSTOMERS...

CREATE TABLE CUSTOMERS (
    customer_id         NUMBER GENERATED ALWAYS AS IDENTITY
                        CONSTRAINT pk_customers PRIMARY KEY
                        USING INDEX TABLESPACE TS_SEC_IDX,
    first_name          VARCHAR2(50) NOT NULL,
    last_name           VARCHAR2(50) NOT NULL,
    email               VARCHAR2(100) NOT NULL,
    phone_number        VARCHAR2(25) NOT NULL,
    national_id         VARCHAR2(20) NOT NULL,
    credit_card_num     VARCHAR2(25),
    account_balance     NUMBER(12, 2) DEFAULT 0.00 NOT NULL,
    risk_classification VARCHAR2(20) DEFAULT 'STANDARD' NOT NULL,
    branch_code         VARCHAR2(10) NOT NULL,
    created_date        DATE DEFAULT SYSDATE NOT NULL,
    CONSTRAINT ck_cust_risk_class CHECK (risk_classification IN ('STANDARD', 'VIP', 'HIGH_NET_WORTH', 'WATCHLIST'))
) TABLESPACE TS_SEC_DATA;

CREATE INDEX idx_customers_branch ON CUSTOMERS(branch_code) TABLESPACE TS_SEC_IDX;
CREATE INDEX idx_customers_email ON CUSTOMERS(email) TABLESPACE TS_SEC_IDX;

-- ----------------------------------------------------------------------------
-- 5. Table: RISK_RULES
--    Catalog of real-time threat signals, evaluation types, and weights
-- ----------------------------------------------------------------------------
PROMPT Creating Table: RISK_RULES...

CREATE TABLE RISK_RULES (
    rule_id             NUMBER GENERATED ALWAYS AS IDENTITY
                        CONSTRAINT pk_risk_rules PRIMARY KEY
                        USING INDEX TABLESPACE TS_SEC_IDX,
    rule_code           VARCHAR2(30) NOT NULL
                        CONSTRAINT uq_risk_rules_code UNIQUE
                        USING INDEX TABLESPACE TS_SEC_IDX,
    rule_name           VARCHAR2(100) NOT NULL,
    weight              NUMBER(3) NOT NULL,
    evaluation_type     VARCHAR2(20) NOT NULL,
    is_active           VARCHAR2(1) DEFAULT 'Y' NOT NULL,
    description         VARCHAR2(255),
    created_at          TIMESTAMP DEFAULT SYSTIMESTAMP NOT NULL,
    CONSTRAINT ck_rule_weight CHECK (weight BETWEEN 0 AND 100),
    CONSTRAINT ck_rule_active CHECK (is_active IN ('Y', 'N')),
    CONSTRAINT ck_rule_eval_type CHECK (evaluation_type IN ('TEMPORAL', 'NETWORK', 'VELOCITY', 'SECURITY', 'VOLUME'))
) TABLESPACE TS_SEC_DATA;

-- ----------------------------------------------------------------------------
-- 6. Table: USER_RISK
--    Dynamic behavioral telemetry & risk score tracking per application user
-- ----------------------------------------------------------------------------
PROMPT Creating Table: USER_RISK...

CREATE TABLE USER_RISK (
    risk_profile_id             NUMBER GENERATED ALWAYS AS IDENTITY
                                CONSTRAINT pk_user_risk PRIMARY KEY
                                USING INDEX TABLESPACE TS_SEC_IDX,
    user_id                     NUMBER NOT NULL
                                CONSTRAINT uq_user_risk_user UNIQUE
                                USING INDEX TABLESPACE TS_SEC_IDX,
    current_score               NUMBER(3) DEFAULT 0 NOT NULL,
    risk_tier                   VARCHAR2(10) DEFAULT 'LOW' NOT NULL,
    failed_logins_24h           NUMBER(5) DEFAULT 0 NOT NULL,
    query_count_current_window  NUMBER(7) DEFAULT 0 NOT NULL,
    last_evaluated              TIMESTAMP DEFAULT SYSTIMESTAMP NOT NULL,
    score_override              NUMBER(3),
    CONSTRAINT fk_user_risk_user FOREIGN KEY (user_id)
        REFERENCES APP_USERS(user_id) ON DELETE CASCADE,
    CONSTRAINT ck_user_risk_score CHECK (current_score BETWEEN 0 AND 100),
    CONSTRAINT ck_user_risk_tier CHECK (risk_tier IN ('LOW', 'MEDIUM', 'HIGH')),
    CONSTRAINT ck_user_risk_override CHECK (score_override IS NULL OR score_override BETWEEN 0 AND 100)
) TABLESPACE TS_SEC_DATA;

-- ----------------------------------------------------------------------------
-- 7. Table: ACCESS_LOGS
--    Immutable forensic audit repository written via autonomous transactions
-- ----------------------------------------------------------------------------
PROMPT Creating Table: ACCESS_LOGS...

CREATE TABLE ACCESS_LOGS (
    log_id              NUMBER GENERATED ALWAYS AS IDENTITY
                        CONSTRAINT pk_access_logs PRIMARY KEY
                        USING INDEX TABLESPACE TS_SEC_IDX,
    session_user        VARCHAR2(50) NOT NULL,
    app_username        VARCHAR2(50) NOT NULL,
    client_ip           VARCHAR2(50),
    action_type         VARCHAR2(20) NOT NULL,
    target_object       VARCHAR2(100) NOT NULL,
    records_accessed    NUMBER(8) DEFAULT 0 NOT NULL,
    calculated_risk     NUMBER(3) NOT NULL,
    applied_tier        VARCHAR2(10) NOT NULL,
    triggered_rules     VARCHAR2(255),
    access_time         TIMESTAMP DEFAULT SYSTIMESTAMP NOT NULL,
    CONSTRAINT ck_access_logs_tier CHECK (applied_tier IN ('LOW', 'MEDIUM', 'HIGH'))
) TABLESPACE TS_SEC_DATA;

CREATE INDEX idx_access_logs_time ON ACCESS_LOGS(access_time) TABLESPACE TS_SEC_IDX;
CREATE INDEX idx_access_logs_user ON ACCESS_LOGS(app_username, access_time) TABLESPACE TS_SEC_IDX;

-- ----------------------------------------------------------------------------
-- 8. Table: MASKING_POLICIES
--    Declarative column-level masking rules by risk tier
-- ----------------------------------------------------------------------------
PROMPT Creating Table: MASKING_POLICIES...

CREATE TABLE MASKING_POLICIES (
    policy_id             NUMBER GENERATED ALWAYS AS IDENTITY
                          CONSTRAINT pk_masking_policies PRIMARY KEY
                          USING INDEX TABLESPACE TS_SEC_IDX,
    table_name            VARCHAR2(50) DEFAULT 'CUSTOMERS' NOT NULL,
    column_name           VARCHAR2(50) NOT NULL
                          CONSTRAINT uq_masking_col UNIQUE
                          USING INDEX TABLESPACE TS_SEC_IDX,
    low_risk_strategy     VARCHAR2(30) DEFAULT 'CLEARTEXT' NOT NULL,
    medium_risk_strategy  VARCHAR2(30) DEFAULT 'PARTIAL_MASK' NOT NULL,
    high_risk_strategy    VARCHAR2(30) DEFAULT 'FULL_REDACT' NOT NULL,
    created_at            TIMESTAMP DEFAULT SYSTIMESTAMP NOT NULL
) TABLESPACE TS_SEC_DATA;

COMMIT;

PROMPT ------------------------------------------------------------------------
PROMPT [TABLE VERIFICATION] Validating table structures in SEC_OWNER...
PROMPT ------------------------------------------------------------------------

COLUMN table_name FORMAT A20
COLUMN tablespace_name FORMAT A15
COLUMN num_rows FORMAT 999,999
SELECT table_name, tablespace_name, status 
FROM user_tables 
ORDER BY table_name;

COLUMN constraint_name FORMAT A25
COLUMN constraint_type FORMAT A5
COLUMN table_name FORMAT A18
COLUMN status FORMAT A10
SELECT constraint_name, constraint_type, table_name, status
FROM user_constraints
WHERE constraint_type IN ('P', 'R', 'U')
ORDER BY table_name, constraint_type;

PROMPT ------------------------------------------------------------------------
PROMPT [SUCCESS] All 7 Schema Tables Created with Constraints and Indexes!
PROMPT ------------------------------------------------------------------------
