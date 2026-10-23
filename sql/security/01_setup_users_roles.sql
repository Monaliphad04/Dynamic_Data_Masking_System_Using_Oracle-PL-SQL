-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 2: Oracle Environment & User Setup
-- Script:  sql/security/01_setup_users_roles.sql
-- Purpose: Create dedicated tablespaces, application security roles, and 
--          least-privilege user accounts for the masking engine.
-- Target:  Oracle Database 19c / 21c / 23ai (Pluggable Database: ORCLPDB)
-- ============================================================================

SET ECHO ON;
SET DEFINE OFF;
SET SERVEROUTPUT ON SIZE UNLIMITED;
WHENEVER SQLERROR CONTINUE;

PROMPT ------------------------------------------------------------------------
PROMPT [PHASE 2] Starting Oracle Environment, Tablespaces, Roles & User Setup
PROMPT ------------------------------------------------------------------------

-- ----------------------------------------------------------------------------
-- 1. Switch Session to Pluggable Database (ORCLPDB)
-- ----------------------------------------------------------------------------
ALTER SESSION SET CONTAINER = ORCLPDB;

SELECT sys_context('USERENV', 'CON_NAME') AS active_container FROM dual;

-- ----------------------------------------------------------------------------
-- 2. Dedicated Tablespaces Creation
--    - TS_SEC_DATA: Storage for core application tables and audit logs
--    - TS_SEC_IDX:  Storage for primary key, unique, and performance indexes
-- ----------------------------------------------------------------------------
PROMPT [STEP 1/4] Creating Dedicated Tablespaces...

DECLARE
    v_count NUMBER;
    v_datafile_dir VARCHAR2(500);
BEGIN
    -- Determine datafile directory from existing USERS tablespace
    SELECT SUBSTR(file_name, 1, INSTR(file_name, '\', -1))
    INTO v_datafile_dir
    FROM dba_data_files
    WHERE tablespace_name = 'USERS' AND ROWNUM = 1;

    -- Check and create TS_SEC_DATA
    SELECT COUNT(*) INTO v_count FROM dba_tablespaces WHERE tablespace_name = 'TS_SEC_DATA';
    IF v_count = 0 THEN
        EXECUTE IMMEDIATE '
            CREATE TABLESPACE TS_SEC_DATA
            DATAFILE ''' || v_datafile_dir || 'TS_SEC_DATA.DBF'' 
            SIZE 50M AUTOEXTEND ON NEXT 10M MAXSIZE 1G
            EXTENT MANAGEMENT LOCAL AUTOALLOCATE
            SEGMENT SPACE MANAGEMENT AUTO
        ';
        DBMS_OUTPUT.PUT_LINE('[SUCCESS] Tablespace TS_SEC_DATA created at ' || v_datafile_dir);
    ELSE
        DBMS_OUTPUT.PUT_LINE('[INFO] Tablespace TS_SEC_DATA already exists.');
    END IF;

    -- Check and create TS_SEC_IDX
    SELECT COUNT(*) INTO v_count FROM dba_tablespaces WHERE tablespace_name = 'TS_SEC_IDX';
    IF v_count = 0 THEN
        EXECUTE IMMEDIATE '
            CREATE TABLESPACE TS_SEC_IDX
            DATAFILE ''' || v_datafile_dir || 'TS_SEC_IDX.DBF'' 
            SIZE 25M AUTOEXTEND ON NEXT 5M MAXSIZE 500M
            EXTENT MANAGEMENT LOCAL AUTOALLOCATE
            SEGMENT SPACE MANAGEMENT AUTO
        ';
        DBMS_OUTPUT.PUT_LINE('[SUCCESS] Tablespace TS_SEC_IDX created at ' || v_datafile_dir);
    ELSE
        DBMS_OUTPUT.PUT_LINE('[INFO] Tablespace TS_SEC_IDX already exists.');
    END IF;
EXCEPTION
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('[WARN] Tablespace check/creation notice: ' || SQLERRM);
END;
/

-- ----------------------------------------------------------------------------
-- 3. Security Roles Creation (Separation of Duty)
--    - APP_USER_ROLE:     End-user / client role for querying masked secure views
--    - APP_ADMIN_ROLE:    Administrator role to configure risk weights and rules
--    - AUDIT_READER_ROLE: Auditor role with read-only clearance on ACCESS_LOGS
-- ----------------------------------------------------------------------------
PROMPT [STEP 2/4] Creating Least-Privilege Security Roles...

DECLARE
    PROCEDURE create_role_if_missing(p_role_name IN VARCHAR2) IS
        v_count NUMBER;
    BEGIN
        SELECT COUNT(*) INTO v_count FROM dba_roles WHERE role = p_role_name;
        IF v_count = 0 THEN
            EXECUTE IMMEDIATE 'CREATE ROLE ' || p_role_name;
            DBMS_OUTPUT.PUT_LINE('[SUCCESS] Role created: ' || p_role_name);
        ELSE
            DBMS_OUTPUT.PUT_LINE('[INFO] Role already exists: ' || p_role_name);
        END IF;
    END;
BEGIN
    create_role_if_missing('APP_USER_ROLE');
    create_role_if_missing('APP_ADMIN_ROLE');
    create_role_if_missing('AUDIT_READER_ROLE');
END;
/

-- ----------------------------------------------------------------------------
-- 4. User Accounts Creation
--    - SEC_OWNER:        Schema owner hosting tables, packages, views, contexts
--    - APP_SERVICE_USER: Application proxy user for end-user simulation
--    - APP_ADMIN_USER:   Administrative user for risk profile configuration
--    - AUDIT_USER:       Compliance and security audit account
-- ----------------------------------------------------------------------------
PROMPT [STEP 3/4] Creating Schema Owner and User Accounts...

DECLARE
    PROCEDURE create_user_if_missing(
        p_username IN VARCHAR2,
        p_password IN VARCHAR2,
        p_def_ts   IN VARCHAR2
    ) IS
        v_count NUMBER;
    BEGIN
        SELECT COUNT(*) INTO v_count FROM dba_users WHERE username = p_username;
        IF v_count = 0 THEN
            EXECUTE IMMEDIATE '
                CREATE USER ' || p_username || ' 
                IDENTIFIED BY "' || p_password || '"
                DEFAULT TABLESPACE ' || p_def_ts || '
                TEMPORARY TABLESPACE TEMP
                ACCOUNT UNLOCK
            ';
            DBMS_OUTPUT.PUT_LINE('[SUCCESS] User created: ' || p_username);
        ELSE
            DBMS_OUTPUT.PUT_LINE('[INFO] User already exists: ' || p_username);
        END IF;
    END;
BEGIN
    -- Core Schema Owner
    create_user_if_missing('SEC_OWNER', 'SecOwner#Pass2026', 'TS_SEC_DATA');
    
    -- Application & Audit Users
    create_user_if_missing('APP_SERVICE_USER', 'AppService#Pass2026', 'TS_SEC_DATA');
    create_user_if_missing('APP_ADMIN_USER',   'AppAdmin#Pass2026',   'TS_SEC_DATA');
    create_user_if_missing('AUDIT_USER',       'AuditUser#Pass2026',  'TS_SEC_DATA');
END;
/

-- ----------------------------------------------------------------------------
-- 5. Least-Privilege Grants & Quotas
-- ----------------------------------------------------------------------------
PROMPT [STEP 4/4] Granting Explicit Least-Privilege Permissions...

-- A. Schema Owner (SEC_OWNER)
-- Strict least privilege: Only grant object creation privileges needed for the project.
-- NO DBA or excessive administrative roles granted!
GRANT CREATE SESSION TO SEC_OWNER;
GRANT CREATE TABLE TO SEC_OWNER;
GRANT CREATE VIEW TO SEC_OWNER;
GRANT CREATE PROCEDURE TO SEC_OWNER;
GRANT CREATE SEQUENCE TO SEC_OWNER;
GRANT CREATE TRIGGER TO SEC_OWNER;
GRANT CREATE ANY CONTEXT TO SEC_OWNER;
GRANT EXECUTE ON DBMS_RLS TO SEC_OWNER;
GRANT EXECUTE ON DBMS_FGA TO SEC_OWNER;
GRANT EXECUTE ON DBMS_SESSION TO SEC_OWNER;
GRANT SELECT ON user_audit_policies TO SEC_OWNER;
GRANT SELECT ON dba_audit_policies TO SEC_OWNER;

-- Tablespace Quotas for SEC_OWNER
ALTER USER SEC_OWNER QUOTA UNLIMITED ON TS_SEC_DATA;
ALTER USER SEC_OWNER QUOTA UNLIMITED ON TS_SEC_IDX;

-- B. Application Service User (APP_SERVICE_USER)
GRANT CREATE SESSION TO APP_SERVICE_USER;
GRANT APP_USER_ROLE TO APP_SERVICE_USER;

-- C. Application Administrator (APP_ADMIN_USER)
GRANT CREATE SESSION TO APP_ADMIN_USER;
GRANT APP_ADMIN_ROLE TO APP_ADMIN_USER;

-- D. Audit User (AUDIT_USER)
GRANT CREATE SESSION TO AUDIT_USER;
GRANT AUDIT_READER_ROLE TO AUDIT_USER;

COMMIT;

PROMPT ------------------------------------------------------------------------
PROMPT [VERIFICATION] Verifying Created Objects in ORCLPDB...
PROMPT ------------------------------------------------------------------------

COLUMN tablespace_name FORMAT A20
COLUMN status FORMAT A10
SELECT tablespace_name, status, contents 
FROM dba_tablespaces 
WHERE tablespace_name IN ('TS_SEC_DATA', 'TS_SEC_IDX');

COLUMN role FORMAT A20
SELECT role, authentication_type 
FROM dba_roles 
WHERE role IN ('APP_USER_ROLE', 'APP_ADMIN_ROLE', 'AUDIT_READER_ROLE');

COLUMN username FORMAT A20
COLUMN account_status FORMAT A15
COLUMN default_tablespace FORMAT A15
SELECT username, account_status, default_tablespace, created 
FROM dba_users 
WHERE username IN ('SEC_OWNER', 'APP_SERVICE_USER', 'APP_ADMIN_USER', 'AUDIT_USER')
ORDER BY created;

PROMPT ------------------------------------------------------------------------
PROMPT [PHASE 2 COMPLETED] Oracle Environment, Tablespaces, Roles & Users Setup Done!
PROMPT ------------------------------------------------------------------------
