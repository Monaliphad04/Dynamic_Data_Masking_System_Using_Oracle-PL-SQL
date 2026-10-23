"""
Database Interface Module for Context-Aware Dynamic Data Masking System.
Connects to Oracle Database 21c (ORCLPDB) using python-oracledb in thin mode.
"""

import os
from typing import Dict, Any, List, Optional
import oracledb

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "1521"))
DB_SERVICE = os.getenv("DB_SERVICE", "orclpdb")

DSN = f"{DB_HOST}:{DB_PORT}/{DB_SERVICE}"

CREDENTIALS = {
    "app": {
        "user": os.getenv("APP_DB_USER", "APP_SERVICE_USER"),
        "password": os.getenv("APP_DB_PASSWORD", "AppService#Pass2026"),
    },
    "audit": {
        "user": os.getenv("AUDIT_DB_USER", "AUDIT_USER"),
        "password": os.getenv("AUDIT_DB_PASSWORD", "AuditUser#Pass2026"),
    },
    "admin": {
        "user": os.getenv("ADMIN_DB_USER", "SEC_OWNER"),
        "password": os.getenv("ADMIN_DB_PASSWORD", "SecOwner#Pass2026"),
    },
}

def get_connection(user_type: str = "app") -> oracledb.Connection:
    """Creates a connection using the requested privilege tier."""
    creds = CREDENTIALS.get(user_type, CREDENTIALS["app"])
    conn = oracledb.connect(
        user=creds["user"],
        password=creds["password"],
        dsn=DSN
    )
    return conn

def init_user_session(
    conn: oracledb.Connection,
    username: str,
    client_ip: Optional[str] = None,
    simulated_hour: Optional[int] = None
) -> Dict[str, Any]:
    """
    Initializes trusted application context in CTX_SEC_MASK and evaluates risk.
    """
    with conn.cursor() as cursor:
        cursor.callproc(
            "SEC_OWNER.PKG_SESSION_CTX.INITIALIZE_SESSION",
            [username, client_ip]
        )
        cursor.callproc(
            "SEC_OWNER.PKG_RISK_ENGINE.EVALUATE_AND_SYNC_SESSION",
            [client_ip, simulated_hour]
        )
    return get_session_context(conn)

def set_manual_risk(
    conn: oracledb.Connection,
    score: int,
    tier: str
) -> Dict[str, Any]:
    """Manually overrides the session risk score and tier."""
    with conn.cursor() as cursor:
        cursor.callproc(
            "SEC_OWNER.PKG_SESSION_CTX.SET_SESSION_RISK",
            [score, tier]
        )
    return get_session_context(conn)

def set_branch_context(
    conn: oracledb.Connection,
    branch_code: str
) -> Dict[str, Any]:
    """Switches branch context for the session."""
    with conn.cursor() as cursor:
        cursor.callproc(
            "SEC_OWNER.PKG_SESSION_CTX.SET_BRANCH_CONTEXT",
            [branch_code]
        )
    return get_session_context(conn)

def get_session_context(conn: oracledb.Connection) -> Dict[str, Any]:
    """Queries CTX_SEC_MASK attributes from the active Oracle session."""
    sql = """
    SELECT 
        SYS_CONTEXT('CTX_SEC_MASK', 'APP_USER')           AS app_user,
        SYS_CONTEXT('CTX_SEC_MASK', 'USER_ID')            AS user_id,
        SYS_CONTEXT('CTX_SEC_MASK', 'ROLE_NAME')          AS role_name,
        SYS_CONTEXT('CTX_SEC_MASK', 'BRANCH_CODE')        AS branch_code,
        SYS_CONTEXT('CTX_SEC_MASK', 'CLIENT_IP')          AS client_ip,
        SYS_CONTEXT('CTX_SEC_MASK', 'TRUSTED_IP_SUBNET')  AS trusted_ip_subnet,
        SYS_CONTEXT('CTX_SEC_MASK', 'WORK_HOUR_START')    AS work_hour_start,
        SYS_CONTEXT('CTX_SEC_MASK', 'WORK_HOUR_END')      AS work_hour_end,
        SYS_CONTEXT('CTX_SEC_MASK', 'RISK_SCORE')         AS risk_score,
        SYS_CONTEXT('CTX_SEC_MASK', 'RISK_TIER')          AS risk_tier,
        SYS_CONTEXT('CTX_SEC_MASK', 'IS_INITIALIZED')     AS is_initialized,
        SYS_CONTEXT('CTX_SEC_MASK', 'STATUS')             AS status
    FROM DUAL
    """
    with conn.cursor() as cursor:
        cursor.execute(sql)
        row = cursor.fetchone()
        cols = [col[0].lower() for col in cursor.description]
        data = dict(zip(cols, row))
        try:
            data["risk_score"] = int(data["risk_score"]) if data["risk_score"] is not None else 100
        except (ValueError, TypeError):
            data["risk_score"] = 100
        return data

def fetch_masked_customers(conn: oracledb.Connection, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Fetches dynamically masked customer records from VW_CUSTOMERS.
    """
    sql = f"""
    SELECT 
        customer_id,
        first_name,
        last_name,
        email,
        phone_number,
        national_id,
        credit_card_num,
        account_balance,
        risk_classification,
        branch_code,
        TO_CHAR(created_date, 'YYYY-MM-DD') AS created_date
    FROM VW_CUSTOMERS
    WHERE ROWNUM <= :lim
    ORDER BY customer_id
    """
    with conn.cursor() as cursor:
        cursor.execute(sql, lim=limit)
        cols = [col[0].lower() for col in cursor.description]
        results = []
        for row in cursor.fetchall():
            results.append(dict(zip(cols, row)))
        return results

def fetch_app_personas() -> List[Dict[str, Any]]:
    """Fetches list of seeded application test users."""
    conn = get_connection("admin")
    try:
        sql = """
        SELECT 
            u.user_id,
            u.username,
            u.full_name,
            u.email,
            r.role_name,
            u.account_status,
            u.trusted_ip_subnet,
            u.branch_code,
            u.work_hour_start,
            u.work_hour_end
        FROM SEC_OWNER.APP_USERS u
        JOIN SEC_OWNER.USER_ROLES r ON u.role_id = r.role_id
        ORDER BY u.user_id
        """
        with conn.cursor() as cursor:
            cursor.execute(sql)
            cols = [col[0].lower() for col in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
    finally:
        conn.close()

def fetch_risk_rules() -> List[Dict[str, Any]]:
    """Fetches defined active risk evaluation rules."""
    conn = get_connection("admin")
    try:
        sql = """
        SELECT rule_id, rule_code, rule_name, weight, evaluation_type, is_active, description
        FROM SEC_OWNER.RISK_RULES
        ORDER BY rule_id
        """
        with conn.cursor() as cursor:
            cursor.execute(sql)
            cols = [col[0].lower() for col in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
    finally:
        conn.close()

def fetch_audit_logs(limit: int = 20) -> List[Dict[str, Any]]:
    """Fetches immutable security audit logs as AUDIT_USER."""
    conn = get_connection("audit")
    try:
        sql = f"""
        SELECT 
            log_id,
            session_user,
            app_username,
            client_ip,
            action_type,
            target_object,
            records_accessed,
            calculated_risk,
            applied_tier,
            triggered_rules,
            TO_CHAR(access_time, 'YYYY-MM-DD HH24:MI:SS') AS access_time
        FROM SEC_OWNER.ACCESS_LOGS
        ORDER BY log_id DESC
        FETCH FIRST :lim ROWS ONLY
        """
        with conn.cursor() as cursor:
            cursor.execute(sql, lim=limit)
            cols = [col[0].lower() for col in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
    finally:
        conn.close()
