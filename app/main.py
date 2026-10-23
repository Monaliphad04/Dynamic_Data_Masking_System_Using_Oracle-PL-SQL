"""
FastAPI Server for Context-Aware Dynamic Data Masking Interactive Dashboard.
Exposes REST endpoints that bridge the UI controls to live Oracle PL/SQL engines.
"""

import os
from pathlib import Path
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

import database

app = FastAPI(
    title="Context-Aware Dynamic Data Masking API",
    description="Real-Time Risk-Adaptive Oracle PL/SQL Security Engine Interface",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Active interactive simulation state
class DemoState:
    username: str = "agent_sarah"
    client_ip: str = "192.168.1.102"
    simulated_hour: Optional[int] = 14  # 2:00 PM (Business Hours)
    manual_risk_score: Optional[int] = None
    manual_risk_tier: Optional[str] = None
    manual_branch: Optional[str] = None
    burst_query_count: int = 1

demo_state = DemoState()

class SessionUpdateRequest(BaseModel):
    username: Optional[str] = None
    client_ip: Optional[str] = None
    simulated_hour: Optional[int] = None
    manual_risk_score: Optional[int] = None
    manual_risk_tier: Optional[str] = None
    manual_branch: Optional[str] = None

@app.get("/api/health")
def check_health():
    """Verifies Oracle DB connection."""
    try:
        conn = database.get_connection("app")
        version = conn.version
        conn.close()
        return {"status": "HEALTHY", "database": "Oracle 21c Enterprise Edition", "version": version}
    except Exception as e:
        return {"status": "UNHEALTHY", "error": str(e)}

@app.get("/api/personas")
def get_personas():
    """Returns all seeded database test personas."""
    try:
        return database.fetch_app_personas()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/rules")
def get_risk_rules():
    """Returns active risk evaluation rules."""
    try:
        return database.fetch_risk_rules()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audit")
def get_audit_trail(limit: int = 25):
    """Fetches real-time non-repudiable audit logs."""
    try:
        return database.fetch_audit_logs(limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/session")
def get_current_session():
    """Initializes and returns current session security state from Oracle."""
    conn = database.get_connection("app")
    try:
        database.init_user_session(
            conn=conn,
            username=demo_state.username,
            client_ip=demo_state.client_ip,
            simulated_hour=demo_state.simulated_hour
        )

        if demo_state.manual_risk_score is not None:
            database.set_manual_risk(
                conn=conn,
                score=demo_state.manual_risk_score,
                tier=demo_state.manual_risk_tier or "HIGH"
            )

        if demo_state.manual_branch is not None:
            database.set_branch_context(
                conn=conn,
                branch_code=demo_state.manual_branch
            )

        ctx = database.get_session_context(conn)
        return {
            "demo_settings": {
                "username": demo_state.username,
                "client_ip": demo_state.client_ip,
                "simulated_hour": demo_state.simulated_hour,
                "manual_score": demo_state.manual_risk_score,
                "manual_branch": demo_state.manual_branch,
                "burst_query_count": demo_state.burst_query_count,
            },
            "oracle_context": ctx
        }
    finally:
        conn.close()

@app.post("/api/session")
def update_session(req: SessionUpdateRequest):
    """Updates the simulated threat parameters."""
    if req.username is not None:
        demo_state.username = req.username
    if req.client_ip is not None:
        demo_state.client_ip = req.client_ip
    if req.simulated_hour is not None:
        demo_state.simulated_hour = req.simulated_hour
    if req.manual_risk_score is not None:
        demo_state.manual_risk_score = req.manual_risk_score
        demo_state.manual_risk_tier = req.manual_risk_tier or ("HIGH" if req.manual_risk_score >= 70 else "MEDIUM" if req.manual_risk_score >= 30 else "LOW")
    if req.manual_branch is not None:
        demo_state.manual_branch = req.manual_branch

    return get_current_session()

@app.post("/api/simulate/burst")
def simulate_query_burst(burst_count: int = 15):
    """Simulates query velocity burst anomaly."""
    demo_state.burst_query_count = burst_count
    conn = database.get_connection("admin")
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE SEC_OWNER.USER_RISK ur
                SET ur.query_count_current_window = NVL(ur.query_count_current_window, 0) + :b_cnt
                WHERE ur.user_id = (SELECT user_id FROM SEC_OWNER.APP_USERS WHERE username = LOWER(:u))
                """,
                b_cnt=burst_count,
                u=demo_state.username
            )
            conn.commit()
        return {"status": "BURST_SIMULATED", "queries_added": burst_count, "username": demo_state.username}
    finally:
        conn.close()

@app.post("/api/simulate/reset")
def reset_simulation():
    """Resets anomalies and manual overrides for the active user."""
    demo_state.manual_risk_score = None
    demo_state.manual_risk_tier = None
    demo_state.manual_branch = None
    demo_state.burst_query_count = 1
    demo_state.simulated_hour = 14
    demo_state.client_ip = "192.168.1.102"

    conn = database.get_connection("admin")
    try:
        with conn.cursor() as cursor:
            cursor.callproc(
                "SEC_OWNER.PKG_RISK_ENGINE.RESET_USER_ANOMALIES",
                [demo_state.username]
            )
            conn.commit()
        return {"status": "ANOMALIES_RESET", "username": demo_state.username}
    finally:
        conn.close()

@app.get("/api/customers")
def get_masked_customers(limit: int = 50):
    """
    Executes live query on VW_CUSTOMERS with active session context.
    Applies real-time column masking, row filtering, and FGA auditing.
    """
    conn = database.get_connection("app")
    try:
        database.init_user_session(
            conn=conn,
            username=demo_state.username,
            client_ip=demo_state.client_ip,
            simulated_hour=demo_state.simulated_hour
        )

        if demo_state.manual_risk_score is not None:
            database.set_manual_risk(
                conn=conn,
                score=demo_state.manual_risk_score,
                tier=demo_state.manual_risk_tier or "HIGH"
            )

        if demo_state.manual_branch is not None:
            database.set_branch_context(
                conn=conn,
                branch_code=demo_state.manual_branch
            )

        ctx = database.get_session_context(conn)
        rows = database.fetch_masked_customers(conn=conn, limit=limit)
        return {
            "session_context": ctx,
            "row_count": len(rows),
            "customers": rows
        }
    finally:
        conn.close()

# Mount frontend static dashboard
STATIC_DIR = Path(__file__).parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/")
def serve_index():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"message": "Context-Aware Dynamic Data Masking API is Active"}
