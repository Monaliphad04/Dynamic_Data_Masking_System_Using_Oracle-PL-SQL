-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 4: Trusted Context & Session Management
-- Package: SEC_OWNER.PKG_SESSION_CTX (Specification)
-- File:    sql/procedures/pkg_session_ctx.pks
-- Target:  Oracle Database (ORCLPDB) - Schema: SEC_OWNER
-- Purpose: Public contract for trusted application session initialization,
--          context manipulation, and security state queries.
-- ============================================================================

CREATE OR REPLACE PACKAGE SEC_OWNER.PKG_SESSION_CTX AUTHID DEFINER AS

    -- Context Namespace Constant
    C_CONTEXT_NAMESPACE CONSTANT VARCHAR2(30) := 'CTX_SEC_MASK';

    -- Default Fallback Values
    C_DEFAULT_USER      CONSTANT VARCHAR2(30) := 'ANONYMOUS';
    C_DEFAULT_ROLE      CONSTANT VARCHAR2(30) := 'PUBLIC';
    C_DEFAULT_IP        CONSTANT VARCHAR2(50) := '127.0.0.1';
    C_MAX_RISK_SCORE    CONSTANT NUMBER       := 100;

    /**
     * Initializes the private application context for an authenticated user.
     * Validates identity against APP_USERS, resolves active role, and populates
     * trusted attributes into CTX_SEC_MASK.
     *
     * @param p_username   The verified username (e.g., 'agent_sarah')
     * @param p_client_ip  The verified client or proxy IP (optional)
     */
    PROCEDURE INITIALIZE_SESSION(
        p_username  IN VARCHAR2,
        p_client_ip IN VARCHAR2 DEFAULT NULL
    );

    /**
     * Updates the dynamic risk score and tier within the current session context.
     * Called exclusively by the Risk Evaluation Engine (PKG_RISK_ENGINE).
     *
     * @param p_score Clamped numerical risk score (0 to 100)
     * @param p_tier  Risk category ('LOW', 'MEDIUM', 'HIGH')
     */
    PROCEDURE SET_SESSION_RISK(
        p_score IN NUMBER,
        p_tier  IN VARCHAR2
    );

    /**
     * Clears all attributes from CTX_SEC_MASK.
     * Used on session logout, connection pool release, or context resets.
     */
    PROCEDURE CLEAR_SESSION;

    -- ========================================================================
    -- Context Query Functions (Callable from SQL Queries and Views)
    -- ========================================================================

    FUNCTION GET_APP_USER            RETURN VARCHAR2 DETERMINISTIC;
    FUNCTION GET_USER_ID             RETURN NUMBER   DETERMINISTIC;
    FUNCTION GET_ROLE_NAME           RETURN VARCHAR2 DETERMINISTIC;
    FUNCTION GET_MAX_PERMITTED_RISK  RETURN NUMBER   DETERMINISTIC;
    FUNCTION GET_CLIENT_IP           RETURN VARCHAR2 DETERMINISTIC;
    FUNCTION GET_CURRENT_RISK_SCORE  RETURN NUMBER   DETERMINISTIC;
    FUNCTION GET_CURRENT_RISK_TIER   RETURN VARCHAR2 DETERMINISTIC;
    FUNCTION GET_WORK_HOUR_START     RETURN NUMBER   DETERMINISTIC;
    FUNCTION GET_WORK_HOUR_END       RETURN NUMBER   DETERMINISTIC;
    FUNCTION GET_TRUSTED_IP_SUBNET   RETURN VARCHAR2 DETERMINISTIC;
    FUNCTION IS_SESSION_INITIALIZED  RETURN VARCHAR2 DETERMINISTIC;

END PKG_SESSION_CTX;
/
