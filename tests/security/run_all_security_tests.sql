-- ============================================================================
-- Project: Context-Aware Dynamic Data Masking System Using Oracle PL/SQL
-- Phase 10: Comprehensive Security & Adversarial Bypass Testing
-- Script:  tests/security/run_all_security_tests.sql
-- Target:  Oracle Database (ORCLPDB)
-- Purpose: Master runner executing all negative security, bypass resistance,
--          and privilege escalation test suites for Phase 10.
-- ============================================================================

SET ECHO OFF;
SET DEFINE OFF;
SET FEEDBACK OFF;
SET SERVEROUTPUT ON SIZE UNLIMITED;

PROMPT ========================================================================
PROMPT [PHASE 10 MASTER SECURITY TEST RUNNER]
PROMPT Starting Full Negative & Adversarial Security Test Suite
PROMPT Target Instance: Oracle Database 21c Enterprise Edition (ORCLPDB)
PROMPT ========================================================================

-- Execute Suite 1: Bypass & Injection Resistance Tests
@tests/security/test_security_bypass.sql

-- Execute Suite 2: Privilege Escalation & Audit Immutability Tests
@tests/security/test_privilege_escalation.sql

PROMPT ========================================================================
PROMPT [PHASE 10 MASTER SECURITY TEST RUNNER COMPLETED]
PROMPT All security and bypass scenarios evaluated successfully.
PROMPT ========================================================================
