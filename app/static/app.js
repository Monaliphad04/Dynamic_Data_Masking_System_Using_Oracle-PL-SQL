/**
 * Context-Aware Dynamic Data Masking Interactive Client
 * Connects frontend sliders and controls to Oracle Database 21c backend.
 */

document.addEventListener("DOMContentLoaded", () => {
    // DOM Elements
    const personaSelect = document.getElementById("persona-select");
    const networkIpSelect = document.getElementById("network-ip-select");
    const timeSlider = document.getElementById("time-slider");
    const timeDisplay = document.getElementById("time-display");
    const workHourBadge = document.getElementById("work-hour-badge");
    const branchSelect = document.getElementById("branch-select");
    const riskOverrideSlider = document.getElementById("risk-override-slider");
    const riskOverrideDisplay = document.getElementById("risk-override-display");
    const btnSimulateBurst = document.getElementById("btn-simulate-burst");
    const btnResetSim = document.getElementById("btn-reset-simulation");
    const btnRefreshGrid = document.getElementById("btn-refresh-grid");

    // Gauge & Telemetry Elements
    const gaugeScore = document.getElementById("gauge-score");
    const gaugeCircle = document.getElementById("gauge-circle");
    const gaugeTierBadge = document.getElementById("gauge-tier-badge");
    const headerRole = document.getElementById("header-role");
    const headerUsername = document.getElementById("header-username");

    const ctxUser = document.getElementById("ctx-user");
    const ctxRole = document.getElementById("ctx-role");
    const ctxBranch = document.getElementById("ctx-branch");
    const ctxIp = document.getElementById("ctx-ip");
    const ctxCeiling = document.getElementById("ctx-ceiling");
    const ctxStatus = document.getElementById("ctx-status");

    // Grid & Feed Elements
    const customerTbody = document.getElementById("customer-tbody");
    const rowCountBadge = document.getElementById("row-count-badge");
    const auditFeed = document.getElementById("audit-feed");
    const rulesList = document.getElementById("rules-list");

    // ------------------------------------------------------------------------
    // API Interaction Methods
    // ------------------------------------------------------------------------

    async function updateSession(params = {}) {
        try {
            const res = await fetch("/api/session", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(params)
            });
            return await res.json();
        } catch (err) {
            console.error("Error updating session:", err);
        }
    }

    async function loadCustomers() {
        try {
            const res = await fetch("/api/customers?limit=50");
            const data = await res.json();
            renderSessionTelemetry(data.session_context);
            renderCustomerTable(data.customers);
            loadAuditLogs();
        } catch (err) {
            console.error("Error loading customers:", err);
            customerTbody.innerHTML = `<tr><td colspan="9" class="loading-cell error">Error connecting to Oracle: ${err.message}</td></tr>`;
        }
    }

    async function loadAuditLogs() {
        try {
            const res = await fetch("/api/audit?limit=15");
            const logs = await res.json();
            renderAuditFeed(logs);
        } catch (err) {
            console.error("Error fetching audit logs:", err);
        }
    }

    async function loadRules() {
        try {
            const res = await fetch("/api/rules");
            const rules = await res.json();
            renderRules(rules);
        } catch (err) {
            console.error("Error fetching rules:", err);
        }
    }

    // ------------------------------------------------------------------------
    // UI Rendering Functions
    // ------------------------------------------------------------------------

    function renderSessionTelemetry(ctx) {
        if (!ctx) return;

        const score = ctx.risk_score || 0;
        const tier = (ctx.risk_tier || "LOW").toUpperCase();

        // 1. Update Gauge
        gaugeScore.textContent = score;
        gaugeTierBadge.textContent = `${tier} RISK`;

        gaugeCircle.classList.remove("tier-medium", "tier-high");
        gaugeTierBadge.classList.remove("tier-low", "tier-medium", "tier-high");

        if (tier === "HIGH" || score >= 70) {
            gaugeCircle.classList.add("tier-high");
            gaugeTierBadge.classList.add("tier-high");
        } else if (tier === "MEDIUM" || score >= 30) {
            gaugeCircle.classList.add("tier-medium");
            gaugeTierBadge.classList.add("tier-medium");
        } else {
            gaugeTierBadge.classList.add("tier-low");
        }

        // 2. Update Header
        headerRole.textContent = ctx.role_name || "PUBLIC";
        headerUsername.textContent = ctx.app_user || "UNKNOWN";

        // 3. Update Context Telemetry Strip
        ctxUser.textContent = ctx.app_user || "-";
        ctxRole.textContent = ctx.role_name || "-";
        ctxBranch.textContent = ctx.branch_code || "NONE";
        ctxIp.textContent = ctx.client_ip || "-";
        ctxCeiling.textContent = ctx.role_name === "SEC_ADMIN" ? "100" : (ctx.role_name === "CUSTOMER_CARE" ? "60" : "80");
        ctxStatus.textContent = ctx.status || "ACTIVE";

        if (ctx.status !== "ACTIVE") {
            ctxStatus.className = "telemetry-val highlight";
            ctxStatus.style.color = "var(--color-high)";
        } else {
            ctxStatus.className = "telemetry-val status-ok";
            ctxStatus.style.color = "var(--color-low)";
        }
    }

    function renderCustomerTable(customers) {
        if (!customers || customers.length === 0) {
            customerTbody.innerHTML = `<tr><td colspan="9" class="loading-cell">0 records returned (Fail-Closed Row Isolation Enforced by Oracle VPD)</td></tr>`;
            rowCountBadge.textContent = "0 Records";
            return;
        }

        rowCountBadge.textContent = `${customers.length} Records`;

        const rowsHtml = customers.map(c => {
            const emailHtml = formatCell(c.email, "email");
            const phoneHtml = formatCell(c.phone_number, "phone");
            const natIdHtml = formatCell(c.national_id, "id");
            const cardHtml  = formatCell(c.credit_card_num, "card");
            const balHtml   = formatBalance(c.account_balance);

            return `
                <tr>
                    <td class="cell-mono">${c.customer_id}</td>
                    <td><strong>${escapeHtml(c.first_name)} ${escapeHtml(c.last_name)}</strong></td>
                    <td class="cell-mono">${emailHtml}</td>
                    <td class="cell-mono">${phoneHtml}</td>
                    <td class="cell-mono">${natIdHtml}</td>
                    <td class="cell-mono">${cardHtml}</td>
                    <td class="cell-mono">${balHtml}</td>
                    <td><span class="branch-badge">${escapeHtml(c.branch_code)}</span></td>
                    <td><span class="badge-status in-hours" style="font-size:0.65rem;">${escapeHtml(c.risk_classification)}</span></td>
                </tr>
            `;
        }).join("");

        customerTbody.innerHTML = rowsHtml;
    }

    function formatCell(val, type) {
        if (val === null || val === undefined || val === "") {
            return `<span class="val-redacted">[REDACTED]</span>`;
        }
        const str = String(val);
        if (str.includes("*")) {
            return `<span class="val-partial">${escapeHtml(str)}</span>`;
        }
        return `<span class="val-clear">${escapeHtml(str)}</span>`;
    }

    function formatBalance(bal) {
        if (bal === null || bal === undefined) {
            return `<span class="val-redacted">[RESTRICTED]</span>`;
        }
        const num = Number(bal);
        if (isNaN(num)) return `<span class="val-redacted">[REDACTED]</span>`;
        if (num === 0) return `<span class="val-partial">$0.00</span>`;
        return `<span class="val-clear">$${num.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</span>`;
    }

    function renderAuditFeed(logs) {
        if (!logs || logs.length === 0) {
            auditFeed.innerHTML = `<div class="audit-item">No audit records retrieved.</div>`;
            return;
        }

        const itemsHtml = logs.map(l => {
            const tierClass = l.applied_tier === "HIGH" ? "tier-high" : (l.applied_tier === "MEDIUM" ? "tier-medium" : "tier-low");
            return `
                <div class="audit-entry">
                    <div class="audit-entry-top">
                        <span>#${l.log_id} ${escapeHtml(l.action_type)} on ${escapeHtml(l.target_object)}</span>
                        <span class="audit-entry-time">${l.access_time ? l.access_time.split(" ")[1] : ""}</span>
                    </div>
                    <div class="audit-entry-body">
                        <span class="audit-user-tag">${escapeHtml(l.app_username)}</span>
                        <span class="audit-tier-tag ${tierClass}">TIER: ${escapeHtml(l.applied_tier)} (${l.calculated_risk})</span>
                    </div>
                    <div class="audit-rules-tag">${escapeHtml(l.triggered_rules || "NORMAL_BASELINE")}</div>
                </div>
            `;
        }).join("");

        auditFeed.innerHTML = itemsHtml;
    }

    function renderRules(rules) {
        if (!rules || rules.length === 0) return;
        rulesList.innerHTML = rules.map(r => `
            <div class="rule-card">
                <div>
                    <div class="rule-code">${escapeHtml(r.rule_code)} (+${r.weight})</div>
                    <div class="rule-desc">${escapeHtml(r.description)}</div>
                </div>
            </div>
        `).join("");
    }

    function escapeHtml(str) {
        if (!str) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // ------------------------------------------------------------------------
    // Event Handlers
    // ------------------------------------------------------------------------

    personaSelect.addEventListener("change", async (e) => {
        const username = e.target.value;
        await updateSession({ username });
        loadCustomers();
    });

    networkIpSelect.addEventListener("change", async (e) => {
        const client_ip = e.target.value;
        await updateSession({ client_ip });
        loadCustomers();
    });

    timeSlider.addEventListener("input", (e) => {
        const hour = parseInt(e.target.value, 10);
        const ampm = hour >= 12 ? "PM" : "AM";
        const h12 = hour % 12 === 0 ? 12 : hour % 12;
        timeDisplay.textContent = `${String(hour).padStart(2, '0')}:00 (${h12}:00 ${ampm})`;

        if (hour >= 9 && hour <= 18) {
            workHourBadge.textContent = "Normal Business Hours";
            workHourBadge.className = "badge-status in-hours";
        } else {
            workHourBadge.textContent = "Off-Hours Anomaly (+35 Risk)";
            workHourBadge.className = "badge-status off-hours";
        }
    });

    timeSlider.addEventListener("change", async (e) => {
        const simulated_hour = parseInt(e.target.value, 10);
        await updateSession({ simulated_hour });
        loadCustomers();
    });

    branchSelect.addEventListener("change", async (e) => {
        const val = e.target.value;
        const manual_branch = val === "AUTO" ? null : val;
        await updateSession({ manual_branch });
        loadCustomers();
    });

    riskOverrideSlider.addEventListener("input", (e) => {
        const val = parseInt(e.target.value, 10);
        if (val === -1) {
            riskOverrideDisplay.textContent = "Auto (Rule Engine)";
        } else {
            riskOverrideDisplay.textContent = `${val} / 100`;
        }
    });

    riskOverrideSlider.addEventListener("change", async (e) => {
        const val = parseInt(e.target.value, 10);
        const manual_risk_score = val === -1 ? null : val;
        await updateSession({ manual_risk_score });
        loadCustomers();
    });

    btnSimulateBurst.addEventListener("click", async () => {
        btnSimulateBurst.disabled = true;
        btnSimulateBurst.innerHTML = "<span>⚡</span> Triggering Velocity Spike...";
        try {
            await fetch("/api/simulate/burst?burst_count=15", { method: "POST" });
            await loadCustomers();
        } finally {
            setTimeout(() => {
                btnSimulateBurst.disabled = false;
                btnSimulateBurst.innerHTML = "<span>⚡</span> Simulate Query Burst (+15)";
            }, 600);
        }
    });

    btnResetSim.addEventListener("click", async () => {
        btnResetSim.disabled = true;
        try {
            await fetch("/api/simulate/reset", { method: "POST" });
            timeSlider.value = 14;
            timeSlider.dispatchEvent(new Event("input"));
            networkIpSelect.value = "192.168.1.102";
            branchSelect.value = "AUTO";
            riskOverrideSlider.value = -1;
            riskOverrideSlider.dispatchEvent(new Event("input"));

            await updateSession({
                username: personaSelect.value,
                client_ip: "192.168.1.102",
                simulated_hour: 14,
                manual_risk_score: null,
                manual_branch: null
            });
            await loadCustomers();
        } finally {
            btnResetSim.disabled = false;
        }
    });

    btnRefreshGrid.addEventListener("click", () => {
        loadCustomers();
    });

    // ------------------------------------------------------------------------
    // Initial Load
    // ------------------------------------------------------------------------
    loadRules();
    loadCustomers();
});
