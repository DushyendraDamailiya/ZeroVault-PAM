// ZeroVault PAM - Enterprise Command Center Controller
let currentLeases = [];
let countdownInterval = null;
let pendingJitRequest = null;
let currentMfaDemoCode = "777888";

document.addEventListener('DOMContentLoaded', () => {
    initApp();
});

function initApp() {
    loadKPIs();
    loadServers();
    loadLeases();
    loadSessions();
    loadLedger();
    loadAccessRequests();

    // Polling intervals (auto-refresh leases & approvals every 4 seconds)
    setInterval(loadKPIs, 4000);
    setInterval(loadSessions, 4000);
    setInterval(loadLeases, 4000);
    setInterval(loadAccessRequests, 4000);

    // 1-Second Countdown Timer
    if (countdownInterval) clearInterval(countdownInterval);
    countdownInterval = setInterval(updateCountdowns, 1000);
}

// --- Tab Navigation ---
function switchTab(tabId) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

    const btn = Array.from(document.querySelectorAll('.tab-btn')).find(b => b.getAttribute('onclick')?.includes(tabId));
    if (btn) btn.classList.add('active');

    const pane = document.getElementById(`pane-${tabId}`);
    if (pane) pane.classList.add('active');

    if (tabId === 'ledger') loadLedger();
    if (tabId === 'sessions') loadSessions();
    if (tabId === 'vault') loadServers();
    if (tabId === 'jit') loadLeases();
    if (tabId === 'approvals') loadAccessRequests();
}

// --- Load KPIs ---
async function loadKPIs() {
    try {
        const resp = await fetch('/api/kpis');
        if (resp.ok) {
            const data = await resp.json();
            document.getElementById('kpi-servers').innerText = data.total_servers || 0;
            document.getElementById('kpi-leases').innerText = data.active_leases || 0;
            document.getElementById('kpi-sessions').innerText = data.active_sessions || 0;
            document.getElementById('kpi-blocked').innerText = data.blocked_commands || 0;
            document.getElementById('kpi-blocks').innerText = data.total_ledger_blocks || 0;

            if (data.db_engine) {
                const dbEngineEl = document.getElementById('header-db-engine');
                if (dbEngineEl) {
                    dbEngineEl.innerText = data.db_engine;
                }
            }

            const pendingCount = data.pending_approvals || 0;
            const badgePendingEl = document.getElementById('badge-pending-count');
            if (badgePendingEl) {
                badgePendingEl.innerText = pendingCount;
                badgePendingEl.style.display = pendingCount > 0 ? 'inline-block' : 'none';
            }

            const isIntegrityValid = (data.chain_integrity === "VALID");
            const integrityEl = document.getElementById('kpi-integrity');
            const cardEl = document.getElementById('kpi-card-integrity');
            const headerChainEl = document.getElementById('header-chain-status');
            const badgeLedgerEl = document.getElementById('badge-ledger');

            if (isIntegrityValid) {
                integrityEl.innerText = "VALID";
                integrityEl.className = "kpi-value text-emerald";
                cardEl.className = "kpi-card border-emerald";
                headerChainEl.innerText = "VALID (UNBROKEN)";
                badgeLedgerEl.className = "status-badge badge-emerald";
            } else {
                integrityEl.innerText = "TAMPERED";
                integrityEl.className = "kpi-value text-crimson";
                cardEl.className = "kpi-card border-crimson";
                headerChainEl.innerText = "TAMPER DETECTED!";
                badgeLedgerEl.className = "status-badge badge-crimson";
            }
        }
    } catch (err) {
        console.error("Failed to load KPIs:", err);
    }
}

// --- Load Servers & Populate Select ---
async function loadServers() {
    try {
        const resp = await fetch('/api/servers');
        if (resp.ok) {
            const servers = await resp.json();
            const selectEl = document.getElementById('jit-server-select');
            const tbody = document.getElementById('servers-tbody');

            selectEl.innerHTML = '';
            tbody.innerHTML = '';

            if (servers.length === 0) {
                selectEl.innerHTML = '<option value="" disabled>No servers available</option>';
                tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No servers enrolled yet.</td></tr>';
                return;
            }

            servers.forEach(s => {
                // Populate Select Option
                const opt = document.createElement('option');
                opt.value = s.server_id;
                opt.innerText = `${s.name} (${s.host}:${s.ssh_port})`;
                selectEl.appendChild(opt);

                // Populate Table Row
                const env = s.envelope_preview || {};
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><code style="color:var(--cyan);font-weight:700;">${escapeHtml(s.server_id)}</code></td>
                    <td><strong>${escapeHtml(s.name)}</strong></td>
                    <td><code>${escapeHtml(s.host)}:${s.ssh_port}</code></td>
                    <td><code>${escapeHtml(s.admin_user)}</code></td>
                    <td>
                        <span class="badge-purple" title="AES-256-GCM Envelope">${env.cipher || 'AES-GCM'} | Salt: ${env.salt_prefix || '---'}</span>
                    </td>
                    <td style="font-size:11px;color:var(--text-secondary);">${formatTime(s.last_rotated_at)}</td>
                    <td>
                        <button class="btn-sm btn-outline-cyan" onclick="rotatePassword('${s.server_id}')">Rotate Password</button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (err) {
        console.error("Failed to load servers:", err);
    }
}

// --- Load JIT Leases ---
async function loadLeases() {
    try {
        const resp = await fetch('/api/leases');
        if (resp.ok) {
            currentLeases = await resp.json();
            renderLeasesTable();
        }
    } catch (err) {
        console.error("Failed to load leases:", err);
    }
}

function renderLeasesTable() {
    const tbody = document.getElementById('leases-tbody');
    tbody.innerHTML = '';

    if (currentLeases.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No JIT leases issued yet. Request access above!</td></tr>';
        return;
    }

    currentLeases.forEach(l => {
        const tr = document.createElement('tr');
        const isExpired = l.remaining_seconds <= 0 || l.status !== 'ACTIVE';
        const remMinutes = Math.floor(l.remaining_seconds / 60);
        const remSecs = l.remaining_seconds % 60;
        const timeDisplay = isExpired ? '00:00 (EXPIRED)' : `${String(remMinutes).padStart(2, '0')}:${String(remSecs).padStart(2, '0')}`;
        const cmdStr = `ssh -p 2222 ${l.lease_id}@127.0.0.1`;

        tr.innerHTML = `
            <td><strong style="color:var(--amber);">${escapeHtml(l.lease_id)}</strong></td>
            <td>${escapeHtml(l.server_name || l.server_id)}</td>
            <td><code>${escapeHtml(l.ephemeral_user)}</code></td>
            <td>${escapeHtml(l.requester)}</td>
            <td>
                <span class="countdown-badge ${isExpired ? 'countdown-expired' : 'countdown-active'}" id="timer-${l.lease_id}">
                    ${timeDisplay}
                </span>
            </td>
            <td>
                <span class="status-badge ${l.status === 'ACTIVE' ? 'badge-emerald' : 'badge-crimson'}" style="padding:2px 8px;font-size:11px;">
                    ${escapeHtml(l.status)}
                </span>
            </td>
            <td>
                <div style="display:flex;align-items:center;gap:6px;">
                    <code class="code-highlight" style="font-size:11px;">${cmdStr}</code>
                    <button class="btn-sm btn-outline-cyan" style="padding:2px 6px;" onclick="copyToClipboard('${cmdStr}')" title="Copy to clipboard">Copy</button>
                </div>
            </td>
            <td>
                ${l.status === 'ACTIVE' ?
                    `<button class="btn-sm btn-outline-danger" onclick="revokeLease('${l.lease_id}')">Revoke Lease</button>` :
                    `<span class="text-muted" style="font-size:11px;">Account Purged</span>`
                }
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function updateCountdowns() {
    currentLeases.forEach(l => {
        if (l.status === 'ACTIVE' && l.remaining_seconds > 0) {
            l.remaining_seconds -= 1;
            const el = document.getElementById(`timer-${l.lease_id}`);
            if (el) {
                const remMinutes = Math.floor(l.remaining_seconds / 60);
                const remSecs = l.remaining_seconds % 60;
                el.innerText = `${String(remMinutes).padStart(2, '0')}:${String(remSecs).padStart(2, '0')}`;
                if (l.remaining_seconds <= 0) {
                    el.innerText = "00:00 (EXPIRED)";
                    el.className = "countdown-badge countdown-expired";
                    loadKPIs();
                    loadLeases();
                }
            }
        }
    });
}

// --- Request JIT Lease (Trigger MFA Modal) ---
async function handleRequestJit(e) {
    e.preventDefault();
    const server_id = document.getElementById('jit-server-select').value;
    const requester = document.getElementById('jit-requester').value.trim();
    const reason = document.getElementById('jit-reason').value.trim();
    const ttl_minutes = parseInt(document.getElementById('jit-ttl').value);
    const risk_level = document.getElementById('jit-risk-level') ? document.getElementById('jit-risk-level').value : 'STANDARD';

    if (!server_id) {
        alert("Please select a target production server.");
        return;
    }

    pendingJitRequest = {
        server_id,
        requester,
        reason,
        ttl_minutes,
        risk_level
    };

    // Fetch Google Authenticator Setup & QR Code
    try {
        const resp = await fetch(`/api/mfa/setup?username=${encodeURIComponent(requester)}`);
        if (resp.ok) {
            const mfaData = await resp.json();
            document.getElementById('mfa-qr-img').src = mfaData.qr_code_url;
            document.getElementById('mfa-secret-code').innerText = mfaData.secret;
            currentMfaDemoCode = mfaData.current_totp;
            document.getElementById('mfa-input-code').value = '';
            document.getElementById('mfa-input-code').onkeydown = (ev) => {
                if (ev.key === 'Enter') {
                    ev.preventDefault();
                    confirmMfaAndSubmit();
                }
            };
            document.getElementById('mfa-modal').style.display = 'flex';
            setTimeout(() => document.getElementById('mfa-input-code').focus(), 150);
        } else {
            confirmMfaAndSubmit("777888");
        }
    } catch (err) {
        console.error("MFA setup error:", err);
        confirmMfaAndSubmit("777888");
    }
}

function closeMfaModal() {
    document.getElementById('mfa-modal').style.display = 'none';
}

async function confirmMfaAndSubmit(overrideCode) {
    const code = overrideCode || document.getElementById('mfa-input-code').value.trim();
    if (!code) {
        alert("Please enter the 6-digit Google Authenticator code.");
        return;
    }

    if (!pendingJitRequest) {
        closeMfaModal();
        return;
    }

    const payload = {
        ...pendingJitRequest,
        mfa_code: code
    };

    try {
        const resp = await fetch('/api/leases', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await resp.json();

        closeMfaModal();

        if (resp.status === 202) {
            // Maker-Checker Pending Approval Flow
            alert(`🛡️ High-Risk Access Request Submitted for Approval!\n\nRequest ID: ${data.request_id}\nTarget: ${data.server_name}\nRequester: ${data.requester}\n\nYour request has been quarantined in the Maker-Checker Approvals Queue. A Senior Security Admin must approve it before SSH credentials become active.`);
            switchTab('approvals');
            loadAccessRequests();
            loadKPIs();
        } else if (resp.ok) {
            // Standard Instant JIT Issue
            alert(`✅ JIT Ephemeral Lease Issued Successfully!\n\n[2FA Verified via Google Authenticator]\nLease ID: ${data.lease_id}\nEphemeral User: ${data.ephemeral_user}\nTTL: ${data.ttl_minutes} minutes\n\nRun in PowerShell:\n${data.ssh_connection_string}`);
            loadLeases();
            loadKPIs();
        } else {
            alert('Error issuing lease: ' + (data.error || 'Unknown error'));
        }
    } catch (err) {
        alert('Connection error: ' + err.message);
    }
}

// --- Maker-Checker Approvals Queue ---
async function loadAccessRequests() {
    try {
        const resp = await fetch('/api/requests');
        if (resp.ok) {
            const requests = await resp.json();
            renderAccessRequests(requests);
        }
    } catch (err) {
        console.error("Failed to load access requests:", err);
    }
}

function renderAccessRequests(requests) {
    const tbody = document.getElementById('approvals-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (!requests || requests.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No access requests in governance queue.</td></tr>';
        return;
    }

    requests.forEach(r => {
        const tr = document.createElement('tr');
        const isPending = r.status === 'PENDING_APPROVAL';
        const isApproved = r.status === 'APPROVED';

        let statusBadge = `<span class="status-badge badge-amber" style="padding:2px 8px;font-size:11px;">PENDING</span>`;
        if (isApproved) {
            statusBadge = `<span class="status-badge badge-emerald" style="padding:2px 8px;font-size:11px;">APPROVED</span>`;
        } else if (r.status === 'REJECTED') {
            statusBadge = `<span class="status-badge badge-crimson" style="padding:2px 8px;font-size:11px;">REJECTED</span>`;
        }

        let actionHtml = '';
        if (isPending) {
            actionHtml = `
                <div style="display:flex;gap:6px;">
                    <button class="btn-sm btn-emerald" onclick="approveRequest('${r.request_id}')">✓ Approve</button>
                    <button class="btn-sm btn-outline-danger" onclick="rejectRequest('${r.request_id}')">✕ Reject</button>
                </div>
            `;
        } else if (isApproved) {
            actionHtml = `<span style="font-size:11px;color:var(--emerald);">Active Lease: <code>${escapeHtml(r.lease_id || '---')}</code></span>`;
        } else {
            actionHtml = `<span style="font-size:11px;color:var(--crimson);">${escapeHtml(r.reviewer_comments || 'Rejected')}</span>`;
        }

        tr.innerHTML = `
            <td><strong style="color:var(--cyan);font-family:var(--font-mono);">${escapeHtml(r.request_id)}</strong></td>
            <td>${escapeHtml(r.server_name || r.server_id)}</td>
            <td><code>${escapeHtml(r.requester)}</code></td>
            <td>
                <span class="${r.risk_level === 'CRITICAL' ? 'badge-crimson' : 'badge-cyan'}" style="padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;">
                    ${escapeHtml(r.risk_level)}
                </span>
            </td>
            <td>${r.ttl_minutes}m</td>
            <td style="font-size:12px;color:var(--text-secondary);max-width:260px;">${escapeHtml(r.reason)}</td>
            <td>${statusBadge}</td>
            <td>${actionHtml}</td>
        `;
        tbody.appendChild(tr);
    });
}

async function approveRequest(requestId) {
    if (!confirm(`Are you sure you want to approve high-risk access request '${requestId}' as Senior Security Admin? This will dynamically mint temporary OS credentials.`)) {
        return;
    }

    try {
        const resp = await fetch(`/api/requests/${requestId}/approve`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reviewer: "Security_Admin_Lead", comments: "Approved emergency maintenance window" })
        });
        const data = await resp.json();
        if (resp.ok) {
            alert(`✅ Request '${requestId}' Approved!\n\nLease ID: ${data.lease_id}\nEphemeral User: ${data.ephemeral_user}\n\nConnection Command:\n${data.ssh_connection_string}`);
            loadAccessRequests();
            loadLeases();
            loadKPIs();
        } else {
            alert("Approval failed: " + (data.error || "Unknown error"));
        }
    } catch (err) {
        alert("Network error: " + err.message);
    }
}

async function rejectRequest(requestId) {
    const reason = prompt("Enter reason for rejecting this access request:", "Insufficient business justification or outside approved maintenance window.");
    if (reason === null) return;

    try {
        const resp = await fetch(`/api/requests/${requestId}/reject`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reviewer: "Security_Admin_Lead", comments: reason })
        });
        const data = await resp.json();
        if (resp.ok) {
            alert(`Access request '${requestId}' rejected.`);
            loadAccessRequests();
            loadKPIs();
        } else {
            alert("Rejection failed: " + (data.error || "Unknown error"));
        }
    } catch (err) {
        alert("Network error: " + err.message);
    }
}

// --- Revoke Lease ---
async function revokeLease(leaseId) {
    if (!confirm(`Are you sure you want to revoke lease '${leaseId}' immediately? This will kill active SSH connections and purge the Linux OS user.`)) {
        return;
    }

    try {
        const resp = await fetch(`/api/leases/${leaseId}/revoke`, { method: 'POST' });
        const data = await resp.json();
        if (resp.ok) {
            alert(`Lease '${leaseId}' revoked! Ephemeral account purged.`);
            loadLeases();
            loadSessions();
            loadKPIs();
        } else {
            alert('Revoke failed: ' + data.error);
        }
    } catch (err) {
        alert('Error: ' + err.message);
    }
}

// --- Enroll Server ---
async function handleEnrollServer(e) {
    e.preventDefault();
    const server_id = document.getElementById('srv-id').value.trim();
    const name = document.getElementById('srv-name').value.trim();
    const host = document.getElementById('srv-host').value.trim();
    const ssh_port = parseInt(document.getElementById('srv-port').value);
    const admin_user = document.getElementById('srv-user').value.trim();
    const password = document.getElementById('srv-pass').value.trim();

    try {
        const resp = await fetch('/api/servers', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ server_id, name, host, ssh_port, admin_user, password })
        });
        const data = await resp.json();
        if (resp.ok) {
            alert(`Server '${name}' enrolled with AES-256-GCM Envelope Encryption!`);
            document.getElementById('enroll-server-form').reset();
            loadServers();
            loadKPIs();
        } else {
            alert('Enroll error: ' + data.error);
        }
    } catch (err) {
        alert('Error: ' + err.message);
    }
}

// --- Rotate Password ---
async function rotatePassword(serverId) {
    if (!confirm(`Rotate master password for server '${serverId}' now? A new 256-bit cryptographically random password will be generated and stored in the vault.`)) {
        return;
    }

    try {
        const resp = await fetch(`/api/servers/${serverId}/rotate`, { method: 'POST' });
        const data = await resp.json();
        if (resp.ok) {
            alert(`Success: ${data.message}`);
            loadServers();
            loadKPIs();
        } else {
            alert('Rotation error: ' + data.error);
        }
    } catch (err) {
        alert('Error: ' + err.message);
    }
}

// --- Load Active Sessions & DVR ---
async function loadSessions() {
    try {
        const resp = await fetch('/api/sessions/active');
        if (resp.ok) {
            const sessions = await resp.json();
            const tbody = document.getElementById('sessions-tbody');
            tbody.innerHTML = '';

            if (sessions.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No active SSH sessions right now. Connect via Port 2222 to start!</td></tr>';
                return;
            }

            sessions.forEach(s => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><code style="color:var(--cyan);">${escapeHtml(s.session_id)}</code></td>
                    <td><strong style="color:var(--amber);">${escapeHtml(s.lease_id)}</strong></td>
                    <td><code>${escapeHtml(s.client_ip)}</code></td>
                    <td>${s.commands_count || 0}</td>
                    <td><span style="color:${s.violations_count > 0 ? 'var(--crimson)' : 'inherit'};font-weight:700;">${s.violations_count || 0}</span></td>
                    <td><span class="status-badge badge-emerald" style="padding:2px 8px;font-size:11px;">TUNNEL ACTIVE</span></td>
                    <td>
                        <button class="btn-sm btn-outline-cyan" onclick="viewSessionDvr('${s.session_id}')">View DVR</button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (err) {
        console.error("Failed to load sessions:", err);
    }
}

async function viewSessionDvr(sessionId) {
    try {
        const resp = await fetch(`/api/sessions/${sessionId}/transcript`);
        if (resp.ok) {
            const session = await resp.json();
            document.getElementById('dvr-session-tag').innerText = `Session: ${sessionId}`;
            const display = document.getElementById('terminal-dvr-display');
            display.innerText = session.transcript || "No commands typed in this session yet.";
        }
    } catch (err) {
        alert("Failed to load DVR transcript: " + err.message);
    }
}

// --- Load Merkle Audit Ledger ---
async function loadLedger() {
    try {
        const resp = await fetch('/api/ledger');
        if (resp.ok) {
            const blocks = await resp.json();
            const tbody = document.getElementById('ledger-tbody');
            tbody.innerHTML = '';

            if (blocks.length === 0) {
                tbody.innerHTML = '<tr><td colspan="9" class="text-center text-muted">Ledger is empty.</td></tr>';
                return;
            }

            // Update meta hashes
            document.getElementById('meta-genesis').innerText = blocks[0].current_hash.slice(0, 16) + '...';
            document.getElementById('meta-latest').innerText = blocks[blocks.length - 1].current_hash.slice(0, 16) + '...';

            blocks.forEach(b => {
                const tr = document.createElement('tr');
                const isBlocked = b.action === 'BLOCKED';
                const isGenesis = b.action === 'GENESIS';

                tr.innerHTML = `
                    <td><strong>#${b.block_index}</strong></td>
                    <td style="font-size:11px;color:var(--text-secondary);">${formatTime(b.timestamp)}</td>
                    <td><code>${escapeHtml(b.lease_id)}</code></td>
                    <td><code>${escapeHtml(b.user)}</code></td>
                    <td><code style="color:${isBlocked ? 'var(--crimson)' : 'var(--text-primary)'};">${escapeHtml(b.command)}</code></td>
                    <td>
                        <span class="status-badge ${isBlocked ? 'badge-crimson' : (isGenesis ? 'badge-cyan' : 'badge-emerald')}" style="padding:2px 8px;font-size:11px;">
                            ${escapeHtml(b.action)}
                        </span>
                    </td>
                    <td style="font-size:11px;color:var(--amber);">${escapeHtml(b.rule_triggered || 'NONE')}</td>
                    <td class="hash-cell" title="${b.prev_hash}">${b.prev_hash.slice(0, 12)}...</td>
                    <td class="hash-cell" title="${b.current_hash}">${b.current_hash.slice(0, 12)}...</td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (err) {
        console.error("Failed to load ledger:", err);
    }
}

// --- Verify Merkle Chain Integrity ---
async function runIntegrityCheck() {
    try {
        const resp = await fetch('/api/ledger/verify');
        if (resp.ok) {
            const data = await resp.json();
            const banner = document.getElementById('ledger-status-banner');
            const headline = document.getElementById('ledger-headline');
            const subline = document.getElementById('ledger-subline');
            const icon = document.getElementById('ledger-icon');

            if (data.valid) {
                banner.className = 'ledger-status-box';
                icon.innerText = '✓';
                headline.innerText = 'LEDGER INTEGRITY VERIFIED (BLOCKS 100% UNBROKEN)';
                subline.innerText = `Verified ${data.total_blocks} blocks. All cryptographic SHA-256 Merkle links match.`;
                alert(`Cryptographic Verification Succeeded!\n\nAll ${data.total_blocks} blocks in the Merkle Hash-Chain maintain 100% unbroken cryptographic integrity.`);
            } else {
                banner.className = 'ledger-status-box tampered';
                icon.innerText = '⚠';
                headline.innerText = `CRITICAL TAMPER DETECTED AT BLOCK #${data.tampered_block_index}!`;
                subline.innerText = data.message;
                alert(`CRITICAL FRAUD ALERT:\n\n${data.message}\n\nA database row was secretly modified, breaking the SHA-256 hash chain!`);
            }
            loadKPIs();
        }
    } catch (err) {
        alert("Integrity verification error: " + err.message);
    }
}

// --- Tamper Simulation Modal ---
function openTamperModal() {
    document.getElementById('tamper-modal').style.display = 'flex';
}

function closeTamperModal() {
    document.getElementById('tamper-modal').style.display = 'none';
}

async function executeTamperAttack() {
    const blockNum = parseInt(document.getElementById('tamper-block-num').value);
    const tamperedCmd = document.getElementById('tamper-cmd').value.trim();

    try {
        const resp = await fetch('/api/ledger/tamper_test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ block_index: blockNum, tampered_command: tamperedCmd })
        });
        const data = await resp.json();
        if (resp.ok) {
            closeTamperModal();
            alert(`Tamper Attack Injected!\n\nBlock #${blockNum} was secretly modified to: '${tamperedCmd}'.\nNow click 'Verify Chain Integrity' to watch the Merkle chain catch the fraud!`);
            loadLedger();
            loadKPIs();
        } else {
            alert('Tamper injection failed: ' + data.error);
        }
    } catch (err) {
        alert('Error: ' + err.message);
    }
}

// --- Feature 1: In-Browser Web Shell ---
async function handleWebShellSubmit(e) {
    if (e) e.preventDefault();
    const inputEl = document.getElementById('webshell-input');
    const cmd = inputEl.value.trim();
    if (!cmd) return;
    inputEl.value = '';
    await runWebShellCmd(cmd);
}

async function runWebShellCmd(cmd) {
    const screen = document.getElementById('webshell-screen');
    
    // Echo user prompt
    const userLine = document.createElement('div');
    userLine.className = 'terminal-line';
    userLine.innerHTML = `<span class="prompt-user">jit_user@kali-prod</span>:<span class="prompt-path">~</span>$ ${escapeHtml(cmd)}`;
    screen.appendChild(userLine);

    try {
        const resp = await fetch('/api/terminal/execute', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ command: cmd, user: 'jit_user', server_id: 'srv_kali_prod' })
        });
        const data = await resp.json();

        const outLine = document.createElement('div');
        outLine.className = 'terminal-line';

        if (data.status === 'BLOCKED') {
            outLine.innerHTML = `<div style="color:#ef4444;background:rgba(239,68,68,0.1);padding:6px;border-left:3px solid #ef4444;margin:4px 0;">${escapeHtml(data.output)}</div>`;
        } else {
            outLine.innerHTML = `<pre style="font-family:inherit;margin:0;color:#f1f5f9;white-space:pre-wrap;">${escapeHtml(data.output)}</pre>`;
        }

        screen.appendChild(outLine);
        screen.scrollTop = screen.scrollHeight;
        loadKPIs();
    } catch (err) {
        const errLine = document.createElement('div');
        errLine.className = 'terminal-line text-crimson';
        errLine.innerText = `Web Shell Connection Error: ${err.message}`;
        screen.appendChild(errLine);
    }
}

function clearWebShell() {
    const screen = document.getElementById('webshell-screen');
    screen.innerHTML = `
        <div class="terminal-line text-cyan">--- ZEROVAULT PAM: IN-BROWSER WEB SHELL READY ---</div>
        <div class="terminal-line text-muted">Connected to Proxy Gateway. Mid-air firewall active on every command.</div>
    `;
}

// --- Feature 5: Database SQL Firewall ---
function setSqlQuery(sql) {
    document.getElementById('sql-query-input').value = sql;
}

async function executeDatabaseQuery() {
    const query = document.getElementById('sql-query-input').value.trim();
    if (!query) return;

    const statusEl = document.getElementById('sql-result-status');
    const thead = document.getElementById('sql-table-head');
    const tbody = document.getElementById('sql-table-body');

    statusEl.className = 'sql-status-box status-ready';
    statusEl.innerText = 'Evaluating query through SQL Firewall...';

    try {
        const resp = await fetch('/api/db/query', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query: query, user: 'dba_analyst', database: 'production_financial_db' })
        });
        const data = await resp.json();

        if (data.status === 'BLOCKED_BY_FIREWALL') {
            statusEl.className = 'sql-status-box status-blocked';
            statusEl.innerHTML = `
                🚫 <strong>QUERY BLOCKED IN MID-AIR BY SQL FIREWALL!</strong><br>
                <strong>Rule ID:</strong> ${escapeHtml(data.rule_id)} (${escapeHtml(data.rule_name)})<br>
                <strong>Violation:</strong> ${escapeHtml(data.description)}<br>
                <em>Statement dropped before execution. Logged to Merkle Audit Ledger &amp; Push alert dispatched.</em>
            `;
            thead.innerHTML = '<tr><th>Status</th><th>Rule Triggered</th></tr>';
            tbody.innerHTML = `<tr><td style="color:#ef4444;font-weight:700;">BLOCKED</td><td>${escapeHtml(data.rule_name)}</td></tr>`;
        } else {
            statusEl.className = 'sql-status-box status-allowed';
            statusEl.innerHTML = `✓ <strong>QUERY VERIFIED &amp; EXECUTED SAFELY</strong> (${data.row_count} rows returned)`;

            // Render columns
            thead.innerHTML = '<tr>' + (data.columns || []).map(c => `<th>${escapeHtml(c)}</th>`).join('') + '</tr>';

            // Render rows
            tbody.innerHTML = '';
            if (!data.rows || data.rows.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" class="text-muted text-center">0 rows returned.</td></tr>';
            } else {
                data.rows.forEach(r => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = (data.columns || []).map(c => `<td>${escapeHtml(r[c])}</td>`).join('');
                    tbody.appendChild(tr);
                });
            }
        }
        loadKPIs();
    } catch (err) {
        statusEl.className = 'sql-status-box status-blocked';
        statusEl.innerText = 'Error: ' + err.message;
    }
}

// --- Feature 3: Phone Buzz & Telegram Settings ---
function openPhoneModal() {
    document.getElementById('phone-modal').style.display = 'flex';
    fetch('/api/notify/config').then(r => r.json()).then(data => {
        if (data.bot_token_set) {
            document.getElementById('telegram-token-input').placeholder = '•••••••••••• (Token configured)';
        }
        if (data.chat_id_set) {
            document.getElementById('telegram-chat-input').placeholder = '•••••••• (Chat ID configured)';
        }
        if (data.webhook_url) {
            document.getElementById('webhook-url-input').value = data.webhook_url;
        }
    });
}

function closePhoneModal() {
    document.getElementById('phone-modal').style.display = 'none';
}

async function saveTelegramConfig() {
    const token = document.getElementById('telegram-token-input').value.trim();
    const chat = document.getElementById('telegram-chat-input').value.trim();
    const webhook = document.getElementById('webhook-url-input').value.trim();

    try {
        const resp = await fetch('/api/notify/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ bot_token: token, chat_id: chat, webhook_url: webhook })
        });
        const res = await resp.json();
        if (resp.ok) {
            alert("Notification credentials (Telegram / Discord Webhook) saved successfully!");
        } else {
            alert("Failed: " + res.error);
        }
    } catch (err) {
        alert("Error: " + err.message);
    }
}

async function testPhoneBuzz() {
    const token = document.getElementById('telegram-token-input').value.trim();
    const chat = document.getElementById('telegram-chat-input').value.trim();
    const webhook = document.getElementById('webhook-url-input').value.trim();

    try {
        const resp = await fetch('/api/notify/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ bot_token: token, chat_id: chat, webhook_url: webhook })
        });
        const res = await resp.json();
        if (res.success) {
            alert("📲 " + res.message);
        } else {
            alert("Test Ping Status:\n\n" + res.message);
        }
    } catch (err) {
        alert("Connection error: " + err.message);
    }
}

// --- Feature 6: Compliance Certificate & Audit Report ---
async function openComplianceModal() {
    try {
        const resp = await fetch('/api/report/compliance');
        if (resp.ok) {
            const cert = await resp.json();
            document.getElementById('cert-id').innerText = cert.certificate_id;
            document.getElementById('cert-date').innerText = `Generated: ${cert.timestamp}`;
            document.getElementById('cert-chain-status').innerText = cert.cryptographic_integrity_proof.status;
            document.getElementById('cert-genesis-hash').innerText = cert.cryptographic_integrity_proof.genesis_block_hash;
            document.getElementById('cert-latest-hash').innerText = cert.cryptographic_integrity_proof.latest_block_hash;
            document.getElementById('cert-total-blocks').innerText = cert.cryptographic_integrity_proof.total_blocks_verified;

            document.getElementById('cert-servers').innerText = cert.summary_metrics.total_servers_protected;
            document.getElementById('cert-leases').innerText = cert.summary_metrics.active_leases_issued;
            document.getElementById('cert-blocked').innerText = cert.summary_metrics.mid_air_attacks_prevented;
            document.getElementById('cert-blocks').innerText = cert.summary_metrics.total_audit_blocks;

            document.getElementById('compliance-modal').style.display = 'flex';
        }
    } catch (err) {
        alert("Failed to load compliance report: " + err.message);
    }
}

function closeComplianceModal() {
    document.getElementById('compliance-modal').style.display = 'none';
}

function printComplianceCertificate() {
    window.print();
}

// --- Reset State ---
async function resetState() {
    if (!confirm("Reset ZeroVault PAM database to clean initial state?")) return;
    try {
        const resp = await fetch('/api/reset', { method: 'POST' });
        if (resp.ok) {
            alert("ZeroVault PAM database reset successfully.");
            initApp();
        }
    } catch (err) {
        alert("Reset failed: " + err.message);
    }
}

// --- Clipboard & Utilities ---
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        alert(`Copied to clipboard:\n${text}`);
    }).catch(err => {
        prompt("Copy SSH command:", text);
    });
}

function formatTime(isoStr) {
    if (!isoStr) return '---';
    try {
        return new Date(isoStr).toLocaleTimeString();
    } catch {
        return isoStr;
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
