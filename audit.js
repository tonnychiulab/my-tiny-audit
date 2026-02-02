// my-tiny-audit v1.1.0 Core
// Author: [Your Name]

const AUDIT_TARGETS = [
    // === 高風險設定檔 (需內容驗證) ===
    {
        path: '/.env',
        desc: 'Environment Variables (Critical)',
        signature: /(DB_PASSWORD|APP_KEY|AWS_ACCESS_KEY|ROOT_PASSWORD)/i
    },
    {
        path: '/.git/HEAD',
        desc: 'Git Repository Leak',
        signature: /^ref: refs\//
    },
    {
        path: '/wp-config.php.bak',
        desc: 'WordPress Config Backup',
        signature: /define\(/
    },

    // === 一般設定檔 ===
    { path: '/config.json', desc: 'General Configuration' },
    { path: '/web.config', desc: 'IIS Configuration' },

    // === 資訊洩露 ===
    { path: '/robots.txt', desc: 'Robots.txt' },
    { path: '/sitemap.xml', desc: 'Sitemap' },
    { path: '/phpinfo.php', desc: 'PHP Info Page', signature: /phpinfo\(/ },
    { path: '/.DS_Store', desc: 'macOS Metadata' },

    // === 開發/備份 ===
    { path: '/backup.zip', desc: 'Archive Backup' },
    { path: '/sql.dump', desc: 'SQL Dump', signature: /(INSERT INTO|CREATE TABLE)/i },
    { path: '/package.json', desc: 'Node.js Package Info', signature: /"dependencies":/ }
];

const WP_TARGETS = [
    { path: '/wp-config.php.bak', desc: 'WP Config Backup', signature: /define\(/ },
    { path: '/wp-content/debug.log', desc: 'WP Debug Log', signature: /PHP (Notice|Warning|Fatal|Parse)/ },
    { path: '/wp-content/uploads/dump.sql', desc: 'Uploads SQL Dump', signature: /(INSERT INTO|CREATE TABLE)/i },
    { path: '/wp-content/ai1wm-backups/', desc: 'All-in-One WP Migration', signature: /Index of/i },
    { path: '/wp-content/updraft/', desc: 'UpdraftPlus Backup', signature: /Index of/i },
    { path: '/wp-login.php', desc: 'WP Login Page', signature: /login/i }
];

// CORS Proxy
const PROXY_GATEWAY = 'https://corsproxy.io/?';

let abortController = null;

async function startAudit() {
    const urlInput = document.getElementById('targetUrl').value.trim();
    const btn = document.getElementById('auditBtn');
    const terminal = document.getElementById('terminalOutput');
    const statusText = document.getElementById('statusText');
    const progressText = document.getElementById('progressText');

    if (!urlInput.startsWith('http')) {
        logToTerminal(`[Error] Invalid URL format. Please use http:// or https://`, 'text-danger');
        return;
    }

    // Reset UI
    // Reset UI
    toggleButtons(true);

    terminal.innerHTML = '';
    abortController = new AbortController(); // Initialize new controller

    logToTerminal(`[*] Target: ${urlInput}`);
    logToTerminal(`[*] Starting my-tiny-audit v1.1.0 process...`);

    // 0. Reset & Run Header Analysis
    document.getElementById('headerAnalysis').style.display = 'none';
    analyzeHeaders(urlInput);

    // 1. Check Soft 404
    logToTerminal(`[*] Checking for Soft 404...`);
    const isSoft404 = await checkSoft404(urlInput);

    if (isSoft404) {
        logToTerminal(`[!] WARNING: Target seems to return 200 OK for non-existent files (Soft 404).`, 'text-warning');
        logToTerminal(`[!] Results might be inaccurate. Relying on Content Verification where possible.`, 'text-warning');
    }

    logToTerminal(`------------------------------------------------`);

    let risksFound = 0;

    try {
        for (let i = 0; i < AUDIT_TARGETS.length; i++) {
            if (abortController.signal.aborted) throw new Error('Cancelled');

            const item = AUDIT_TARGETS[i];
            const targetUrl = urlInput.replace(/\/$/, "") + item.path;

            // UI Updates
            const percent = Math.round(((i + 1) / AUDIT_TARGETS.length) * 100);
            progressText.innerText = `${percent}%`;
            statusText.innerText = `Checking: ${item.path}`;

            try {
                // HEAD Request
                const response = await fetch(PROXY_GATEWAY + encodeURIComponent(targetUrl), {
                    method: 'HEAD',
                    signal: abortController.signal
                });

                if (response.status === 200) {
                    if (isSoft404 && !item.signature) {
                        // If Soft 404 and no signature to verify, we treat it as suspicious but maybe false positive
                        logToTerminal(`[?] IGNORED: ${item.path} (Soft 404 detected, no signature to verify)`, 'text-dim');
                    } else if (item.signature) {
                        // Perform Content Verification
                        statusText.innerText = `Verifying: ${item.path}`;
                        const isVerified = await verifyContent(targetUrl, item.signature);
                        if (isVerified) {
                            risksFound++;
                            logToTerminal(`[!] CONFIRMED: ${item.path} - ${item.desc}`, 'text-danger');
                        } else {
                            logToTerminal(`[-] FALSE POSITIVE: ${item.path} (Content mismatch)`, 'text-dim');
                        }
                    } else {
                        // Standard 200 OK (No Soft 404)
                        risksFound++;
                        logToTerminal(`[!] FOUND: ${item.path} - ${item.desc}`, 'text-danger');
                    }
                } else if (response.status === 403) {
                    logToTerminal(`[-] FORBIDDEN: ${item.path} (Exists but blocked)`, 'text-warning');
                }

            } catch (error) {
                if (error.name === 'AbortError') throw error;
                // Ignore other network errors
            }

            // Rate limiting
            await new Promise(r => setTimeout(r, 150));
        }

        logToTerminal(`------------------------------------------------`);

        if (risksFound === 0) {
            logToTerminal(`[+] Audit Complete. No confirmed risks found.`, 'text-success');
        } else {
            logToTerminal(`[!] Audit Complete. ${risksFound} confirmed risks identified.`, 'text-danger');
        }

    } catch (err) {
        if (err.message === 'Cancelled') {
            logToTerminal(`[!] Audit Cancelled by user.`, 'text-warning');
        } else {
            console.error(err);
        }
    } finally {
        resetUI();
    }
}

async function checkSoft404(baseUrl) {
    const randomPath = `/wibble-wobble-${Date.now()}`;
    try {
        const response = await fetch(PROXY_GATEWAY + encodeURIComponent(baseUrl.replace(/\/$/, "") + randomPath), {
            method: 'HEAD',
            signal: abortController.signal
        });
        return response.status === 200;
    } catch (e) {
        return false;
    }
}

async function verifyContent(url, signatureRegex) {
    try {
        const response = await fetch(PROXY_GATEWAY + encodeURIComponent(url), {
            method: 'GET',
            signal: abortController.signal
        });

        // Read only first part of text allows for efficient checking without downloading large files
        // But Response.text() downloads whole body. For "Tiny" audit, this is acceptable.
        // Optimization: clone response, read chunks? simpler to just read text for now.
        const text = await response.text();

        return signatureRegex.test(text.slice(0, 1000)); // Check first 1000 chars
    } catch (e) {
        return false;
    }
}

function resetUI() {
    toggleButtons(false);
    document.getElementById('statusText').innerText = "System Idle";
    abortController = null;
}

function logToTerminal(message, cssClass = 'text-success') {
    const terminal = document.getElementById('terminalOutput');
    const div = document.createElement('div');
    div.className = `log-line ${cssClass}`;
    div.innerText = message;
    terminal.appendChild(div);
    terminal.scrollTop = terminal.scrollHeight;
}

function cancelAudit() {
    if (abortController) {
        abortController.abort();
    }
}

function copyReport() {
    const terminal = document.getElementById('terminalOutput');
    const text = terminal.innerText;
    navigator.clipboard.writeText(text).then(() => {
        alert('Report copied to clipboard!');
    }).catch(err => {
        console.error('Failed to copy text: ', err);
    });
}

// === WordPress Specific Functions ===

async function startWpAudit() {
    const urlInput = document.getElementById('targetUrl').value.trim();

    if (!urlInput.startsWith('http')) {
        logToTerminal(`[Error] Invalid URL format. Please use http:// or https://`, 'text-danger');
        return;
    }

    // Reset UI for WP Scan
    toggleButtons(true);
    const terminal = document.getElementById('terminalOutput');
    terminal.innerHTML = '';
    abortController = new AbortController();

    logToTerminal(`[*] Target: ${urlInput}`);
    logToTerminal(`[*] Starting WordPress Audit...`);

    // 0. Reset & Run Header Analysis
    document.getElementById('headerAnalysis').style.display = 'none';
    analyzeHeaders(urlInput);

    // 1. Detect WordPress
    logToTerminal(`[*] Identifying WordPress...`);
    const isWp = await checkIsWordpress(urlInput);

    if (isWp) {
        logToTerminal(`[+] WordPress DETECTED!`, 'text-success');

        // 2. Detect Version
        const version = await getWpVersion(urlInput);
        if (version) {
            logToTerminal(`[+] Version detected: ${version}`, 'text-success');
        } else {
            logToTerminal(`[?] Version could not be identified.`, 'text-warning');
        }

        // 3. Run WP Specific Targets
        await runAuditLoop(urlInput, WP_TARGETS);

    } else {
        logToTerminal(`[-] WordPress NOT detected. Aborting WP specific scan.`, 'text-warning');
        logToTerminal(`[*] Hint: Try the regular "Audit" for a broader check.`, 'text-dim');
    }

    resetUI();
}

async function checkIsWordpress(baseUrl) {
    try {
        let score = 0;
        logToTerminal(`[debug] Identifying WordPress signals...`, 'text-dim');

        // Method A: Check for wp-login.php (Strong Signal)
        const response = await fetch(PROXY_GATEWAY + encodeURIComponent(baseUrl.replace(/\/$/, "") + '/wp-login.php'), {
            method: 'HEAD',
            signal: abortController.signal
        });

        if (response.status === 200 || response.status === 401 || response.status === 403) {
            logToTerminal(`[debug] /wp-login.php detected (${response.status})`, 'text-dim');
            score += 2;
        }

        // Method B: Check Homepage source (content / meta / links)
        const homeResponse = await fetch(PROXY_GATEWAY + encodeURIComponent(baseUrl), {
            method: 'GET',
            signal: abortController.signal
        });
        const text = await homeResponse.text();

        if (text.includes('wp-content') || text.includes('wp-includes')) {
            logToTerminal(`[debug] Source contains 'wp-content'`, 'text-dim');
            score += 1;
        }

        if (text.includes('/wp-json/')) {
            logToTerminal(`[debug] Source contains 'wp-json' API`, 'text-dim');
            score += 2;
        }

        if (text.match(/<meta name="generator" content="WordPress/i)) {
            logToTerminal(`[debug] Found WordPress Meta Generator`, 'text-dim');
            score += 2;
        }

        // Method C: Check API Endpoint directly (Strong Signal)
        const apiResponse = await fetch(PROXY_GATEWAY + encodeURIComponent(baseUrl.replace(/\/$/, "") + '/wp-json/'), {
            method: 'HEAD',
            signal: abortController.signal
        });
        if (apiResponse.status === 200) {
            logToTerminal(`[debug] /wp-json/ API endpoint accessible`, 'text-dim');
            score += 2;
        }

        if (score >= 2) {
            logToTerminal(`[+] WordPress Confirmed (Score: ${score})`, 'text-success');
            return true;
        }

        return false;
    } catch (e) {
        logToTerminal(`[Error] Detection failed: ${e.message}`, 'text-danger');
        console.error(e);
        return false;
    }
}

async function getWpVersion(baseUrl) {
    try {
        const response = await fetch(PROXY_GATEWAY + encodeURIComponent(baseUrl), {
            method: 'GET',
            signal: abortController.signal
        });
        const text = await response.text();
        const match = text.match(/<meta name="generator" content="WordPress ([0-9.]+)"/i);
        return match ? match[1] : null;
    } catch (e) {
        return null;
    }
}

// Reusable Audit Loop
async function runAuditLoop(baseUrl, targets) {
    const statusText = document.getElementById('statusText');
    const progressText = document.getElementById('progressText');

    let risksFound = 0;

    // Check Soft 404 (Re-use existing logic if possible, or simple check here)
    const isSoft404 = await checkSoft404(baseUrl);

    for (let i = 0; i < targets.length; i++) {
        if (abortController.signal.aborted) return; // Exit if cancelled

        const item = targets[i];
        const targetUrl = baseUrl.replace(/\/$/, "") + item.path;

        const percent = Math.round(((i + 1) / targets.length) * 100);
        progressText.innerText = `${percent}%`;
        statusText.innerText = `Checking: ${item.path}`;

        try {
            const response = await fetch(PROXY_GATEWAY + encodeURIComponent(targetUrl), {
                method: 'HEAD',
                signal: abortController.signal
            });

            if (response.status === 200) {
                if (isSoft404 && !item.signature) {
                    logToTerminal(`[?] IGNORED: ${item.path} (Soft 404)`, 'text-dim');
                } else if (item.signature) {
                    statusText.innerText = `Verifying: ${item.path}`;
                    const isVerified = await verifyContent(targetUrl, item.signature);
                    if (isVerified) {
                        risksFound++;
                        logToTerminal(`[!] CONFIRMED: ${item.path} - ${item.desc}`, 'text-danger');
                    } else {
                        logToTerminal(`[-] FALSE POSITIVE: ${item.path}`, 'text-dim');
                    }
                } else {
                    risksFound++;
                    logToTerminal(`[!] FOUND: ${item.path} - ${item.desc}`, 'text-danger');
                }
            }
        } catch (e) { }

        await new Promise(r => setTimeout(r, 150));
    }

    logToTerminal(`------------------------------------------------`);
    logToTerminal(`[!] Scan Complete. Found ${risksFound} issues.`);
}

function toggleButtons(isScanning) {
    const btn = document.getElementById('auditBtn');
    const wpBtn = document.getElementById('wpAuditBtn');
    const cancelBtn = document.getElementById('cancelBtn');
    const copyBtn = document.getElementById('copyBtn');

    if (isScanning) {
        btn.style.display = 'none';
        wpBtn.style.display = 'none';
        cancelBtn.style.display = 'inline-block';
        copyBtn.style.display = 'none';
    } else {
        btn.style.display = 'inline-block';
        wpBtn.style.display = 'inline-block';
        cancelBtn.style.display = 'none';
        copyBtn.style.display = 'inline-block';
    }
    btn.disabled = isScanning;
    wpBtn.disabled = isScanning;
}

// === Header Analysis Functions ===

async function analyzeHeaders(baseUrl) {
    try {
        const response = await fetch(PROXY_GATEWAY + encodeURIComponent(baseUrl), {
            method: 'HEAD',
            signal: abortController.signal
        });

        const headers = response.headers;
        const results = [];

        // 1. Security Headers (Missing = Bad)
        const securityHeaders = [
            { key: 'strict-transport-security', label: 'HSTS' },
            { key: 'content-security-policy', label: 'CSP' },
            { key: 'x-frame-options', label: 'X-Frame-Options' },
            { key: 'x-content-type-options', label: 'X-Content-Type' },
            { key: 'referrer-policy', label: 'Referrer Policy' }
        ];

        securityHeaders.forEach(item => {
            const val = headers.get(item.key);
            if (val) {
                results.push({ key: item.label, value: 'Present', status: 'good', detail: val });
            } else {
                results.push({ key: item.label, value: 'Missing', status: 'bad' });
            }
        });

        // 2. Information Leakage (Present = Warn/Bad)
        const leakageHeaders = [
            { key: 'server', label: 'Server Software' },
            { key: 'x-powered-by', label: 'X-Powered-By' },
            { key: 'x-aspnet-version', label: 'ASP.NET Ver' }
        ];

        leakageHeaders.forEach(item => {
            const val = headers.get(item.key);
            if (val) {
                results.push({ key: item.label, value: 'Revealed', status: 'warn', detail: val });
            } else {
                results.push({ key: item.label, value: 'Hidden', status: 'good' });
            }
        });

        displayHeaderResults(results);

    } catch (e) {
        console.error("Header Analysis Failed", e);
    }
}

function displayHeaderResults(results) {
    const container = document.getElementById('headerAnalysis');
    const resultsDiv = document.getElementById('headerResults');
    container.style.display = 'block';
    resultsDiv.innerHTML = '';

    results.forEach(item => {
        const row = document.createElement('div');
        row.className = 'header-item';

        let valClass = `header-val-${item.status}`;
        let displayVal = item.value;
        if (item.detail) displayVal += ` (${item.detail})`;

        row.innerHTML = `
            <span class="header-key">${item.key}</span>
            <span class="${valClass}">${displayVal}</span>
        `;
        resultsDiv.appendChild(row);
    });
}