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
    btn.disabled = true;
    btn.style.display = 'none';

    document.getElementById('cancelBtn').style.display = 'inline-block';
    document.getElementById('copyBtn').style.display = 'none';

    terminal.innerHTML = '';
    abortController = new AbortController(); // Initialize new controller

    logToTerminal(`[*] Target: ${urlInput}`);
    logToTerminal(`[*] Starting my-tiny-audit v1.1.0 process...`);

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
    const btn = document.getElementById('auditBtn');
    const cancelBtn = document.getElementById('cancelBtn');
    const copyBtn = document.getElementById('copyBtn');
    const statusText = document.getElementById('statusText');

    btn.disabled = false;
    btn.innerText = "開始審計 (Audit)";
    btn.style.display = 'inline-block';

    cancelBtn.style.display = 'none';
    copyBtn.style.display = 'inline-block'; // Show Copy button after scan

    statusText.innerText = "System Idle";
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