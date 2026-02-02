// my-tiny-audit v1.0.0 Core
// Author: [Your Name]

const AUDIT_TARGETS = [
    // === 高風險設定檔 ===
    { path: '/.env', desc: 'Environment Variables (Critical)' },
    { path: '/.git/HEAD', desc: 'Git Repository Leak' },
    { path: '/wp-config.php.bak', desc: 'WordPress Config Backup' },
    { path: '/config.json', desc: 'General Configuration' },
    { path: '/web.config', desc: 'IIS Configuration' },
    
    // === 資訊洩露 ===
    { path: '/robots.txt', desc: 'Robots.txt' },
    { path: '/sitemap.xml', desc: 'Sitemap' },
    { path: '/phpinfo.php', desc: 'PHP Info Page' },
    { path: '/.DS_Store', desc: 'macOS Metadata' },
    
    // === 開發/備份 ===
    { path: '/backup.zip', desc: 'Archive Backup' },
    { path: '/sql.dump', desc: 'SQL Dump' },
    { path: '/package.json', desc: 'Node.js Package Info' }
];

// CORS Proxy (開發階段使用，建議未來替換為自建 Worker)
const PROXY_GATEWAY = 'https://corsproxy.io/?';

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

    // UI 重置與鎖定
    btn.disabled = true;
    btn.innerText = "Auditing...";
    terminal.innerHTML = ''; 
    
    logToTerminal(`[*] Target: ${urlInput}`);
    logToTerminal(`[*] Starting my-tiny-audit v1.0.0 process...`);
    logToTerminal(`------------------------------------------------`);

    let risksFound = 0;

    for (let i = 0; i < AUDIT_TARGETS.length; i++) {
        const item = AUDIT_TARGETS[i];
        const targetUrl = urlInput.replace(/\/$/, "") + item.path;
        
        // 進度計算
        const percent = Math.round(((i + 1) / AUDIT_TARGETS.length) * 100);
        progressText.innerText = `${percent}%`;
        statusText.innerText = `Checking: ${item.path}`;

        try {
            // 發送 HEAD 請求
            const response = await fetch(PROXY_GATEWAY + encodeURIComponent(targetUrl), {
                method: 'HEAD',
                cache: 'no-cache'
            });

            if (response.status === 200) {
                risksFound++;
                logToTerminal(`[!] FOUND: ${item.path} - ${item.desc}`, 'text-danger');
            } else if (response.status === 403) {
                logToTerminal(`[-] FORBIDDEN: ${item.path} (Exists but blocked)`, 'text-warning');
            }

        } catch (error) {
            // 忽略網路錯誤 (通常是 Proxy 連線問題或 Timeout)
        }
        
        // 降低請求頻率，避免被 WAF 封鎖
        await new Promise(r => setTimeout(r, 150));
    }

    logToTerminal(`------------------------------------------------`);
    
    if (risksFound === 0) {
        logToTerminal(`[+] Audit Complete. No obvious risks found.`, 'text-success');
    } else {
        logToTerminal(`[!] Audit Complete. ${risksFound} potential risks identified.`, 'text-danger');
    }
    
    btn.disabled = false;
    btn.innerText = "開始審計 (Audit)";
    statusText.innerText = "System Idle";
}

function logToTerminal(message, cssClass = 'text-success') {
    const terminal = document.getElementById('terminalOutput');
    const div = document.createElement('div');
    div.className = `log-line ${cssClass}`;
    div.innerText = message;
    terminal.appendChild(div);
    terminal.scrollTop = terminal.scrollHeight;
}