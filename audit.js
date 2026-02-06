// my-tiny-audit v1.3.0 Optimized
// Author: [Your Name]

// ============================================
// 目標檔案清單 (AUDIT_TARGETS)
// ============================================
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

// ============================================
// WordPress 目標檔案清單 (WP_TARGETS)
// ============================================
const WP_TARGETS = [
    { path: '/wp-config.php.bak', desc: 'WP Config Backup', signature: /define\(/ },
    { path: '/wp-content/debug.log', desc: 'WP Debug Log', signature: /PHP (Notice|Warning|Fatal|Parse)/ },
    { path: '/wp-content/uploads/dump.sql', desc: 'Uploads SQL Dump', signature: /(INSERT INTO|CREATE TABLE)/i },
    { path: '/wp-content/ai1wm-backups/', desc: 'All-in-One WP Migration', signature: /Index of/i },
    { path: '/wp-content/updraft/', desc: 'UpdraftPlus Backup', signature: /Index of/i },
    { path: '/wp-login.php', desc: 'WP Login Page', signature: /login/i }
];

// ============================================
// CORS Proxy 設定 (可自行更換)
// ============================================
// 建議：如果 corsproxy.io 失敗，可在此添加其他 proxy
const PROXY_GATEWAYS = [
    'https://corsproxy.io/?',
    'https://api.allorigins.win/raw?url='
];

let proxyIndex = 0;
let abortController = null;

// ============================================
// 公共功能：取得可用的 Proxy
// ============================================
function getProxyUrl(encodedUrl) {
    const proxy = PROXY_GATEWAYS[proxyIndex];
    proxyIndex = (proxyIndex + 1) % PROXY_GATEWAYS.length;
    return proxy + encodedUrl;
}

// ============================================
// 主程式：開始掃描
// ============================================
async function startAudit() {
    const urlInput = document.getElementById('targetUrl').value.trim();
    const btn = document.getElementById('auditBtn');
    const terminal = document.getElementById('terminalOutput');
    const statusText = document.getElementById('statusText');
    const progressText = document.getElementById('progressText');

    // URL 格式驗證
    if (!urlInput.startsWith('http')) {
        logToTerminal(`[Error] 請輸入完整 URL (http:// 或 https://)`, 'text-danger');
        return;
    }

    // 判斷是否為 HTTPS
    const isHttps = urlInput.startsWith('https://');

    // 重置 UI
    resetUI();
    terminal.innerHTML = '';
    abortController = new AbortController();

    logToTerminal(`[*] 目標網站: ${urlInput}`);
    logToTerminal(`[*] 掃描模式: 一般網站`);
    if (isHttps) {
        logToTerminal(`[*] 協議: HTTPS (會檢測安全頭部)`, 'text-dim');
    } else {
        logToTerminal(`[*] 協議: HTTP (跳過安全頭部檢測)`, 'text-dim');
    }

    // 0. 執行標頭分析
    document.getElementById('headerAnalysis').style.display = 'none';
    if (isHttps) {
        analyzeHeaders(urlInput);
    } else {
        logToTerminal(`[!] HTTP 網站不適合檢測安全頭部 (HSTS/CSP 等)`, 'text-dim');
    }

    // 1. 檢查軟體 404
    logToTerminal(`[*] 檢查軟體 404...`);
    const isSoft404 = await checkSoft404(urlInput);

    if (isSoft404) {
        logToTerminal(`[!] 警告: 目標似乎會將不存在路徑返回 200 OK (軟體 404)`, 'text-warning');
        logToTerminal(`[!] 掃描結果可能不準確，內容驗證將被啟用`, 'text-warning');
    }

    logToTerminal(`------------------------------------------------`);

    let risksFound = 0;

    try {
        for (let i = 0; i < AUDIT_TARGETS.length; i++) {
            if (abortController.signal.aborted) throw new Error('已取消');

            const item = AUDIT_TARGETS[i];
            const targetUrl = urlInput.replace(/\/$/, "") + item.path;

            // UI 更新
            const percent = Math.round(((i + 1) / AUDIT_TARGETS.length) * 100);
            progressText.innerText = `${percent}%`;
            statusText.innerText = `正在檢查: ${item.path}`;

            try {
                // 使用 Proxy 請求
                const proxyUrl = getProxyUrl(encodeURIComponent(targetUrl));
                const response = await fetch(proxyUrl, {
                    method: 'HEAD',
                    signal: abortController.signal
                });

                if (response.status === 200) {
                    // 處理軟體 404 情況
                    if (isSoft404 && !item.signature) {
                        // 如果沒有內容簽名驗證，視為可疑但不跳過
                        risksFound++;
                        logToTerminal(`[!] 可疑: ${item.path} - ${item.desc} (需手動確認)`, 'text-warning');
                    } else if (item.signature) {
                        // 執行內容驗證
                        statusText.innerText = `正在驗證: ${item.path}`;
                        const isVerified = await verifyContent(targetUrl, item.signature);
                        if (isVerified) {
                            risksFound++;
                            logToTerminal(`[!] 已確認: ${item.path} - ${item.desc}`, 'text-danger');
                        } else {
                            logToTerminal(`[-] 誤判: ${item.path} - 內容不符`, 'text-dim');
                        }
                    } else {
                        // 正常 200 OK
                        risksFound++;
                        logToTerminal(`[!] 發現: ${item.path} - ${item.desc}`, 'text-danger');
                    }
                } else if (response.status === 403) {
                    logToTerminal(`[-] 拒絕存取: ${item.path} (存在但被阻擋)`, 'text-warning');
                } else {
                    logToTerminal(`[-] 預期狀態 200，實際 ${response.status}: ${item.path}`, 'text-dim');
                }

            } catch (error) {
                // 錯誤處理
                if (error.name === 'AbortError') throw error;
                if (error.message.includes('Failed to fetch')) {
                    logToTerminal(`[!] Proxy 錯誤: ${item.path} - 無法連線`, 'text-warning');
                } else {
                    logToTerminal(`[!] 網路錯誤: ${item.path} - ${error.message}`, 'text-danger');
                }
            }

            // 速率限制 (調整為 100ms，提升效率)
            await new Promise(r => setTimeout(r, 100));
        }

        logToTerminal(`------------------------------------------------`);

        if (risksFound === 0) {
            logToTerminal(`[+] 掃描完成，未發現確認風險`, 'text-success');
        } else {
            logToTerminal(`[!] 掃描完成，發現 ${risksFound} 個確認風險`, 'text-danger');
        }

    } catch (err) {
        if (err.message === '已取消') {
            logToTerminal(`[!] 用戶取消掃描`, 'text-warning');
        } else {
            console.error(err);
            logToTerminal(`[!] 掃描失敗: ${err.message}`, 'text-danger');
        }
    } finally {
        resetUI();
    }
}

// ============================================
// 輔助功能：檢查軟體 404
// ============================================
async function checkSoft404(baseUrl) {
    const randomPath = `/wibble-wobble-${Date.now()}`;
    try {
        const proxyUrl = getProxyUrl(encodeURIComponent(baseUrl.replace(/\/$/, "") + randomPath));
        const response = await fetch(proxyUrl, {
            method: 'HEAD',
            signal: abortController.signal
        });
        return response.status === 200;
    } catch (e) {
        logToTerminal(`[!] 軟體 404 檢測失敗: ${e.message}`, 'text-dim');
        return false;
    }
}

// ============================================
// 輔助功能：驗證內容
// ============================================
async function verifyContent(url, signatureRegex) {
    try {
        const proxyUrl = getProxyUrl(encodeURIComponent(url));
        const response = await fetch(proxyUrl, {
            method: 'GET',
            signal: abortController.signal
        });

        const text = await response.text();
        // 檢查前 2000 字元（提高準確度）
        return signatureRegex.test(text.slice(0, 2000));
    } catch (e) {
        if (e.name === 'AbortError') throw e;
        return false;
    }
}

// ============================================
// UI 重置功能
// ============================================
function resetUI() {
    toggleButtons(false);
    document.getElementById('statusText').innerText = '系統閒置';
    abortController = null;
    proxyIndex = 0;
}

// ============================================
// 終端機輸出
// ============================================
function logToTerminal(message, cssClass = 'text-success') {
    const terminal = document.getElementById('terminalOutput');
    const div = document.createElement('div');
    div.className = `log-line ${cssClass}`;
    div.textContent = message; // 使用 textContent 防止 XSS
    terminal.appendChild(div);
    terminal.scrollTop = terminal.scrollHeight;
}

// ============================================
// 用戶操作：取消
// ============================================
function cancelAudit() {
    if (abortController) {
        abortController.abort();
        logToTerminal(`[!] 正在停止掃描...`, 'text-warning');
    }
}

// ============================================
// 用戶操作：複製報告
// ============================================
function copyReport() {
    const terminal = document.getElementById('terminalOutput');
    const text = terminal.innerText;
    navigator.clipboard.writeText(text).then(() => {
        alert('報告已複製到剪貼簿！');
    }).catch(err => {
        console.error('複製失敗: ', err);
        logToTerminal(`[!] 複製報告失敗`, 'text-danger');
    });
}

// ============================================
// 切換按鈕顯示狀態
// ============================================
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

// ============================================
// WordPress 掃描程式
// ============================================
async function startWpAudit() {
    const urlInput = document.getElementById('targetUrl').value.trim();

    if (!urlInput.startsWith('http')) {
        logToTerminal(`[Error] 請輸入完整 URL (http:// 或 https://)`, 'text-danger');
        return;
    }

    const isHttps = urlInput.startsWith('https://');

    // 重置 UI
    resetUI();
    const terminal = document.getElementById('terminalOutput');
    terminal.innerHTML = '';
    abortController = new AbortController();

    logToTerminal(`[*] 目標網站: ${urlInput}`);
    logToTerminal(`[*] 掃描模式: WordPress`);
    if (isHttps) {
        logToTerminal(`[*] 協議: HTTPS (會檢測安全頭部)`, 'text-dim');
    } else {
        logToTerminal(`[*] 協議: HTTP (跳過安全頭部檢測)`, 'text-dim');
    }

    // 執行標頭分析
    document.getElementById('headerAnalysis').style.display = 'none';
    if (isHttps) {
        analyzeHeaders(urlInput);
    } else {
        logToTerminal(`[!] HTTP 網站不適合檢測安全頭部`, 'text-dim');
    }

    // 1. 檢測 WordPress
    logToTerminal(`[*] 正在識別 WordPress...`);
    const isWp = await checkIsWordpress(urlInput);

    if (isWp) {
        logToTerminal(`[+] WordPress 已識別！`, 'text-success');

        // 2. 檢測版本
        const version = await getWpVersion(urlInput);
        if (version) {
            logToTerminal(`[+] 版本: ${version}`, 'text-success');
        } else {
            logToTerminal(`[?] 無法識別版本`, 'text-warning');
        }

        // 3. 執行 WordPress 專屬掃描
        await runAuditLoop(urlInput, WP_TARGETS);

    } else {
        logToTerminal(`[-] 未檢測到 WordPress，已結束 WP 專屬掃描`, 'text-warning');
        logToTerminal(`[*] 提示：嘗試一般掃描看看`, 'text-dim');
    }

    resetUI();
}

// ============================================
// WordPress：檢測 WordPress 識別
// ============================================
async function checkIsWordpress(baseUrl) {
    try {
        let score = 0;
        logToTerminal(`[debug] 檢測 WordPress 訊號...`, 'text-dim');

        // 方法 A: 檢查 wp-login.php (強訊號)
        const loginUrl = baseUrl.replace(/\/$/, "") + '/wp-login.php';
        try {
            const proxyUrl = getProxyUrl(encodeURIComponent(loginUrl));
            const response = await fetch(proxyUrl, {
                method: 'HEAD',
                signal: abortController.signal
            });

            if (response.status === 200 || response.status === 401 || response.status === 403) {
                logToTerminal(`[debug] 檢測到 /wp-login.php (${response.status})`, 'text-dim');
                score += 2;
            }
        } catch (e) {
            // 忽略登入頁面檢測失敗
        }

        // 方法 B: 檢查首頁來源 (content / meta / links)
        const homeUrl = baseUrl;
        try {
            const homeProxyUrl = getProxyUrl(encodeURIComponent(homeUrl));
            const homeResponse = await fetch(homeProxyUrl, {
                method: 'GET',
                signal: abortController.signal
            });
            const text = await homeResponse.text();

            if (text.includes('wp-content') || text.includes('wp-includes')) {
                logToTerminal(`[debug] 來源包含 'wp-content'`, 'text-dim');
                score += 1;
            }

            if (text.includes('/wp-json/')) {
                logToTerminal(`[debug] 來源包含 'wp-json' API`, 'text-dim');
                score += 2;
            }

            if (text.match(/<meta name="generator" content="WordPress/i)) {
                logToTerminal(`[debug] 檢測到 WordPress Meta Generator`, 'text-dim');
                score += 2;
            }
        } catch (e) {
            // 忽略首頁檢測失敗
        }

        // 方法 C: 檢查 API 端點 (強訊號)
        const apiUrl = baseUrl.replace(/\/$/, "") + '/wp-json/';
        try {
            const apiProxyUrl = getProxyUrl(encodeURIComponent(apiUrl));
            const apiResponse = await fetch(apiProxyUrl, {
                method: 'HEAD',
                signal: abortController.signal
            });
            if (apiResponse.status === 200) {
                logToTerminal(`[debug] /wp-json/ API 端點可存取`, 'text-dim');
                score += 2;
            }
        } catch (e) {
            // 忽略 API 檢測失敗
        }

        if (score >= 2) {
            logToTerminal(`[+] WordPress 已確認 (得分: ${score})`, 'text-success');
            return true;
        }

        return false;
    } catch (e) {
        logToTerminal(`[Error] 檢測失敗: ${e.message}`, 'text-danger');
        console.error(e);
        return false;
    }
}

// ============================================
// WordPress：取得版本
// ============================================
async function getWpVersion(baseUrl) {
    try {
        const proxyUrl = getProxyUrl(encodeURIComponent(baseUrl));
        const response = await fetch(proxyUrl, {
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

// ============================================
// 公共：執行掃描迴圈
// ============================================
async function runAuditLoop(baseUrl, targets) {
    const statusText = document.getElementById('statusText');
    const progressText = document.getElementById('progressText');

    let risksFound = 0;

    // 檢查軟體 404
    const isSoft404 = await checkSoft404(baseUrl);

    for (let i = 0; i < targets.length; i++) {
        if (abortController.signal.aborted) return;

        const item = targets[i];
        const targetUrl = baseUrl.replace(/\/$/, "") + item.path;

        const percent = Math.round(((i + 1) / targets.length) * 100);
        progressText.innerText = `${percent}%`;
        statusText.innerText = `正在檢查: ${item.path}`;

        try {
            const proxyUrl = getProxyUrl(encodeURIComponent(targetUrl));
            const response = await fetch(proxyUrl, {
                method: 'HEAD',
                signal: abortController.signal
            });

            if (response.status === 200) {
                if (isSoft404 && !item.signature) {
                    risksFound++;
                    logToTerminal(`[!] 可疑: ${item.path} - ${item.desc}`, 'text-warning');
                } else if (item.signature) {
                    statusText.innerText = `正在驗證: ${item.path}`;
                    const isVerified = await verifyContent(targetUrl, item.signature);
                    if (isVerified) {
                        risksFound++;
                        logToTerminal(`[!] 已確認: ${item.path} - ${item.desc}`, 'text-danger');
                    } else {
                        logToTerminal(`[-] 誤判: ${item.path}`, 'text-dim');
                    }
                } else {
                    risksFound++;
                    logToTerminal(`[!] 發現: ${item.path} - ${item.desc}`, 'text-danger');
                }
            }
        } catch (e) {
            // 錯誤處理
            if (e.name === 'AbortError') return;
            if (e.message.includes('Failed to fetch')) {
                logToTerminal(`[!] Proxy 錯誤: ${item.path}`, 'text-warning');
            }
        }

        await new Promise(r => setTimeout(r, 100));
    }

    logToTerminal(`------------------------------------------------`);
    logToTerminal(`[!] 掃描完成，發現 ${risksFound} 個問題`);
}

// ============================================
// 標頭分析程式
// ============================================
async function analyzeHeaders(baseUrl) {
    try {
        const proxyUrl = getProxyUrl(encodeURIComponent(baseUrl));
        const response = await fetch(proxyUrl, {
            method: 'HEAD',
            signal: abortController.signal
        });

        const headers = response.headers;
        const results = [];

        // 1. 安全性頭部 (缺失 = 不良)
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
                results.push({ key: item.label, value: '已設定', status: 'good', detail: val });
            } else {
                results.push({ key: item.label, value: '未設定', status: 'bad' });
            }
        });

        // 2. 資訊洩露 (存在 = 警告/不良)
        const leakageHeaders = [
            { key: 'server', label: '伺服器軟體' },
            { key: 'x-powered-by', label: 'X-Powered-By' },
            { key: 'x-aspnet-version', label: 'ASP.NET 版本' }
        ];

        leakageHeaders.forEach(item => {
            const val = headers.get(item.key);
            if (val) {
                results.push({ key: item.label, value: '已洩露', status: 'warn', detail: val });
            } else {
                results.push({ key: item.label, value: '已隱藏', status: 'good' });
            }
        });

        displayHeaderResults(results);

    } catch (e) {
        console.error("Header Analysis Failed", e);
        logToTerminal(`[!] 標頭分析失敗: ${e.message}`, 'text-danger');
    }
}

// ============================================
// 顯示標頭分析結果
// ============================================
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
