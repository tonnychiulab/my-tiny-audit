# My Tiny Audit 🔍

> A pure HTML/JS Client-side Security Auditor.
> 透過純前端技術實現的網站敏感檔案輕量檢測工具。

## 專案簡介 (Introduction)
**my-tiny-audit** 是一個運行在瀏覽器端的資安快篩工具。它不需要安裝 Python 或任何後端伺服器，旨在提供開發者一個快速檢查網站是否暴露敏感檔案（如 `.env`, `.git`）的儀表板。

## 特色 (Features)
* ⚡ **Serverless:** 純靜態網頁，可直接部署於 GitHub Pages。
* 🕵️ **Recon:** 自動掃描常見的敏感路徑 (Sensitive File Enumeration)。
* 🛡️ **CORS Bypass:** 整合 CORS Proxy 技術解決瀏覽器跨域限制。

## 如何使用 (Usage)
1. 下載此專案。
2. 直接用瀏覽器開啟 `index.html`。
3. 輸入目標網址 (包含 `https://`)。
4. 點擊 "開始審計 (Audit)"。

## 技術限制 (Limitations)
* 本工具依賴公共 CORS Proxy，穩定性視第三方服務而定。
* 僅依賴 HTTP Status Code 進行判讀。

## 免責聲明 (Disclaimer)
本工具僅供**資安教育與自我檢測**使用。請勿用於未經授權的目標。
