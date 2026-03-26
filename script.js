// ==UserScript==
// @name         Advanced Security Recon v3.1 - Full Source Analyzer 
// @namespace    http://tampermonkey.net/
// @version      3.1
// @description  Complete source code analysis - case-insensitive keyword search for admin, USER_ROLE, API_KEYS, etc.
// @author       Nam3l3ss
// @match        *://*/*
// @grant        GM_log
// @grant        GM_notification
// @grant        GM_xmlhttpRequest
// @grant        GM_getValue
// @grant        GM_setValue
// @run-at       document-start
// @noframes
// ==/UserScript==

(function() {
    'use strict';
    
    const CONFIG = {
        stealthMode: false,
        autoHidePanel: false,
        minPanelOpacity: 0.9,
        scanDelay: 2000,
        throttleRequests: 500,
        maxRequests: 10,
        analyzeJSFiles: true,
        maxJSSize: 5 * 1024 * 1024,
        ignoreDomains: ['google-analytics.com', 'doubleclick.net', 'googletagmanager.com'],
        stealth: {
            randomizeDelay: true,
            minDelay: 1000,
            maxDelay: 5000,
            randomUserAgent: false,
            silentMode: false,
            hidePanelOnIdle: false,
            idleTimeout: 30000,
            encryptLogs: false,
            antiDetection: true,
            randomizeRequestOrder: true,
            simulateHumanBehavior: true
        },
        keywords: [
            'admin', 'super_admin', 'superadmin', 'sysadmin', 'system_admin',
            'role', 'user_role', 'userrole', 'user_roles', 'userroles',
            'register', 'registration', 'signup',
            'moderator', 'moderators', 'editor', 'editors',
            'permission', 'permissions', 'privilege', 'privileges',
            'authorization', 'auth', 'authenticate', 'authentication',
            'id', 'name', 'role', 'first_name', 'last_name', 'username',
            'user_id', 'user_name', 'user_role', 'email', 'phone',
            'profile', 'account', 'member', 'employee', 'staff',
            'root', 'sudo', 'superuser', 'super_user', 'administrator',
            'dashboard', 'control_panel', 'controlpanel', 'cpanel',
            'webadmin', 'web_admin', 'admin_panel', 'adminpanel',
            'database', 'db_user', 'db_password', 'dbpass', 'dbname',
            'connection_string', 'connectionstring', 'mongodb_uri', 'mysql',
            'postgresql', 'redis_url', 'redisurl', 'database_url',
            'secret', 'secrets', 'api_key', 'apikey', 'api_secret', 'apisecret',
            'access_token', 'accesstoken', 'refresh_token', 'refreshtoken',
            'private_key', 'privatekey', 'public_key', 'publickey',
            'certificate', 'pem', 'key', 'keys', 'token', 'tokens',
            'jwt_secret', 'jwtsecret', 'session_secret', 'cookie_secret',
            'encryption_key', 'encryptionkey', 'crypto_key', 'cryptokey',
            'smtp', 'mailer', 'email_password', 'emailpassword',
            'sendgrid', 'mailgun', 'aws_access_key', 'aws_secret',
            's3_bucket', 's3bucket', 'azure_key', 'azurekey',
            'stripe_key', 'stripekey', 'paypal_key', 'paypalkey',
            'merchant_id', 'merchantid', 'oauth_secret', 'oauthsecret',
            'firebase', 'firebase_config', 'firebaseconfig',
            'debug', 'test_mode', 'development', 'staging', 'production',
            'dev_mode', 'debug_mode', 'verbose', 'logging', 'log_level',
            'backdoor', 'shell', 'exec', 'eval', 'system_call', 'systemcall',
            'passthru', 'popen', 'proc_open', 'shell_exec',
            'swagger', 'api_docs', 'apidocs', 'redoc', 'graphql', 'rest_api',
            'restapi','swagger-ui/index.html','swagger-ui.html','swagger-ui','api','openapi','api/docs','api-docs','api_spec','apispec',
            'user_id', 'uid', 'admin_id', 'adminid', 'role_id', 'roleid',
            'permission_id', 'permissionid', 'user_role_id', 'userroleid'
        ],
        apiPatterns: [
            /\/api(?:\/v\d+)?\/[^\s"',<>(){}]+/gi,
            /\/(graphql|rest|rpc|admin|debug|swagger|docs|redoc)[^\s"',<>(){}]+/gi,
            /\/v\d+\/[^\s"',<>(){}]+/gi,
            /\/oauth(?:2)?\/[^\s"',<>(){}]+/gi,
            /\/auth\/[^\s"',<>(){}]+/gi,
            /\/user(?:s)?\/[^\s"',<>(){}]+/gi,
            /\/role(?:s)?\/[^\s"',<>(){}]+/gi,
            /\/admin(?:s)?\/[^\s"',<>(){}]+/gi,
            /\/(service|microservice|api-gateway|gateway)\/[^\s"',<>(){}]+/gi,
            /\/(internal|private|external)\/(api|service)\/[^\s"',<>(){}]+/gi,
            /\/(health|status|ping|ready|alive)\/[^\s"',<>(){}]+/gi,
            /\/(metrics|prometheus|monitoring|telemetry)\/[^\s"',<>(){}]+/gi,
            /\/(config|configuration|settings)\/[^\s"',<>(){}]+/gi,
            /\/(aws|azure|gcp|firebase)\/[^\s"',<>(){}]+/gi,
            /\/(lambda|function|serverless)\/[^\s"',<>(){}]+/gi,
            /\/(storage|bucket|cdn|asset)\/[^\s"',<>(){}]+/gi,
            /\/(next|nuxt|remix)\/(api|route)\/[^\s"',<>(){}]+/gi,
            /\/(app|web|client)\/(api|v\d+)\/[^\s"',<>(){}]+/gi,
            /\/_next\/api\/[^\s"',<>(){}]+/gi,
            /\/__webpack?__\/[^\s"',<>(){}]+/gi,
            /\/(db|database|cache|redis|mongo)\/[^\s"',<>(){}]+/gi,
            /\/(query|mutation|subscription)\/[^\s"',<>(){}]+/gi,
            /\/(login|logout|signin|signup|register)\/[^\s"',<>(){}]+/gi,
            /\/(token|jwt|session|cookie)\/[^\s"',<>(){}]+/gi,
            /\/(2fa|mfa|totp|verification)\/[^\s"',<>(){}]+/gi,
            /\/(upload|download|file|media|image|document)\/[^\s"',<>(){}]+/gi,
            /\/(static|assets|public|resources)\/[^\s"',<>(){}]+/gi,
            /\/(manage|management|control|panel|dashboard)\/[^\s"',<>(){}]+/gi,
            /\/(settings|config|preferences|profile)\/[^\s"',<>(){}]+/gi,
            /\/(payment|checkout|order|cart|billing)\/[^\s"',<>(){}]+/gi,
            /\/(stripe|paypal|square|braintree)\/[^\s"',<>(){}]+/gi,
            /\/(chat|message|notification|feed|social)\/[^\s"',<>(){}]+/gi,
            /\/(friend|follow|like|share|comment)\/[^\s"',<>(){}]+/gi,
            /\/(analytics|tracking|pixel|event|log)\/[^\s"',<>(){}]+/gi,
            /\/(beacon|telemetry|insight|report)\/[^\s"',<>(){}]+/gi
        ],
        sensitivePatterns: [
            { regex: /(?:api[_-]?key|apikey|api_key)\s*[:=]\s*['"]?([A-Za-z0-9+/]{20,})['"]?/gi, type: 'API Key' },
            { regex: /sk-[a-zA-Z0-9]{48}/gi, type: 'OpenAI Secret Key' },
            { regex: /AKIA[0-9A-Z]{16}/gi, type: 'AWS Access Key' },
            { regex: /ghp_[0-9a-zA-Z]{36}/gi, type: 'GitHub Personal Token' },
            { regex: /gho_[0-9a-zA-Z]{36}/gi, type: 'GitHub OAuth Token' },
            { regex: /eyJ[A-Za-z0-9-_]+?\.eyJ[A-Za-z0-9-_]+?\./g, type: 'JWT Token' },
            { regex: /-----BEGIN (?:RSA|PRIVATE|OPENSSH) KEY-----[\s\S]+?-----END (?:RSA|PRIVATE|OPENSSH) KEY-----/gi, type: 'Private Key' },
            { regex: /(?:mongodb|mysql|postgresql):\/\/[^\s"',<>]+/gi, type: 'Database URL' },
            { regex: /redis:\/\/[^\s"',<>]+/gi, type: 'Redis URL' },
            { regex: /(?:smtp|mail):\/\/[^\s"',<>]+/gi, type: 'SMTP URL' },
            { regex: /[a-zA-Z0-9._%+-]+@(?!gmail\.com|yahoo\.com|hotmail\.com|outlook\.com|aol\.com|icloud\.com)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, type: 'Email Address' },
            { regex: /password\s*[:=]\s*['"]([^'"]{8,})['"]/gi, type: 'Password' },
            { regex: /secret\s*[:=]\s*['"]([^'"]{8,})['"]/gi, type: 'Secret' },
            { regex: /token\s*[:=]\s*['"]([A-Za-z0-9+/]{20,})['"]/gi, type: 'Token' },
            { regex: /(?:stripe|paypal|braintree)_(?:key|secret)\s*[:=]\s*['"]([^'"]+)['"]/gi, type: 'Payment Key' },
            { regex: /jwt_secret\s*[:=]\s*['"]([^'"]+)['"]/gi, type: 'JWT Secret' },
            { regex: /session_secret\s*[:=]\s*['"]([^'"]+)['"]/gi, type: 'Session Secret' },
            { regex: /db_password\s*[:=]\s*['"]([^'"]+)['"]/gi, type: 'Database Password' },
            { regex: /user_role\s*[:=]\s*['"]([^'"]+)['"]/gi, type: 'User Role Assignment' }
        ],
        rolePatterns: [
            /role\s*[:=]\s*['"]([^'"]+)['"]/gi,
            /user_role\s*[:=]\s*['"]([^'"]+)['"]/gi,
            /userrole\s*[:=]\s*['"]([^'"]+)['"]/gi,
            /is_admin\s*[:=]\s*(?:true|false)/gi,
            /is_super_admin\s*[:=]\s*(?:true|false)/gi,
            /is_moderator\s*[:=]\s*(?:true|false)/gi,
            /permissions\s*[:=]\s*\[[^\]]+\]/gi,
            /privileges\s*[:=]\s*\[[^\]]+\]/gi,
            /USER_ROLE\s*[:=]\s*['"]([^'"]+)['"]/gi,
            /ROLE\s*[:=]\s*['"]([^'"]+)['"]/gi
        ]
    };
    
    const findings = {
        endpoints: new Set(),
        sensitiveData: [],
        jsFiles: new Map(),
        adminContent: new Map(),
        rolesFound: new Set(),
        swaggerUrls: new Set(),
        emails: new Set(),
        hardcodedSecrets: [],
        keywordMatches: new Map()
    };
    
    class ReconPanel {
        constructor() {
            this.panel = null;
            this.content = null;
            this.resultsPanel = null;
            this.isExpanded = false;
            this.findingsCount = 0;
        }
        
        create() {
            if (this.panel) return;
            
            this.panel = document.createElement('div');
            this.panel.id = 'recon-panel';
            this.panel.innerHTML = `
                <div style="
                    position: fixed;
                    bottom: 20px;
                    right: 20px;
                    width: auto;
                    min-width: 300px;
                    background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
                    color: #00ff9d;
                    font-family: 'Fira Code', 'Courier New', monospace;
                    font-size: 12px;
                    border: 1px solid rgba(0, 255, 157, 0.4);
                    border-radius: 12px;
                    padding: 0;
                    z-index: 2147483647;
                    backdrop-filter: blur(10px);
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4), 0 0 20px rgba(0, 255, 157, 0.1);
                    transition: all 0.3s ease;
                    overflow: hidden;
                ">
                    <div style="
                        background: rgba(0, 255, 157, 0.1);
                        padding: 12px 15px;
                        cursor: pointer;
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        border-bottom: 1px solid rgba(0, 255, 157, 0.3);
                        transition: all 0.2s;
                    " id="panel-header">
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <span style="font-size: 18px;">*</span>
                            <span style="font-weight: bold; letter-spacing: 0.5px;">SECURITY RECON </span>
                            <span id="badge-count" style="
                                background: #ff4444;
                                color: white;
                                border-radius: 10px;
                                padding: 2px 8px;
                                font-size: 10px;
                                font-weight: bold;
                            ">0</span>
                        </div>
                        <div style="display: flex; gap: 8px;">
                            <button id="expand-results" style="
                                background: rgba(0, 255, 157, 0.2);
                                border: 1px solid #00ff9d;
                                color: #00ff9d;
                                padding: 4px 10px;
                                border-radius: 6px;
                                cursor: pointer;
                                font-size: 11px;
                                transition: all 0.2s;
                            ">RESULTS</button>
                            <button id="cancel-scan" style="
                                background: rgba(255, 68, 68, 0.2);
                                border: 1px solid #ff4444;
                                color: #ff8888;
                                padding: 4px 10px;
                                border-radius: 6px;
                                cursor: pointer;
                                font-size: 11px;
                                transition: all 0.2s;
                            ">CANCEL</button>
                        </div>
                    </div>
                    <div id="scan-status" style="
                        padding: 10px 15px;
                        font-size: 11px;
                        color: #888;
                        border-bottom: 1px solid rgba(255,255,255,0.05);
                    ">
                        Initializing scan...
                    </div>
                    <div id="results-container" style="
                        max-height: 0;
                        overflow-y: auto;
                        transition: max-height 0.4s ease-out;
                        background: rgba(0, 0, 0, 0.5);
                    ">
                        <div id="results-content" style="padding: 15px;"></div>
                    </div>
                </div>
            `;
            
            document.body.appendChild(this.panel);
            this.content = this.panel.querySelector('#results-content');
            this.resultsContainer = this.panel.querySelector('#results-container');
            
            this.panel.querySelector('#expand-results').onclick = () => this.toggleResults();
            this.panel.querySelector('#cancel-scan').onclick = () => this.destroy();
            
            this.updateBadge(0);
        }
        
        toggleResults() {
            this.isExpanded = !this.isExpanded;
            const button = this.panel.querySelector('#expand-results');
            if (this.isExpanded) {
                this.resultsContainer.style.maxHeight = '500px';
                button.textContent = 'HIDE RESULTS';
                this.renderResults();
            } else {
                this.resultsContainer.style.maxHeight = '0';
                button.textContent = 'RESULTS';
            }
        }
        
        updateStatus(message, isError = false) {
            const statusDiv = this.panel.querySelector('#scan-status');
            if (statusDiv) {
                statusDiv.innerHTML = `${isError ? '!' : '*'} ${message}`;
                statusDiv.style.color = isError ? '#ff8888' : '#88ff88';
            }
        }
        
        updateBadge(count) {
            const badge = this.panel.querySelector('#badge-count');
            if (badge) {
                badge.textContent = count;
                badge.style.background = count > 0 ? '#ff4444' : '#666';
            }
            this.findingsCount = count;
        }
        
        // incrementBadge=true  → used during live scan to count findings as they arrive
        // incrementBadge=false → used by renderResults() so re-opening the panel doesn't inflate the counter
        addFinding(category, title, details, severity = 'info', incrementBadge = true) {
            const severityColors = {
                critical: '#ff4444',
                high: '#ff8844',
                medium: '#ffaa44',
                low: '#88ff88',
                info: '#44aaff'
            };
            
            const tempDiv = document.createElement('div');
            tempDiv.innerHTML = `
                <div style="
                    margin: 8px 0;
                    padding: 10px;
                    background: rgba(0, 0, 0, 0.4);
                    border-left: 3px solid ${severityColors[severity] || '#44aaff'};
                    border-radius: 6px;
                    font-size: 11px;
                ">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                        <strong style="color: ${severityColors[severity]}">[${category}]</strong>
                        <span style="color: #888; font-size: 10px;">${new Date().toLocaleTimeString()}</span>
                    </div>
                    <div style="color: #fff; margin-bottom: 5px;">${this.escapeHtml(title)}</div>
                    <details style="margin-top: 5px;">
                        <summary style="color: #00ff9d; cursor: pointer; font-size: 10px;">▼ Show details</summary>
                        <pre style="
                            background: rgba(0,0,0,0.6);
                            padding: 8px;
                            margin-top: 5px;
                            border-radius: 4px;
                            overflow-x: auto;
                            font-size: 10px;
                            color: #88ff88;
                            white-space: pre-wrap;
                            word-wrap: break-word;
                            max-height: 300px;
                            overflow-y: auto;
                        ">${this.escapeHtml(details)}</pre>
                    </details>
                </div>
            `;

            // ✅ FIX: firstElementChild skips the leading whitespace text node
            //    that innerHTML produces before the <div>, so the card is now
            //    actually appended and becomes visible in the panel.
            this.content.appendChild(tempDiv.firstElementChild);

            if (incrementBadge) {
                this.updateBadge(this.findingsCount + 1);
            }
            
            if (this.isExpanded) {
                this.resultsContainer.scrollTop = this.resultsContainer.scrollHeight;
            }
        }
        
        renderResults() {
            this.content.innerHTML = '';
            
            if (!findings) {
                this.addFinding('ERROR', 'No findings data available', 'The scan may not have completed properly.', 'critical', false);
                return;
            }
            
            const totalFindings = (findings.endpoints?.size || 0) + (findings.sensitiveData?.length || 0) + 
                                  (findings.adminContent?.size || 0) + (findings.keywordMatches?.size || 0);
            
            this.addFinding('SUMMARY', 'Scan Complete', `Total Findings: ${totalFindings}
├─ API Endpoints: ${findings.endpoints?.size || 0}
├─ Sensitive Data: ${findings.sensitiveData?.length || 0}
├─ Admin/Role Keywords: ${findings.keywordMatches?.size || 0}
├─ Emails Found: ${findings.emails?.size || 0}
├─ Hardcoded Secrets: ${findings.hardcodedSecrets?.length || 0}
└─ User Roles Found: ${findings.rolesFound?.size || 0}`, 'info', false);
            
            if (findings.endpoints?.size > 0) {
                const endpointArray = Array.from(findings.endpoints);
                this.addFinding('ENDPOINTS', `${findings.endpoints.size} API Endpoints Found`, 
                    endpointArray.slice(0, 20).join('\n') + 
                    (findings.endpoints.size > 20 ? `\n... and ${findings.endpoints.size - 20} more` : ''), 
                    'high', false
                );
            }
            
            if (findings.sensitiveData?.length > 0) {
                const sensitiveArray = findings.sensitiveData.slice(0, 15);
                this.addFinding('SENSITIVE DATA', `${findings.sensitiveData.length} Items Found`,
                    sensitiveArray.map(d => `${d.type}: ${d.value}`).join('\n'),
                    'critical', false
                );
            }
            
            if (findings.keywordMatches?.size > 0) {
                const keywordArray = Array.from(findings.keywordMatches.keys());
                this.addFinding('ADMIN/ROLE KEYWORDS', `${findings.keywordMatches.size} Keywords Found`,
                    keywordArray.slice(0, 20).join('\n'),
                    'high', false
                );
            }
            
            if (findings.emails?.size > 0) {
                const emailArray = Array.from(findings.emails);
                this.addFinding('EMAILS', `${findings.emails.size} Email Addresses Found`,
                    emailArray.slice(0, 15).join('\n'),
                    'medium', false
                );
            }
            
            if (findings.swaggerUrls?.size > 0) {
                const swaggerArray = Array.from(findings.swaggerUrls);
                this.addFinding('API DOCS', 'Swagger/OpenAPI Endpoints',
                    swaggerArray.join('\n'),
                    'high', false
                );
            }
            
            if (findings.hardcodedSecrets?.length > 0) {
                const secretsArray = findings.hardcodedSecrets.slice(0, 10);
                this.addFinding('HARDCODED SECRETS', `${findings.hardcodedSecrets.length} Secrets Found`,
                    secretsArray.map(s => `${s.type}: ${s.value}`).join('\n'),
                    'critical', false
                );
            }

            if (totalFindings === 0 && (findings.emails?.size || 0) === 0 &&
                (findings.swaggerUrls?.size || 0) === 0 && (findings.hardcodedSecrets?.length || 0) === 0) {
                this.addFinding('INFO', 'No findings yet',
                    'Scan may still be in progress, or nothing was detected on this page.',
                    'info', false);
            }
        }
        
        escapeHtml(str) {
            if (!str) return '';
            return str.replace(/[&<>]/g, function(m) {
                if (m === '&') return '&amp;';
                if (m === '<') return '&lt;';
                if (m === '>') return '&gt;';
                return m;
            }).substring(0, 3000);
        }
        
        destroy() {
            if (this.panel) this.panel.remove();
        }
    }
    
    const panel = new ReconPanel();
    
    function getRandomDelay() {
        if (CONFIG.stealth.randomizeDelay) {
            return Math.random() * (CONFIG.stealth.maxDelay - CONFIG.stealth.minDelay) + CONFIG.stealth.minDelay;
        }
        return CONFIG.scanDelay;
    }
    
    function simulateHumanBehavior() {
        if (CONFIG.stealth.simulateHumanBehavior) {
            return Math.random() * 100 + 50;
        }
        return 0;
    }
    
    function antiDetection() {
        if (CONFIG.stealth.antiDetection) {
            if (Math.random() < 0.1) console.clear();
            return Math.random() * 200;
        }
        return 0;
    }
    
    function searchKeywordsCaseInsensitive(content, sourceUrl) {
        CONFIG.keywords.forEach(keyword => {
            const regex = new RegExp(`\\b${keyword}\\b`, 'gi');
            let match;
            let matchCount = 0;
            while ((match = regex.exec(content)) !== null) {
                matchCount++;
                const start = Math.max(0, match.index - 80);
                const end = Math.min(content.length, match.index + 120);
                let context = content.substring(start, end).replace(/\n/g, ' ').trim();
                if (!findings.keywordMatches.has(keyword)) findings.keywordMatches.set(keyword, []);
                findings.keywordMatches.get(keyword).push(context);
                findings.adminContent.set(`${keyword.toUpperCase()} found in ${sourceUrl.split('/').pop()}: ${context.substring(0, 150)}`, true);
            }
            if (matchCount > 0) console.log(`[CASE-INSENSITIVE] Found "${keyword}" (${matchCount}x) in ${sourceUrl}`);
        });
    }
    
    async function fetchAndAnalyzeJS(url) {
        if (findings.jsFiles.has(url)) return;
        return new Promise((resolve) => {
            GM_xmlhttpRequest({
                method: 'GET', url, timeout: 10000,
                onload: function(response) {
                    if (response.status === 200 && response.responseText) {
                        const content = response.responseText;
                        if (content.length > CONFIG.maxJSSize) { panel.updateStatus(`Skipping large JS: ${url.substring(0, 80)}...`); resolve(); return; }
                        findings.jsFiles.set(url, { size: content.length, analyzed: true });
                        panel.updateStatus(`Analyzing: ${url.split('/').pop()}`);
                        analyzeJSContent(content, url);
                    }
                    resolve();
                },
                onerror: () => resolve()
            });
        });
    }
    
    function analyzeJSContent(content, sourceUrl) {
        searchKeywordsCaseInsensitive(content, sourceUrl);
        CONFIG.apiPatterns.forEach(pattern => { let m; while ((m = pattern.exec(content)) !== null) findings.endpoints.add(m[0]); });
        const swaggerPatterns = [/swagger/gi, /openapi/gi, /api-docs/gi, /redoc/gi];
        swaggerPatterns.forEach(pattern => {
            if (pattern.test(content)) {
                const matches = content.match(/["'](\/[^"']*(?:swagger|openapi|api-docs)[^"']*)["']/gi);
                if (matches) matches.forEach(m => { const u = m.replace(/["']/g, ''); findings.swaggerUrls.add(u); findings.endpoints.add(u); });
            }
        });
        CONFIG.sensitivePatterns.forEach(({regex, type}) => {
            let match;
            while ((match = regex.exec(content)) !== null) {
                const value = match[1] || match[0];
                findings.sensitiveData.push({ type, value: value.substring(0, 100), source: sourceUrl, full: value });
                if (type === 'Email Address') findings.emails.add(value);
                if (type.includes('Key') || type.includes('Token') || type.includes('Secret'))
                    findings.hardcodedSecrets.push({ type, value: value.substring(0, 50), source: sourceUrl });
            }
        });
        const rolePatterns = [/role\s*[:=]\s*['"]([^'"]+)['"]/gi, /user_role\s*[:=]\s*['"]([^'"]+)['"]/gi, /is_admin\s*[:=]\s*(true|false)/gi];
        rolePatterns.forEach(pattern => { let m; while ((m = pattern.exec(content)) !== null) findings.rolesFound.add(m[1] || m[0]); });
    }
    
    function extractJSFiles() {
        const jsUrls = new Set();
        document.querySelectorAll('script[src]').forEach(script => {
            let src = script.src;
            if (src && !CONFIG.ignoreDomains.some(d => src.includes(d))) {
                if (src.startsWith('/')) src = window.location.origin + src;
                else if (src.startsWith('./')) src = window.location.href + src.substring(1);
                else if (!src.startsWith('http')) src = window.location.origin + '/' + src;
                jsUrls.add(src);
            }
        });
        const pageContent = document.documentElement.innerHTML;
        [/src=["']([^"']*\.js[^"']*)["']/g, /href=["']([^"']*\.js[^"']*)["']/g].forEach(pattern => {
            let m;
            while ((m = pattern.exec(pageContent)) !== null) {
                let url = m[1];
                if (url && !url.includes('data:') && !CONFIG.ignoreDomains.some(d => url.includes(d))) {
                    if (url.startsWith('/')) url = window.location.origin + url;
                    else if (!url.startsWith('http')) url = window.location.origin + '/' + url;
                    jsUrls.add(url);
                }
            }
        });
        return jsUrls;
    }
    
    function analyzeDOM() {
        panel.updateStatus('Analyzing DOM structure...');
        const htmlContent = document.documentElement.innerHTML;
        CONFIG.keywords.forEach(keyword => {
            const regex = new RegExp(`${keyword}[^<]*`, 'gi');
            let m;
            while ((m = regex.exec(htmlContent)) !== null)
                findings.adminContent.set(`${keyword.toUpperCase()} in HTML: ${m[0].substring(0, 150)}...`, true);
        });
        const emailPattern = /[a-zA-Z0-9._%+-]+@(?!gmail\.com|yahoo\.com|hotmail\.com|outlook\.com|aol\.com|icloud\.com)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
        let m;
        while ((m = emailPattern.exec(htmlContent)) !== null) {
            findings.emails.add(m[0]);
            findings.sensitiveData.push({ type: 'Email Address', value: m[0], source: 'HTML DOM' });
        }
        document.querySelectorAll('meta[name*="api"], meta[name*="key"], meta[content*="token"]').forEach(tag =>
            findings.sensitiveData.push({ type: 'Meta Tag', value: `${tag.getAttribute('name')}=${tag.getAttribute('content')}`, source: 'HTML Meta' }));
        document.querySelectorAll('input[type="hidden"]').forEach(input => {
            if (input.value && input.value.length > 10)
                findings.sensitiveData.push({ type: 'Hidden Input', value: `${input.name}=${input.value.substring(0, 100)}`, source: 'DOM Hidden Field' });
        });
        document.querySelectorAll('[data-api-key], [data-token], [data-secret]').forEach(el =>
            findings.sensitiveData.push({ type: 'Data Attribute', value: JSON.stringify(el.dataset), source: 'DOM Data Attributes' }));
    }
    
    function analyzeInlineScripts() {
        panel.updateStatus('Analyzing inline scripts...');
        document.querySelectorAll('script:not([src])').forEach((script, index) => {
            const content = script.textContent;
            if (content && content.length > 0 && content.length < 500000) analyzeJSContent(content, `inline-script-${index}`);
        });
    }
    
    async function startRecon() {
        panel.create();
        panel.updateStatus('Starting security reconnaissance...');
        analyzeDOM();
        analyzeInlineScripts();
        const jsFiles = extractJSFiles();
        panel.updateStatus(`Found ${jsFiles.size} JavaScript files to analyze...`);
        let analyzed = 0;
        for (const jsUrl of jsFiles) {
            await fetchAndAnalyzeJS(jsUrl);
            analyzed++;
            panel.updateStatus(`Analyzed ${analyzed}/${jsFiles.size} JS files...`);
            await new Promise(resolve => setTimeout(resolve, CONFIG.throttleRequests / 10));
        }
        const pageText = document.documentElement.innerHTML;
        CONFIG.apiPatterns.forEach(pattern => { let m; while ((m = pattern.exec(pageText)) !== null) findings.endpoints.add(m[0]); });
        panel.updateStatus('Scan complete! Click RESULTS to view findings.');
        console.groupCollapsed('%c Security Recon Results', 'color: #00ff9d; font-size: 14px; font-weight: bold');
        console.log('API Endpoints:', Array.from(findings.endpoints));
        console.log('Sensitive Data:', findings.sensitiveData);
        console.log('Admin/Role Keywords:', Array.from(findings.adminContent.keys()));
        console.log('Emails:', Array.from(findings.emails));
        console.log('JS Files Analyzed:', Array.from(findings.jsFiles.keys()));
        console.groupEnd();
        if (findings.sensitiveData.length > 0 || findings.keywordMatches.size > 0)
            panel.updateStatus(`! Found ${findings.sensitiveData.length + findings.keywordMatches.size} potential vulnerabilities!`, true);
    }
    
    function init() {
        const delay = getRandomDelay() + simulateHumanBehavior() + antiDetection();
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => setTimeout(startRecon, delay));
        } else {
            setTimeout(startRecon, delay);
        }
    }
    
    init();
    
    window.addEventListener('beforeunload', () => { if (panel.panel) panel.panel.remove(); });
    
})();