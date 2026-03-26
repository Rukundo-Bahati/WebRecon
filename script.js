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

(function () {
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
        maxFileSize: 5 * 1024 * 1024,
        supportedFileTypes: ['js', 'php', 'html', 'htm', 'json', 'xml', 'txt', 'conf', 'config', 'env', 'log'],
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
            'restapi', 'swagger-ui/index.html', 'swagger-ui.html', 'swagger-ui', 'api', 'openapi', 'api/docs', 'api-docs', 'api_spec', 'apispec',
            'user_id', 'uid', 'admin_id', 'adminid', 'role_id', 'roleid',
            'permission_id', 'permissionid', 'user_role_id', 'userroleid',

            // PHP specific keywords
            '$_SESSION', '$_COOKIE', '$_POST', '$_GET', '$_REQUEST', '$_SERVER',
            'mysqli_query', 'mysql_query', 'pdo', 'database', 'db_connect', 'dbconn',
            'include', 'require', 'include_once', 'require_once', 'file_get_contents',
            'fopen', 'fwrite', 'file_put_contents', 'curl_exec', 'shell_exec',
            'eval', 'assert', 'create_function', 'preg_replace', 'call_user_func',
            'unserialize', 'extract', 'import_request_variables', 'mb_parse_str',
            'password_hash', 'password_verify', 'hash', 'md5', 'sha1', 'crypt',
            'session_start', 'session_destroy', 'session_regenerate_id',
            'setcookie', 'header', 'http_response_code', 'base64_encode', 'base64_decode',

            // Enhanced patterns for specific detection
            'adminStats', 'stats', 'fetch', 'endpoint', 'baseURL', 'apiUrl', 'serverUrl',
            'user_data', 'userData', 'users', 'accounts', 'members', 'profiles',
            'subdomain', 'domain', 'hostname', 'origin', 'host'
        ],
        apiPatterns: [
            // Modern API patterns
            /\/api(?:\/v\d+)?\/[^\s"',<>(){}]+/gi,
            /\/(graphql|rest|rpc|admin|debug|swagger|docs|redoc)[^\s"',<>(){}]+/gi,
            /\/v\d+\/[^\s"',<>(){}]+/gi,
            /\/oauth(?:2)?\/[^\s"',<>(){}]+/gi,
            /\/auth\/[^\s"',<>(){}]+/gi,
            /\/user(?:s)?\/[^\s"',<>(){}]+/gi,
            /\/role(?:s)?\/[^\s"',<>(){}]+/gi,
            /\/admin(?:s)?\/[^\s"',<>(){}]+/gi,
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
            /\/(beacon|telemetry|insight|report)\/[^\s"',<>(){}]+/gi,

            // Enhanced patterns for specific cases
            /url:\s*["']https?:\/\/[^"']+\/api\/[^"']+["']/gi,
            /url:\s*["']https?:\/\/[^"']+\/admin\/[^"']+["']/gi,
            /["']https?:\/\/[^"']*\/admin[^"']*["']/gi,
            /["']https?:\/\/[^"']*\/api[^"']*["']/gi,
            /["']https?:\/\/[^"']*\/role[^"']*["']/gi,
            /["']https?:\/\/api\.[^"']+["']/gi,
            /["']https?:\/\/admin\.[^"']+["']/gi,
            /["']https?:\/\/[a-zA-Z0-9-]+\.[^"']+\/[^"']*["']/gi,
            /\.get\s*\(\s*["']\/[^"']+["']/gi,
            /\.post\s*\(\s*["']\/[^"']+["']/gi,
            /\.put\s*\(\s*["']\/[^"']+["']/gi,
            /\.delete\s*\(\s*["']\/[^"']+["']/gi,
            /endpoint:\s*["']\/[^"']+["']/gi,
            /baseURL:\s*["']https?:\/\/[^"']+["']/gi,
            /apiUrl:\s*["']https?:\/\/[^"']+["']/gi,
            /serverUrl:\s*["']https?:\/\/[^"']+["']/gi,

            // Auth and navigation patterns
            /\.push\s*\(\s*["']\/auth\/[^"']+["']/gi,
            /\.push\s*\(\s*["']\/login[^"']*["']/gi,
            /\.push\s*\(\s*["']\/signup[^"']*["']/gi,
            /\.push\s*\(\s*["']\/register[^"']*["']/gi,
            /\.push\s*\(\s*["']\/signin[^"']*["']/gi,
            /["']\/auth\/sign-up[^"']*["']/gi,
            /["']\/auth\/signin[^"']*["']/gi,
            /["']\/auth\/signup[^"']*["']/gi,
            /["']\/auth\/register[^"']*["']/gi,
            /["']\/auth\/login[^"']*["']/gi,
            /["']\/auth\/logout[^"']*["']/gi,
            /navigate\s*\(\s*["']\/auth\/[^"']+["']/gi,
            /window\.location\s*=\s*["']\/auth\/[^"']+["']/gi,
            /window\.location\.href\s*=\s*["']\/auth\/[^"']+["']/gi,
            /href\s*=\s*["']\/auth\/[^"']+["']/gi,
            /action\s*=\s*["']\/auth\/[^"']+["']/gi
        ],
        sensitivePatterns: [
            { regex: /(?:api[_-]?key|apikey|api_key)\s*[:=]\s*['"]?([A-Za-z0-9+/]{20,})['"]?/gi, type: 'API Key' },
            { regex: /sk-[a-zA-Z0-9]{48}/gi, type: 'OpenAI Secret Key' },
            { regex: /ghp_[0-9a-zA-Z]{36}/gi, type: 'GitHub Personal Token' },
            { regex: /gho_[0-9a-zA-Z]{36}/gi, type: 'GitHub OAuth Token' },
            { regex: /eyJ[A-Za-z0-9-_]+?\.eyJ[A-Za-z0-9-_]+?\./g, type: 'JWT Token' },
            { regex: /-----BEGIN (?:RSA|PRIVATE|OPENSSH) KEY-----[\s\S]+?-----END (?:RSA|PRIVATE|OPENSSH) KEY-----/gi, type: 'Private Key' },
            { regex: /(?:mongodb|mysql|postgresql):\/\/[^\s"',<>]+/gi, type: 'Database URL' },
            { regex: /(?:password|passwd|pwd)\s*[:=]\s*['"]([^"']{6,})['"]/gi, type: 'Password' },
            { regex: /(?:token|bearer|auth)\s*[:=]\s*['"]([^"']{20,})['"]/gi, type: 'Auth Token' },
            { regex: /(?:secret|private_key|secret_key)\s*[:=]\s*['"]([^"']{16,})['"]/gi, type: 'Secret' },
            { regex: /[a-zA-Z0-9._%+-]+@(?!gmail\.com|yahoo\.com|hotmail\.com|outlook\.com|aol\.com|icloud\.com)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, type: 'Email Address' },

            // Enhanced patterns for personal information
            { regex: /(?:email|e_mail|email_address|user_email|contact_email)\s*[:=]\s*['"]([^"']+)["']/gi, type: 'Email Field' },
            { regex: /(?:phone|mobile|telephone|contact_phone|user_phone)\s*[:=]\s*['"]([^"']+)["']/gi, type: 'Phone Number' },
            { regex: /(?:name|full_name|first_name|last_name|user_name|username)\s*[:=]\s*['"]([^"']{2,})["']/gi, type: 'Personal Name' },
            { regex: /(?:id|user_id|userid|uid|employee_id|customer_id)\s*[:=]\s*['"]?(\w+)["']?/gi, type: 'User ID' },
            { regex: /(?:first_name|fname|firstname)\s*[:=]\s*['"]([^"']{2,})["']/gi, type: 'First Name' },
            { regex: /(?:last_name|lname|lastname|surname)\s*[:=]\s*['"]([^"']{2,})["']/gi, type: 'Last Name' },

            // Phone number patterns
            { regex: /\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}/g, type: 'Phone Number' },
            { regex: /\+?[0-9]{1,3}[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{4}/g, type: 'International Phone' },
            { regex: /\+[0-9]{10,15}/g, type: 'Phone Number' },

            // User data patterns in arrays/objects
            { regex: /\{[^}]*email[^}]*\}/gi, type: 'User Object with Email' },
            { regex: /\{[^}]*phone[^}]*\}/gi, type: 'User Object with Phone' },
            { regex: /\{[^}]*name[^}]*\}/gi, type: 'User Object with Name' },

            // ID patterns
            { regex: /["']?[A-Z]{2,}\d{4,}["']?/g, type: 'Potential ID' },
            { regex: /["']?\d{6,10}["']?/g, type: 'Numeric ID' },

            // Social Security Number patterns (be careful with privacy)
            { regex: /\d{3}-\d{2}-\d{4}/g, type: 'SSN Pattern' },

            // Credit card patterns (be careful with privacy)
            { regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g, type: 'Credit Card' },

            // PHP specific patterns
            { regex: /\$db_(?:pass|password|pwd)\s*=\s*['"]([^'"]+)['"]/gi, type: 'PHP Database Password' },
            { regex: /\$api_(?:key|secret|token)\s*=\s*['"]([^'"]+)['"]/gi, type: 'PHP API Key' },
            { regex: /\$jwt_(?:secret|key)\s*=\s*['"]([^'"]+)['"]/gi, type: 'PHP JWT Secret' },
            { regex: /\$session_(?:key|secret)\s*=\s*['"]([^'"]+)['"]/gi, type: 'PHP Session Secret' },
            { regex: /\$encryption_(?:key|secret)\s*=\s*['"]([^'"]+)['"]/gi, type: 'PHP Encryption Key' },
            { regex: /define\s*\(\s*['"](?:API_KEY|SECRET_KEY|DB_PASSWORD|JWT_SECRET)['"]\s*,\s*['"]([^'"]+)['"]\s*\)/gi, type: 'PHP Defined Constant' },
            { regex: /mysql_connect\s*\([^)]*['"]([^'"]+)['"][^)]*['"]([^'"]+)['"]/gi, type: 'MySQL Connection' },
            { regex: /mysqli_connect\s*\([^)]*['"]([^'"]+)['"][^)]*['"]([^'"]+)['"]/gi, type: 'MySQLi Connection' },
            { regex: /PDO\s*::\s*construct\s*\([^)]*['"]([^'"]+)['"]/gi, type: 'PDO Connection String' }
        ],
        rolePatterns: [
            /role\s*[:=]\s*['"]([^'"]+)['"]/gi,
            /user_role\s*[:=]\s*['"]([^'"]+)['"]/gi,
            /userrole\s*[:=]\s*['"]([^'"]+)['"]/gi,
            /is_admin\s*[:=]\s*(?:true|false)/gi,
            /user_id\s*[:=]\s*(?:true|false)/gi,
            /\s*[:=]\s*(?:true|false)/gi,
            /is_super_admin\s*[:=]\s*(?:true|false)/gi,
            /is_moderator\s*[:=]\s*(?:true|false)/gi,
            /permissions\s*[:=]\s*\[[^\]]+\]/gi,
            /privileges\s*[:=]\s*\[[^\]]+\]/gi,
            /USER_ROLE\s*[:=]\s*['"]([^'"]+)['"]/gi,
            /ROLE\s*[:=]\s*['"]([^'"]+)['"]/gi
        ]
    };

    const findings = {
        endpoints: new Map(), // endpoint -> { source, full }
        sensitiveData: [],
        jsFiles: new Map(),
        adminContent: new Map(),
        rolesFound: new Map(), // role -> { source, full }
        swaggerUrls: new Map(), // url -> { source, full }
        emails: new Map(), // email -> { source, full }
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
                    width: 400px;
                    max-width: calc(100vw - 40px);
                    max-height: calc(100vh - 40px);
                    background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
                    color: #00ff9d;
                    font-family: 'Fira Code', 'Courier New', monospace;
                    font-size: 13px;
                    border: 1px solid rgba(0, 255, 157, 0.4);
                    border-radius: 12px;
                    padding: 0;
                    z-index: 2147483647;
                    backdrop-filter: blur(10px);
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4), 0 0 20px rgba(0, 255, 157, 0.1);
                    transition: all 0.3s ease;
                    overflow: hidden;
                    display: flex;
                    flex-direction: column;
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
                                font-size: 11px;
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
                                font-size: 12px;
                                transition: all 0.2s;
                            ">RESULTS</button>
                            <button id="cancel-scan" style="
                                background: rgba(255, 68, 68, 0.2);
                                border: 1px solid #ff4444;
                                color: #ff8888;
                                padding: 4px 10px;
                                border-radius: 6px;
                                cursor: pointer;
                                font-size: 12px;
                                transition: all 0.2s;
                            ">CANCEL</button>
                        </div>
                    </div>
                    <div id="scan-status" style="
                        padding: 10px 15px;
                        font-size: 12px;
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
                this.resultsContainer.style.maxHeight = 'calc(100vh - 120px)';
                this.resultsContainer.style.overflowY = 'auto';
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
        addFinding(category, title, details, severity = 'info', incrementBadge = true, fullData = null) {
            const severityColors = {
                critical: '#ff4444',
                high: '#ff8844',
                medium: '#ffaa44',
                low: '#88ff88',
                info: '#44aaff'
            };

            const findingId = `finding-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
            const hasMoreData = fullData && fullData.length > 0;

            const tempDiv = document.createElement('div');
            tempDiv.innerHTML = `
                <div style="
                    margin: 15px 0;
                    padding: 10px;
                    background: rgba(0, 0, 0, 0.4);
                    border-left: 3px solid ${severityColors[severity] || '#44aaff'};
                    border-radius: 6px;
                    font-size: 13px;
                ">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                        <strong style="color: ${severityColors[severity]}">[${category}]</strong>
                        <span style="color: #888; font-size: 11px;">${new Date().toLocaleTimeString()}</span>
                    </div>
                    <div style="color: #fff; margin-bottom: 5px;">${this.escapeHtml(title)}</div>
                    <details style="margin-top: 5px;">
                        <summary style="color: #00ff9d; cursor: pointer; font-size: 12px;">▼ Show details</summary>
                        <div>
                            <pre style="
                                background: rgba(0,0,0,0.6);
                                padding: 8px;
                                margin-top: 5px;
                                border-radius: 4px;
                                overflow-x: auto;
                                font-size: 11px;
                                color: #88ff88;
                                white-space: pre-wrap;
                                word-wrap: break-word;
                                max-height: 300px;
                                overflow-y: auto;
                            ">${this.escapeHtml(details)}</pre>
                            ${hasMoreData ? `
                                <div style="margin-top: 8px; text-align: center;">
                                    <button id="${findingId}-more" style="
                                        background: rgba(0, 255, 157, 0.2);
                                        border: 1px solid #00ff9d;
                                        color: #00ff9d;
                                        padding: 4px 12px;
                                        border-radius: 4px;
                                        cursor: pointer;
                                        font-size: 11px;
                                        margin: 0 2px;
                                    ">Show ${fullData.length} More</button>
                                    <button id="${findingId}-all" style="
                                        background: rgba(68, 170, 255, 0.2);
                                        border: 1px solid #44aaff;
                                        color: #44aaff;
                                        padding: 4px 12px;
                                        border-radius: 4px;
                                        cursor: pointer;
                                        font-size: 11px;
                                        margin: 0 2px;
                                    ">Show All</button>
                                </div>
                                <div id="${findingId}-expanded" style="display: none; margin-top: 8px;">
                                    <pre style="
                                        background: rgba(0,0,0,0.6);
                                        padding: 8px;
                                        border-radius: 4px;
                                        overflow-x: auto;
                                        font-size: 11px;
                                        color: #88ff88;
                                        white-space: pre-wrap;
                                        word-wrap: break-word;
                                        max-height: 400px;
                                        overflow-y: auto;
                                    ">${this.escapeHtml(fullData.join('\n'))}</pre>
                                </div>
                            ` : ''}
                        </div>
                    </details>
                </div>
            `;

            // ✅ FIX: firstElementChild skips the leading whitespace text node
            //    that innerHTML produces before the <div>, so the card is now
            //    actually appended and becomes visible in the panel.
            this.content.appendChild(tempDiv.firstElementChild);

            // Add event listeners for "Show More" buttons
            if (hasMoreData) {
                const moreBtn = document.getElementById(`${findingId}-more`);
                const allBtn = document.getElementById(`${findingId}-all`);
                const expandedDiv = document.getElementById(`${findingId}-expanded`);

                if (moreBtn && expandedDiv) {
                    moreBtn.addEventListener('click', () => {
                        const currentDisplay = expandedDiv.style.display;
                        expandedDiv.style.display = currentDisplay === 'none' ? 'block' : 'none';
                        moreBtn.textContent = currentDisplay === 'none' ? 'Hide' : `Show ${fullData.length} More`;
                    });
                }

                if (allBtn && expandedDiv) {
                    allBtn.addEventListener('click', () => {
                        expandedDiv.style.display = expandedDiv.style.display === 'none' ? 'block' : 'none';
                        allBtn.textContent = expandedDiv.style.display === 'none' ? 'Show All' : 'Hide All';
                    });
                }
            }

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
                const endpointEntries = Array.from(findings.endpoints.entries());
                const displayCount = 20;
                const preview = endpointEntries.slice(0, displayCount).map(([url, data]) => 
                    `${url}\n  Location: ${data.source}\n  Context: ${data.full || 'N/A'}`
                ).join('\n\n');
                const remaining = endpointEntries.slice(displayCount);
                
                this.addFinding('ENDPOINTS', `${findings.endpoints.size} API Endpoints Found`, 
                    preview + (remaining.length > 0 ? `\n\n... and ${remaining.length} more` : ''), 
                    'high', false, remaining.length > 0 ? remaining.map(([url, data]) => `${url}\n  Location: ${data.source}\n  Context: ${data.full || 'N/A'}`) : null
                );
            }
            
            if (findings.sensitiveData?.length > 0) {
                const sensitiveArray = findings.sensitiveData.slice(0, 15);
                const preview = sensitiveArray.map(d => `${d.type}: ${d.value}\n  Location: ${d.source}\n  Context: ${d.full || 'N/A'}`).join('\n\n');
                const remaining = findings.sensitiveData.slice(15);
                
                this.addFinding('SENSITIVE DATA', `${findings.sensitiveData.length} Items Found`,
                    preview + (remaining.length > 0 ? `\n\n... and ${remaining.length} more` : ''),
                    'critical', false, remaining.length > 0 ? remaining.map(d => `${d.type}: ${d.value}\n  Location: ${d.source}\n  Context: ${d.full || 'N/A'}`) : null
                );
            }
            
            if (findings.keywordMatches?.size > 0) {
                let keywordDetails = [];
                let allKeywordDetails = [];
                let itemCount = 0;
                const maxPreview = 50;
                
                findings.keywordMatches.forEach((matches, keyword) => {
                    keywordDetails.push(`\n${keyword.toUpperCase()} (${matches.length} matches):`);
                    allKeywordDetails.push(`\n${keyword.toUpperCase()} (${matches.length} matches):`);
                    
                    matches.slice(0, 10).forEach(match => {
                        if (itemCount < maxPreview) {
                            keywordDetails.push(`  ${match}`);
                        }
                        allKeywordDetails.push(`  ${match}`);
                        itemCount++;
                    });
                    
                    if (matches.length > 10) {
                        const moreText = `  ... and ${matches.length - 10} more`;
                        if (itemCount < maxPreview) {
                            keywordDetails.push(moreText);
                        }
                        allKeywordDetails.push(moreText);
                    }
                });
                
                const remainingKeywords = allKeywordDetails.slice(keywordDetails.length);
                
                this.addFinding('ADMIN/ROLE KEYWORDS', `${findings.keywordMatches.size} Keywords Found`,
                    keywordDetails.join('\n'),
                    'high', false, remainingKeywords.length > 0 ? remainingKeywords : null
                );
            }
            
            if (findings.emails?.size > 0) {
                const emailEntries = Array.from(findings.emails.entries());
                const preview = emailEntries.slice(0, 15).map(([email, data]) => 
                    `Email: ${email}\n  Location: ${data.source}\n  Context: ${data.full || 'N/A'}`
                ).join('\n\n');
                const remaining = emailEntries.slice(15);
                
                this.addFinding('EMAILS', `${findings.emails.size} Email Addresses Found`,
                    preview + (remaining.length > 0 ? `\n\n... and ${remaining.length} more` : ''),
                    'medium', false, remaining.length > 0 ? remaining.map(([email, data]) => `Email: ${email}\n  Location: ${data.source}\n  Context: ${data.full || 'N/A'}`) : null
                );
            }
            
            if (findings.swaggerUrls?.size > 0) {
                const swaggerEntries = Array.from(findings.swaggerUrls.entries());
                const preview = swaggerEntries.map(([url, data]) => 
                    `${url}\n  Location: ${data.source}\n  Context: ${data.full || 'N/A'}`
                ).join('\n\n');
                
                this.addFinding('API DOCS', 'Swagger/OpenAPI Endpoints',
                    preview,
                    'high', false, swaggerEntries.length > 10 ? swaggerEntries.map(([url, data]) => `${url}\n  Location: ${data.source}\n  Context: ${data.full || 'N/A'}`) : null
                );
            }
            
            if (findings.hardcodedSecrets?.length > 0) {
                const secretsArray = findings.hardcodedSecrets.slice(0, 10);
                const preview = secretsArray.map(s => `${s.type}: ${s.value}\n  Location: ${s.source}`).join('\n\n');
                const remaining = findings.hardcodedSecrets.slice(10);
                
                this.addFinding('HARDCODED SECRETS', `${findings.hardcodedSecrets.length} Secrets Found`,
                    preview + (remaining.length > 0 ? `\n... and ${remaining.length} more` : ''),
                    'critical', false, remaining.length > 0 ? remaining.map(s => `${s.type}: ${s.value}\n  Location: ${s.source}`) : null
                );
            }

            if (totalFindings === 0 && findings.emails?.size === 0 &&
                findings.swaggerUrls?.size === 0 && findings.hardcodedSecrets?.length === 0) {
                this.addFinding('INFO', 'No findings yet',
                    'Scan may still be in progress, or nothing was detected on this page.',
                    'info', false);
            }
        }

        escapeHtml(str) {
            if (!str) return '';
            return str.replace(/[&<>]/g, function (m) {
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

    function isValidEmail(email) {
        if (!email) return false;
        // Basic format check
        const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/;
        if (!emailRegex.test(email)) return false;
        // Exclude common library artifacts
        if (email.includes('/') || email.includes('*') || email.includes('=') || email.includes('(') || email.includes('[') || email.includes('!')) return false;
        return true;
    }

    function isRelatedEndpoint(endpoint) {
        if (!endpoint) return false;
        
        // Block known unrelated domains/patterns
        const blockedPatterns = [/w3\.org/, /unsplash\.com/, /googletagmanager/, /google-analytics/, /facebook\.net/, /hubfly\.app/, /nextjs\.org/, /reactjs\.org/];
        if (blockedPatterns.some(p => p.test(endpoint))) return false;

        // Skip massive encoded junk strings that often appear in minified/obfuscated code
        if (endpoint.length > 300 && !endpoint.includes('?') && !endpoint.includes('.') && (!endpoint.includes('/') || endpoint.split('/').some(s => s.length > 100))) return false;

        // If it starts with / (but not //), it's relative
        if (endpoint.startsWith('/') && !endpoint.startsWith('//')) return true;
        
        // If it's a full URL or protocol-relative
        if (endpoint.includes('://') || endpoint.startsWith('//')) {
            const host = window.location.hostname;
            const parts = host.split('.');
            if (parts.length >= 2) {
                // Get the main domain like example.com from sub.example.com
                // Handle cases like .co.uk if needed, but for now simple 2 parts from end
                const baseDomain = parts.slice(-2).join('.');
                return endpoint.includes(baseDomain);
            }
            return endpoint.includes(host);
        }
        
        // If it looks like a path but doesn't have a domain
        if (endpoint.startsWith('./') || endpoint.startsWith('../')) return true;
        if (endpoint.includes('/') && !endpoint.includes('.') && !endpoint.includes(':')) return true;

        return false;
    }

    function searchKeywordsCaseInsensitive(content, sourceUrl) {
        // Skip minified/webpack content
        if (content.includes('webpackChunk') || content.includes('__next_f') ||
            content.includes('self.__next') || content.includes('webpackChunk_N_E') ||
            content.includes('minified React error') || content.length > 500000) {
            return;
        }

        const lines = content.split('\n');
        lines.forEach((line, lineNum) => {
            // Skip minified lines
            if (line.length > 500 && !line.includes(' ') ||
                line.includes('webpackChunk') ||
                line.includes('__next_f') ||
                line.includes('self.__next') ||
                line.includes('use strict') && line.includes('webpackChunk')) {
                return;
            }

            CONFIG.keywords.forEach(keyword => {
                const regex = new RegExp(`\\b${keyword}\\b`, 'gi');
                if (regex.test(line)) {
                    let extractedValue = '';
                    if (keyword.includes('role') || keyword.includes('admin') || keyword.includes('permission') || keyword.includes('user')) {
                        const valuePatterns = [
                            new RegExp(`${keyword}\\s*[:=]\\s*['"]([^'"]+)['"]`, 'gi'),
                            new RegExp(`${keyword}\\s*[:=]\\s*([^\\s,)}]+)`, 'gi'),
                            new RegExp(`['"]([^'"]*${keyword}[^'"]*)['"]`, 'gi'),
                            new RegExp(`\\$${keyword}\\s*=\\s*['"]([^'"]+)['"]`, 'gi'),
                            new RegExp(`"${keyword}"\\s*:\\s*"([^"]+)"`, 'gi'),
                            new RegExp(`'${keyword}'\\s*:\\s*'([^']+)'`, 'gi'),
                            new RegExp(`${keyword}\\s*:\\s*([^\\s,}]+)`, 'gi')
                        ];

                        for (const pattern of valuePatterns) {
                            const match = pattern.exec(line);
                            if (match && match[1]) {
                                extractedValue = ` → ${match[1]}`;
                                break;
                            }
                        }
                    }

                    const fullMatch = `Line ${lineNum + 1}: ${line.trim()}${extractedValue}`;
                    if (fullMatch.length < 500 && fullMatch.includes(' ')) {
                        if (!findings.keywordMatches.has(keyword)) {
                            findings.keywordMatches.set(keyword, []);
                        }
                        // Avoid duplicates
                        if (!findings.keywordMatches.get(keyword).includes(fullMatch)) {
                            findings.keywordMatches.get(keyword).push(fullMatch);
                        }
                        findings.adminContent.set(`${keyword.toUpperCase()} in ${sourceUrl.split('/').pop()}: ${fullMatch}`, true);
                    }
                }
            });
        });

        // Search whole content for global patterns once per file
        const userDataPatterns = [
            /\{[\s\S]*?name:\s*["'][^"']+["'][\s\S]*?email:\s*[^,}]+[\s\S]*?\}/gi,
            /\{[^}]*id[^}]*name[^}]*email[^}]*\}/gi,
            /\{[^}]*email[^}]*name[^}]*\}/gi,
            /users:\s*\[[\s\S]*?\]/gi,
            /data:\s*\[[\s\S]*?\{[^}]*email[^}]*\}[\s\S]*?\]/gi,
            /adminStats[^)]*\)/gi,
            /\{[\s\S]*?id:\s*["']?\d+["']?[\s\S]*?name:\s*["'][^"']+["'][\s\S]*?role:\s*["'][^"']+["'][\s\S]*?\}/gi,
            /\b[A-Z_]{1,10}\s*=\s*\[[\s\S]{0,500}?\{[\s\S]{0,100}?id:[\s\S]{0,100}?name:[\s\S]{0,500}?\}/gi, // Match AE = [{ ... }]
            /\b[A-Z_]{1,10}\s*=\s*\[\s*["'][^"']+["'](?:\s*,\s*["'][^"']+["'])+\s*\]/gi // Match AI = ["...", "..."]
        ];

        const isTechnicalArray = (text) => {
            const techKeywords = ['"constructor"', '"hasOwnProperty"', '"isPrototypeOf"', '"propertyIsEnumerable"', '"toLocaleString"', '"toString"', '"valueOf"', '[object Int8Array]', '"DELETE"', '"GET"', '"POST"', '"PUT"'];
            // If it has many technical keywords and NO email/human-like data, skip
            let techCount = 0;
            techKeywords.forEach(kw => { if (text.includes(kw)) techCount++; });
            return techCount > 2 && !text.includes('@');
        };

        userDataPatterns.forEach(pattern => {
            let match;
            while ((match = pattern.exec(content)) !== null) {
                const matchedText = match[0];
                if (matchedText.length < 1000 && matchedText.length > 20 && !isTechnicalArray(matchedText)) {
                    // Find line number
                    const lineNum = content.substring(0, match.index).split('\n').length;
                    const userDataMatch = `Line ${lineNum}: ${matchedText.trim().replace(/\s+/g, ' ').substring(0, 300)}`;
                    
                    if (!findings.keywordMatches.has('user_data')) {
                        findings.keywordMatches.set('user_data', []);
                    }
                    if (!findings.keywordMatches.get('user_data').includes(userDataMatch)) {
                        findings.keywordMatches.get('user_data').push(userDataMatch);
                    }
                }
            }
        });

        const apiCallPatterns = [
            /\.get\s*\(\s*["']([^"']+)["']/gi,
            /\.post\s*\(\s*["']([^"']+)["']/gi,
            /\.put\s*\(\s*["']([^"']+)["']/gi,
            /\.delete\s*\(\s*["']([^"']+)["']/gi,
            /url:\s*["']([^"']+)["']/gi,
            /endpoint:\s*["']([^"']+)["']/gi,
            /["']https?:\/\/[^"']*\/api[^"']*["']/gi,
            /["']https?:\/\/[^"']*\/admin[^"']*["']/gi,
            /\.push\s*\(\s*["']([^"']+)["']/gi,
            /navigate\s*\(\s*["']([^"']+)["']/gi,
            /router\.push\s*\(\s*["']([^"']+)["']/gi,
            /window\.location(?:\.href)?\s*=\s*["']([^"']+)["']/gi,
            /action\s*=\s*["']([^"']+)["']/gi
        ];

        apiCallPatterns.forEach(pattern => {
            let match;
            while ((match = pattern.exec(content)) !== null) {
                const endpoint = (match[1] || match[0]).replace(/["']/g, '');
                if (endpoint && endpoint.length < 2000 && isRelatedEndpoint(endpoint) && (
                    endpoint.includes('/api') || 
                    endpoint.includes('/admin') || 
                    endpoint.includes('/auth') ||
                    endpoint.includes('sign-up') ||
                    endpoint.includes('role=') ||
                    endpoint.includes('signup') ||
                    endpoint.includes('register')
                )) {
                    const lineNum = content.substring(0, match.index).split('\n').length;
                    findings.endpoints.set(endpoint, {
                        source: `${sourceUrl.split('/').pop()}:${lineNum}`,
                        full: `Found in ${sourceUrl.split('/').pop()} at line ${lineNum}`
                    });
                }
            }
        });
    }

    async function fetchAndAnalyzeFile(url) {
        if (findings.jsFiles.has(url)) return;
        return new Promise((resolve) => {
            GM_xmlhttpRequest({
                method: 'GET', url, timeout: 10000,
                onload: function (response) {
                    if (response.status === 200 && response.responseText) {
                        const content = response.responseText;
                        const fileExtension = url.split('.').pop()?.toLowerCase();

                        if (content.length > CONFIG.maxFileSize) {
                            panel.updateStatus(`Skipping large file: ${url.substring(0, 80)}...`);
                            resolve();
                            return;
                        }

                        findings.jsFiles.set(url, {
                            type: fileExtension,
                            size: content.length,
                            analyzed: true
                        });

                        panel.updateStatus(`Analyzing: ${url.split('/').pop()} (${fileExtension})`);
                        analyzeFileContent(content, url, fileExtension);
                    }
                    resolve();
                },
                onerror: () => resolve()
            });
        });
    }

    function analyzeFileContent(content, sourceUrl, fileType) {
        // Always search for keywords
        searchKeywordsCaseInsensitive(content, sourceUrl);

        // Search for API endpoints
        CONFIG.apiPatterns.forEach(pattern => {
            let m;
            while ((m = pattern.exec(content)) !== null) {
                const endpoint = m[1] || m[0];
                // Filter out minified/invalid endpoints
                if (endpoint && endpoint.length < 2000 &&
                    !endpoint.includes('webpackChunk') &&
                    !endpoint.includes('__next') &&
                    !endpoint.includes('self.__next') &&
                    !endpoint.includes('minified') &&
                    isRelatedEndpoint(endpoint) &&
                    (endpoint.includes('/') || endpoint.includes('http'))) {
                    findings.endpoints.set(endpoint, {
                        source: `${sourceUrl.split('/').pop()}`,
                        full: `Source match: ${content.substring(Math.max(0, m.index - 50), Math.min(content.length, m.index + endpoint.length + 50)).trim()}`
                    });
                }
            }
        });

        // Search for Swagger/API docs
        const swaggerPatterns = [/swagger/gi, /openapi/gi, /api-docs/gi, /redoc/gi];
        swaggerPatterns.forEach(pattern => {
            if (pattern.test(content)) {
                const matches = content.match(/["'](\/[^"']*(?:swagger|openapi|api-docs)[^"']*)["']/gi);
                if (matches) matches.forEach(m => { 
                    const u = m.replace(/["']/g, ''); 
                    if (isRelatedEndpoint(u)) {
                        findings.swaggerUrls.set(u, { source: sourceUrl.split('/').pop(), full: `Found in ${sourceUrl}` }); 
                        findings.endpoints.set(u, { source: sourceUrl.split('/').pop(), full: `API documentation endpoint` }); 
                    }
                });
            }
        });

        // Search for sensitive data with line context
        const contentLines = content.split('\n');
        contentLines.forEach((line, lineNum) => {
            // Only skip lines that are purely obfuscated junk or giant polyfill wrappers
            if ((line.length > 2000 && !line.includes(' ')) || 
                (line.includes('!function') && line.includes('defineProperty') && line.length < 500)) {
                return;
            }

            CONFIG.sensitivePatterns.forEach(({ regex, type }) => {
                let match;
                // Reset regex lastIndex
                regex.lastIndex = 0;
                while ((match = regex.exec(line)) !== null) {
                    const value = match[1] || match[0];
                    // Skip if value is too long or contains minified patterns
                    if (value && value.length < 1500 &&
                        !value.includes('webpackChunk') &&
                        !value.includes('__next') &&
                        !value.includes('className') &&
                        !value.includes('self.__next')) {

                        if (type === 'Email Address') {
                            if (!isValidEmail(value)) return;
                            findings.emails.set(value, { source: `${sourceUrl.split('/').pop()}:${lineNum + 1}`, full: `Line ${lineNum + 1}: ${line.trim().substring(0, 300)}...` });
                        }
                        
                        findings.sensitiveData.push({
                            type,
                            value: value.substring(0, 100),
                            source: `${sourceUrl.split('/').pop()}:${lineNum + 1}`,
                            full: `Line ${lineNum + 1}: ${line.trim().substring(0, 300)}...`
                        });

                        if (type.includes('Key') || type.includes('Token') || type.includes('Secret'))
                            findings.hardcodedSecrets.push({ type, value: value.substring(0, 50), source: sourceUrl });
                    }
                }
            });
        });

        // File type specific analysis
        if (fileType === 'php') {
            // PHP specific patterns
            const phpPatterns = [
                /\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*['"]([^'"]+)['"]/g, // Variable assignments
                /define\s*\(\s*['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]\s*\)/g, // Define constants
                /function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g, // Function definitions
                /class\s+([a-zA-Z_][a-zA-Z0-9_]*)/g, // Class definitions
                /mysql_(?:query|fetch|assoc|num_rows)\s*\([^)]+\)/g, // MySQL functions
                /mysqli_query\s*\([^)]+\)/g, // MySQLi functions
                /PDO::(?:prepare|execute|query)\s*\([^)]+\)/g, // PDO functions
                /echo\s+['"]([^'"]+)['"]/g, // Echo statements
                /print\s+['"]([^'"]+)['"]/g // Print statements
            ];

            phpPatterns.forEach(pattern => {
                let match;
                while ((match = pattern.exec(content)) !== null) {
                    const value = match[1] || match[0];
                    findings.sensitiveData.push({
                        type: `PHP ${pattern.source.includes('function') ? 'Function' : pattern.source.includes('class') ? 'Class' : pattern.source.includes('mysql') ? 'Database' : pattern.source.includes('define') ? 'Constant' : 'Variable'}`,
                        value: value.substring(0, 100),
                        source: sourceUrl
                    });
                }
            });
        }

        // Enhanced personal information extraction for all file types
        const lines = content.split('\n');
        lines.forEach((line, lineNum) => {
            // Only skip lines that are purely obfuscated junk or giant polyfill wrappers
            if ((line.length > 2000 && !line.includes(' ')) || 
                (line.includes('!function') && line.includes('defineProperty') && line.length < 500)) {
                return;
            }

            // Extract emails with context
            const emailPatterns = [
                /email:\s*["']([^"']+)["']/gi,
                /["']([^"']+@[^"']+\.[^"']+)["']/gi,
                /(?:user_email|contact_email)\s*[:=]\s*["']([^"']+)["']/gi
            ];

            emailPatterns.forEach(pattern => {
                let match;
                while ((match = pattern.exec(line)) !== null) {
                    const email = (match[1] || match[0]).replace(/["']/g, '');
                    if (isValidEmail(email)) {
                        findings.sensitiveData.push({
                            type: 'Email',
                            value: email,
                            source: `${sourceUrl.split('/').pop()}:${lineNum + 1}`,
                            full: `Line ${lineNum + 1}: ${line.trim().substring(0, 300)}...`
                        });
                        findings.emails.set(email, { source: `${sourceUrl.split('/').pop()}:${lineNum + 1}`, full: `Line ${lineNum + 1}: ${line.trim().substring(0, 300)}...` });
                    }
                }
            });

            // Extract names with context
            const namePatterns = [
                /name:\s*["']([^"']+)["']/gi,
                /first_name:\s*["']([^"']+)["']/gi,
                /last_name:\s*["']([^"']+)["']/gi,
                /full_name:\s*["']([^"']+)["']/gi,
                /username:\s*["']([^"']+)["']/gi
            ];

            namePatterns.forEach(pattern => {
                let match;
                while ((match = pattern.exec(line)) !== null) {
                    const name = match[1];
                    if (name && name.length > 1 && name.length < 100) {
                        const type = pattern.source.includes('first') ? 'First Name' :
                            pattern.source.includes('last') ? 'Last Name' :
                                pattern.source.includes('full') ? 'Full Name' :
                                    pattern.source.includes('username') ? 'Username' : 'Name';
                        
                        // Filter out technical function names/verbs that aren't real names
                        const techNames = ['upsert', 'delete', 'update', 'insert', 'invoke', 'toggle', 'init', 'reset', 'clear', 'error', 'success', 'warning', 'info', 'debug', 'trace', 'bind', 'call', 'apply', 'shim', 'polyfill', 'webpack', 'next', 'react', 'object', 'function', 'boolean', 'string', 'number', 'array', 'undefined', 'null', 'prototype', 'constructor'];
                        if (techNames.includes(name.toLowerCase())) return;

                        findings.sensitiveData.push({
                            type: type,
                            value: name,
                            source: `${sourceUrl.split('/').pop()}:${lineNum + 1}`,
                            full: `Line ${lineNum + 1}: ${line.trim().substring(0, 300)}...`
                        });
                    }
                }
            });

            // Extract phone numbers with context
            const phonePatterns = [
                /phone:\s*["']([^"']+)["']/gi,
                /mobile:\s*["']([^"']+)["']/gi,
                /telephone:\s*["']([^"']+)["']/gi,
                /\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}/g
            ];

            phonePatterns.forEach(pattern => {
                let match;
                while ((match = pattern.exec(line)) !== null) {
                    const phone = match[1] || match[0];
                    if (phone && phone.length > 6 && phone.length < 25) {
                        findings.sensitiveData.push({
                            type: 'Phone Number',
                            value: phone,
                            source: `${sourceUrl.split('/').pop()}:${lineNum + 1}`,
                            full: `Line ${lineNum + 1}: ${line.trim().substring(0, 300)}...`
                        });
                    }
                }
            });

            // Extract user IDs with context
            const idPatterns = [
                /id:\s*["']?(\w+)["']?/gi,
                /user_id:\s*["']?(\w+)["']?/gi,
                /employee_id:\s*["']?(\w+)["']?/gi,
                /customer_id:\s*["']?(\w+)["']?/gi
            ];

            idPatterns.forEach(pattern => {
                let match;
                while ((match = pattern.exec(line)) !== null) {
                    const id = match[1];
                    if (id && id.length > 2 && id.length < 50 && !id.includes('className')) {
                        findings.sensitiveData.push({
                            type: 'User ID',
                            value: id,
                            source: `${sourceUrl.split('/').pop()}:${lineNum + 1}`,
                            full: `Line ${lineNum + 1}: ${line.trim().substring(0, 300)}...`
                        });
                    }
                }
            });

            // Extract complete user objects
            const userObjectPatterns = [
                /\{[^}]*email:\s*["']([^"']+)["'][^}]*\}/gi,
                /\{[^}]*name:\s*["']([^"']+)["'][^}]*\}/gi,
                /\{[^}]*phone:\s*["']([^"']+)["'][^}]*\}/gi
            ];

            userObjectPatterns.forEach(pattern => {
                let match;
                while ((match = pattern.exec(line)) !== null) {
                    const objectStr = match[0];
                    if (objectStr.length < 200 && objectStr.includes('{') && objectStr.includes('}')) {
                        const type = pattern.source.includes('email') ? 'User Object with Email' :
                            pattern.source.includes('name') ? 'User Object with Name' :
                                'User Object with Phone';

                        findings.sensitiveData.push({
                            type: type,
                            value: objectStr.substring(0, 500),
                            source: `${sourceUrl.split('/').pop()}:${lineNum + 1}`,
                            full: `Line ${lineNum + 1}: ${line.trim().substring(0, 300)}...`
                        });
                    }
                }
            });
        });

        // Search for role-related patterns
        CONFIG.rolePatterns.forEach(pattern => { 
            let m; 
            while ((m = pattern.exec(content)) !== null) {
                const roleValue = m[1] || m[0];
                findings.rolesFound.set(roleValue, { 
                    source: sourceUrl.split('/').pop(), 
                    full: `Match: ${m[0]}`
                });
            }
        });
    }

    function extractFiles() {
        const fileUrls = new Set();
        // Regex to match chunk files: chunk-*.js, *.chunk.js, [hash].js patterns
        const chunkPattern = /chunk[-.]|\.[a-f0-9]{8,}\.js|_[a-f0-9]{8,}\.js|webpack|_next|static/;

        // Get current page domain to filter only related files
        const currentDomain = window.location.hostname;
        const currentOrigin = window.location.origin;

        // Standard script and link tags
        document.querySelectorAll('script[src], link[href]').forEach(element => {
            let src = element.src || element.href;
            if (src && !CONFIG.ignoreDomains.some(d => src.includes(d))) {
                // Check if file is from current domain or same origin
                if (src.includes(currentDomain) || src.startsWith(currentOrigin)) {
                    const fileExtension = src.split('.').pop()?.toLowerCase();
                    if (CONFIG.supportedFileTypes.includes(fileExtension)) {
                        if (src.startsWith('/')) src = window.location.origin + src;
                        else if (src.startsWith('./')) src = window.location.href + src.substring(1);
                        else if (!src.startsWith('http')) src = window.location.origin + '/' + src;
                        fileUrls.add(src);
                    }
                }
            }
        });

        // Enhanced search for file references in page content
        const pageContent = document.documentElement.innerHTML;
        const filePatterns = [
            // Standard patterns
            /src=["']([^"']*\.(' + CONFIG.supportedFileTypes.join('|') + ')[^"']*)["']/gi,
            /href=["']([^"']*\.(' + CONFIG.supportedFileTypes.join('|') + ')[^"']*)["']/gi,
            /url\s*\(\s*["']?([^"']*\.(' + CONFIG.supportedFileTypes.join('|') + ')[^"']*)["']?\s*\)/gi,

            // Dynamic import patterns
            /import\s*\(\s*["']([^"']*\.(' + CONFIG.supportedFileTypes.join('|') + ')[^"']*)["']\s*\)/gi,
            /require\s*\(\s*["']([^"']*\.(' + CONFIG.supportedFileTypes.join('|') + ')[^"']*)["']\s*\)/gi,

            // Fetch and AJAX patterns
            /fetch\s*\(\s*["']([^"']*\.(' + CONFIG.supportedFileTypes.join('|') + ')[^"']*)["']\s*\)/gi,
            /\.get\s*\(\s*["']([^"']*\.(' + CONFIG.supportedFileTypes.join('|') + ')[^"']*)["']\s*\)/gi,
            /\.post\s*\(\s*["']([^"']*\.(' + CONFIG.supportedFileTypes.join('|') + ')[^"']*)["']\s*\)/gi,

            // Config and asset patterns
            /configUrl:\s*["']([^"']*\.(' + CONFIG.supportedFileTypes.join('|') + ')[^"']*)["']/gi,
            /assetUrl:\s*["']([^"']*\.(' + CONFIG.supportedFileTypes.join('|') + ')[^"']*)["']/gi,
            /baseUrl:\s*["']([^"']*\.(' + CONFIG.supportedFileTypes.join('|') + ')[^"']*)["']/gi,

            // API endpoint patterns that might be files
            /["']https?:\/\/[^"']*\/api\/[^"']*\.(' + CONFIG.supportedFileTypes.join('|') + ')["']/gi,
            /["']https?:\/\/[^"']*\/admin\/[^"']*\.(' + CONFIG.supportedFileTypes.join('|') + ')["']/gi
        ];

        filePatterns.forEach(pattern => {
            let m;
            while ((m = pattern.exec(pageContent)) !== null) {
                let url = m[1];
                if (url && !url.includes('data:') && !CONFIG.ignoreDomains.some(d => url.includes(d)) &&
                    !chunkPattern.test(url) && (url.includes(currentDomain) || url.startsWith(currentOrigin))) {

                    // Skip obvious minified/bundled files
                    if (url.includes('webpack') || url.includes('_next') || url.includes('static') ||
                        url.includes('chunk') || url.includes('bundle') || url.includes('vendor')) {
                        return;
                    }

                    if (url.startsWith('/')) url = window.location.origin + url;
                    else if (!url.startsWith('http')) url = window.location.origin + '/' + url;
                    fileUrls.add(url);
                }
            }
        });

        // Also check for files in inline scripts
        document.querySelectorAll('script:not([src])').forEach(script => {
            if (script.textContent) {
                const scriptContent = script.textContent;
                const inlinePatterns = [
                    /["']([^"']*\.(' + CONFIG.supportedFileTypes.join('|') + ')[^"']*)["']/gi,
                    /import\s*\(\s*["']([^"']*\.(' + CONFIG.supportedFileTypes.join('|') + ')[^"']*)["']\s*\)/gi,
                    /require\s*\(\s*["']([^"']*\.(' + CONFIG.supportedFileTypes.join('|') + ')[^"']*)["']\s*\)/gi
                ];

                inlinePatterns.forEach(pattern => {
                    let m;
                    while ((m = pattern.exec(scriptContent)) !== null) {
                        let url = m[1];
                        if (url && !url.includes('data:') && !CONFIG.ignoreDomains.some(d => url.includes(d)) &&
                            !chunkPattern.test(url) && (url.includes(currentDomain) || url.startsWith(currentOrigin))) {

                            // Skip obvious minified/bundled files
                            if (url.includes('webpack') || url.includes('_next') || url.includes('static') ||
                                url.includes('chunk') || url.includes('bundle') || url.includes('vendor')) {
                                return;
                            }

                            if (url.startsWith('/')) url = window.location.origin + url;
                            else if (!url.startsWith('http')) url = window.location.origin + '/' + url;
                            fileUrls.add(url);
                        }
                    }
                });
            }
        });

        return fileUrls;
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
            if (isValidEmail(m[0])) {
                findings.emails.set(m[0], { source: 'HTML DOM', full: `Detected in page HTML` });
                findings.sensitiveData.push({ type: 'Email Address', value: m[0], source: 'HTML DOM' });
            }
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
            if (content && content.length > 0 && content.length < 500000) analyzeFileContent(content, `inline-script-${index}`, 'js');
        });
    }

    async function startRecon() {
        panel.create();
        panel.updateStatus('Starting security reconnaissance...');
        analyzeDOM();
        analyzeInlineScripts();
        const files = extractFiles();
        panel.updateStatus(`Found ${files.size} files to analyze...`);

        let analyzed = 0;
        for (const fileUrl of files) {
            await fetchAndAnalyzeFile(fileUrl);
            analyzed++;
            panel.updateStatus(`Analyzed ${analyzed}/${files.size} files...`);
            await new Promise(resolve => setTimeout(resolve, CONFIG.throttleRequests / 10));
        }
        const pageText = document.documentElement.innerHTML;
        CONFIG.apiPatterns.forEach(pattern => { 
            let m; 
            while ((m = pattern.exec(pageText)) !== null) {
                const endpoint = m[0].replace(/["']/g, '');
                if (isRelatedEndpoint(endpoint)) {
                    findings.endpoints.set(m[0], { source: 'DOM Page Text', full: 'Detected in static Page HTML' });
                }
            } 
        });
        panel.updateStatus('Scan complete! Click RESULTS to view findings.');
        console.groupCollapsed('%c Security Recon Results', 'color: #00ff9d; font-size: 14px; font-weight: bold');
        console.log('API Endpoints:', Array.from(findings.endpoints));
        console.log('Sensitive Data:', findings.sensitiveData);
        console.log('Admin/Role Keywords:', Array.from(findings.adminContent.keys()));
        console.log('Emails:', Array.from(findings.emails));
        console.log('Files Analyzed:', Array.from(findings.jsFiles.keys()));
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