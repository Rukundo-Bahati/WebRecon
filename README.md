# WebRecon - Advanced Security Reconnaissance Tool

## Overview

WebRecon is a comprehensive browser-based security reconnaissance userscript designed for security professionals and penetration testers. It performs real-time analysis of web pages to identify potential security vulnerabilities, sensitive data exposures, and administrative interfaces.

**Version:** 3.1  
**Author:** Nam3l3ss  
**Type:** Tampermonkey/Greasemonkey Userscript

## Features

###  **Comprehensive Scanning**
- **Case-insensitive keyword detection** for admin panels, user roles, and security-related terms
- **API endpoint discovery** with pattern matching
- **Sensitive data extraction** (API keys, tokens, credentials)
- **JavaScript file analysis** for embedded secrets
- **Email address extraction**
- **Role-based access control detection**

###  **Security Patterns**
The script detects over 100 security-related keywords and patterns including:

- **Admin & Roles:** admin, super_admin, moderator, dashboard, control_panel
- **Authentication:** auth, login, register, oauth, jwt_secret
- **Database:** db_password, connection_string, mongodb_uri
- **API Keys:** api_key, aws_access_key, stripe_key, firebase_config
- **Development:** debug, test_mode, swagger, graphql
- **Dangerous Functions:** eval, exec, shell, system_call

### 🛡️ **Advanced Detection**
- **Regex-based pattern matching** for complex data structures
- **Case-insensitive search** ensuring no variants are missed
- **Real-time scanning** with configurable delays
- **Smart filtering** to avoid false positives
- **Cross-origin JavaScript file analysis**

## Installation

### Prerequisites
1. **Tampermonkey** (Chrome/Firefox/Edge) or **Greasemonkey** (Firefox)
2. Modern browser with ES6+ support

### Setup Steps
1. Install Tampermonkey/Greasemonkey extension
2. Click on the extension icon
3. Select "Create new script"
4. Copy the entire `script.js` content
5. Paste into the editor
6. Save (Ctrl+S)

## Usage

### Automatic Activation
- The script runs automatically on all HTTP/HTTPS pages (`*://*/*`)
- Scanning begins after a configurable delay (default: 2 seconds)
- Results appear in a floating panel on the page

### Manual Controls
The interface provides:
- **Scan Status:** Real-time scanning progress
- **Results Panel:** Collapsible findings display
- **Export Options:** Copy results to clipboard
- **Hide/Show:** Toggle panel visibility

### Configuration Options
Key settings in the `CONFIG` object:
```javascript
stealthMode: false,          // Hide all UI elements
autoHidePanel: false,       // Auto-hide panel after scan
scanDelay: 2000,            // Delay before scanning (ms)
maxJSSize: 5 * 1024 * 1024, // Max JS file size to analyze
analyzeJSFiles: true,       // Enable JS file analysis
```

## Output Categories

###  **Scan Results**
1. **Keywords Found:** Security-related terms detected
2. **API Endpoints:** Discovered API routes and endpoints
3. **Sensitive Data:** Extracted credentials, keys, tokens
4. **Email Addresses:** Found email addresses
5. **User Roles:** Detected role assignments and permissions
6. **JavaScript Files:** Analyzed external JS files

###  **Notifications**
- **Visual alerts** for high-priority findings
- **Console logging** with detailed results
- **Status updates** during scanning process

## Target Use Cases

### 🔬 **Security Assessment**
- Identify exposed administrative interfaces
- Discover hardcoded credentials and API keys
- Find authentication bypass opportunities
- Map application attack surface

###  **Penetration Testing**
- Rapid reconnaissance during engagements
- Identify low-hanging security issues
- Gather intelligence for further exploitation
- Document findings for reports

###  **Development Security**
- Validate secure coding practices
- Detect secrets before deployment
- Review third-party integrations
- Audit application configurations

## Detection Patterns

### API Endpoints
```
/api/v*/users
/admin/dashboard
/auth/login
/graphql
/swagger/docs
```

### Sensitive Data
```
API Keys: sk-*, AKIA*, ghp_*
JWT Tokens: eyJ*.eyJ*
Database URLs: mongodb://*, mysql://*
Email Addresses: user@domain.com
```

### Role Assignments
```
user_role: "admin"
is_admin: true
permissions: ["read", "write"]
```

## Safety & Ethics

 **Important:** This tool is designed for:
- **Authorized security testing**
- **Educational purposes**
- **Own application security**

Always ensure you have:
- Explicit permission to test target systems
- Proper authorization for security assessments
- Compliance with applicable laws and regulations

## Technical Details

### Browser Compatibility
- Chrome 60+
- Firefox 55+
- Edge 79+
- Safari 11+

### Performance Considerations
- Throttled requests to prevent server overload
- Configurable file size limits
- Smart domain filtering
- Memory-efficient data structures

### Privacy
- No data transmitted to external servers
- All processing happens locally in browser
- No tracking or analytics collection

## Troubleshooting

### Common Issues
1. **Script not running:** Check Tampermonkey is enabled
2. **No results found:** Page may be heavily obfuscated
3. **Performance issues:** Reduce `maxJSSize` or disable JS analysis
4. **False positives:** Adjust keyword lists in CONFIG

### Debug Mode
Enable console logging by setting:
```javascript
stealthMode: false
```
Results appear in browser console (F12).

## Contributing

Feel free to:
- Report bugs and issues
- Suggest new detection patterns
- Improve documentation
- Submit pull requests

## License

This tool is provided for educational and authorized security testing purposes. Users are responsible for ensuring compliance with applicable laws and regulations.

---

**Disclaimer:** Use only on systems you own or have explicit permission to test. The author is not responsible for misuse of this tool.
