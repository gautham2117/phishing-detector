# Security Policy

## Supported Versions

1.0.x✅ < 1.0❌


| Version | Supported          |
| ------- | ------------------ |
| 5.1.x   | :white_check_mark: |
| 5.0.x   | :x:                |
| 4.0.x   | :white_check_mark: |
| < 4.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in PhishGuard or the Mahoraga Sentinel extension, please do not open a public GitHub issue.
Report it privately by emailing: gautham02117@gmail.com
Include the following in your report:

A clear description of the vulnerability
Steps to reproduce it
The component affected (Flask backend, FastAPI, Chrome extension, ML module, etc.)
Any proof-of-concept code or screenshots if applicable
Your assessment of the severity and potential impact

You can expect an acknowledgement within 48 hours and a resolution timeline within 7 days for critical issues.
Scope
The following are in scope for vulnerability reports:

backend/ — Flask and FastAPI servers, all API endpoints
chrome_extension/ — Manifest, background service worker, content scripts
backend/modules/ — All scanning and detection modules
backend/ml/ — Model loading and inference pipeline
Authentication, session handling, and secret management
SQL injection, XSS, or CSRF in any route or template
Unsafe deserialization or arbitrary code execution paths
CORS misconfiguration between FastAPI and the browser extension

The following are out of scope:

Vulnerabilities in third-party dependencies not introduced by this project
Rate limiting or DoS on localhost-only deployments
Issues that require physical access to the machine
Social engineering attacks

Security Architecture Notes
PhishGuard is designed to run locally on your own machine. The Flask server binds to 127.0.0.1:5000 and the FastAPI server to 127.0.0.1:8001. Neither is intended to be exposed to the public internet without additional hardening such as a reverse proxy, authentication middleware, and TLS termination.
The Chrome extension communicates exclusively with http://127.0.0.1:8001 and http://127.0.0.1:5000. No user data is sent to any external server. All ML inference runs locally.
Known Security Considerations

The SECRET_KEY in config.py must be set to a strong random value before any deployment beyond localhost.
The SQLite database stores scan history including URLs, email content snippets, and risk scores. Treat this file as sensitive data.
CORS in main.py allows null origin to support the Chrome extension. This is intentional for local use and should be restricted if the API is ever exposed externally.
YARA rule files and ML model weights are loaded from local paths. Ensure these directories have appropriate filesystem permissions.

Disclosure Policy
This project follows responsible disclosure. Once a fix is ready, the vulnerability will be documented in the release notes with credit to the reporter (unless anonymity is requested).
