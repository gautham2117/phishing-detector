# Ethical Use Declaration — Phishing Detection System

## Project Purpose

This system is built for educational and cybersecurity research purposes only.
It is designed to detect phishing threats in controlled, consensual environments.

## Permitted Uses

- Analyzing .eml files you own or have explicit written permission to analyze
- Scanning domains you own or have written authorization to scan
- Running on demo/test mailboxes (your own Gmail, Outlook test accounts)
- Academic research, hackathon demonstrations, portfolio projects
- Internal security awareness training with informed participants

## Prohibited Uses

- Monitoring any person's inbox without their written, informed consent
- Port-scanning third-party production systems without authorization
- Storing, processing, or transmitting real personally identifiable information (PII)
- Deploying as a surveillance or tracking tool
- Using extracted data beyond the scope of a single consented scan session

## Data Handling

- No real email content should ever be committed to version control
- All test data in /tests/sample_emails/ must be synthetic or publicly available samples
- The SQLite database must never contain real user credentials or private communications
- The .env file must never be committed (see .gitignore)

## Acknowledgment

By running this system, you agree to use it only within the boundaries above.
Unauthorized use may violate computer fraud laws (CFAA in the US, IT Act in India,
and equivalent laws in other jurisdictions).

Signed: Gautham P — 15-03-2026
