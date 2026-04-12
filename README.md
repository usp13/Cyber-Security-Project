# ScamShield Django Project

A detailed Django-based cyber security project for analyzing suspicious links. The app includes a polished UI, working routes, templates for every page in the navigation, SQLite history storage, and a long-form URL analysis report.

## Included pages

- Home page
- Check Links page
- Detailed scan result page
- Scan history page
- Check IP page
- Check QR placeholder page
- Password generator page
- Contact page
- Logout placeholder page

## Main analysis coverage

The URL scanner attempts to collect and display:

- normalized URL and parsed components
- registered domain and subdomain breakdown
- entropy-based suspiciousness signal
- DNS records: A, AAAA, MX, NS, TXT, CNAME
- TLS certificate details such as issuer and expiry
- HTTP redirect chain and final URL
- HTML page indicators like forms, password fields, iframes, scripts, meta refresh, and suspicious script patterns
- WHOIS information and approximate domain age
- URLhaus check
- optional VirusTotal check when you provide an API key
- risk score, verdict, reasons, and summary

## Important note

No detector can be truly perfect. This project is a strong educational and portfolio-ready base, but real-world malicious links can still evade static or heuristic checks.

## Setup

```bash
cd scamshield_django
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

Then open:

```text
http://127.0.0.1:8000/
```

## Optional VirusTotal key

Windows Command Prompt:

```bash
set VIRUSTOTAL_API_KEY=your_api_key_here
python manage.py runserver
```

PowerShell:

```powershell
$env:VIRUSTOTAL_API_KEY="your_api_key_here"
python manage.py runserver
```

## Main files to edit

- `scanner/services.py` for scanning logic
- `scanner/views.py` for page behavior
- `scanner/templates/scanner/` for all app templates
- `static/css/styles.css` for the complete UI styling

## Why this zip avoids your earlier errors

- all named views are present in `scanner/views.py`
- all routes are present in `scanner/urls.py`
- every linked page has a template file
- Django settings already include the top-level `templates` directory
- the app uses app-level templates too, so render paths are stable

## Suggested next upgrades

- QR image upload and decoding
- export PDF report
- login and signup system
- dashboard charts
- REST API using Django REST Framework
- deploy to Render or Railway
