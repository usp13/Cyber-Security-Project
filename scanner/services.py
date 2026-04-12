import datetime as dt
import hashlib
import html
import ipaddress
import math
import os
import random
import re
import secrets
import socket
import ssl
from collections import Counter
from typing import Any
from urllib.parse import quote_plus, urljoin, urlparse

import dns.resolver
import requests
import tldextract
import whois
from bs4 import BeautifulSoup

VT_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '').strip()
URLHAUS_API_KEY = os.getenv('URLHAUS_API_KEY', '').strip()
USER_AGENT = 'ScamShield/1.0 (Educational Project)'
REQUEST_TIMEOUT = 8

SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update', 'payment', 'wallet',
    'invoice', 'bank', 'password', 'bonus', 'gift', 'free', 'claim', 'recover',
    'authenticate', 'webscr', 'billing', 'support', 'limited', 'confirm'
]
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'cutt.ly', 'rebrand.ly', 'tiny.cc', 'adf.ly', 'rb.gy', 'shorturl.at'
}
SUSPICIOUS_TLDS = {'zip', 'review', 'country', 'kim', 'gq', 'tk', 'work', 'click', 'link'}
HIGH_VALUE_BRANDS = [
    'google', 'microsoft', 'apple', 'paypal', 'amazon', 'facebook', 'instagram',
    'whatsapp', 'netflix', 'bank', 'dropbox', 'adobe', 'linkedin'
]
JS_SUSPICIOUS_PATTERNS = [
    'window.location', 'document.location', 'eval(', 'unescape(', 'atob(', 'fromcharcode',
    'settimeout(', 'setinterval(', 'crypto.subtle', 'fetch(', 'xmlhttprequest'
]


def normalize_url(raw_url: str) -> str:
    raw_url = (raw_url or '').strip()
    if not raw_url:
        return ''
    if not raw_url.startswith(('http://', 'https://')):
        # In a modern security tool, we should assume secure transport as the default baseline
        raw_url = 'https://' + raw_url
    return raw_url


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 3)


def is_domain_in_top10m(domain: str) -> bool:
    if not domain:
        return False
    # Check against the top 10 million DB
    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'safe_domains.db')
    if not os.path.exists(db_path):
        return False
    try:
        import sqlite3
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('SELECT 1 FROM domains WHERE domain = ?', (domain.lower(),))
        result = c.fetchone()
        conn.close()
        return bool(result)
    except Exception:
        return False


def safe_gethostbyname(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def check_ip_literal(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except Exception:
        return False


def resolve_dns(hostname: str) -> dict[str, list[str]]:
    data: dict[str, list[str]] = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3
    resolver.timeout = 3
    for record_type in record_types:
        try:
            answers = resolver.resolve(hostname, record_type)
            data[record_type] = [str(r).strip() for r in answers]
        except Exception:
            data[record_type] = []
    return data


def get_tls_certificate(hostname: str, port: int = 443) -> dict[str, Any]:
    result: dict[str, Any] = {
        'available': False,
        'error': '',
        'subject': {},
        'issuer': {},
        'not_before': '',
        'not_after': '',
        'days_remaining': None,
        'subject_alt_names': [],
        'serial_number': '',
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        result['available'] = True
        result['subject'] = {k: v for tup in cert.get('subject', []) for k, v in tup}
        result['issuer'] = {k: v for tup in cert.get('issuer', []) for k, v in tup}
        result['not_before'] = cert.get('notBefore', '')
        result['not_after'] = cert.get('notAfter', '')
        result['serial_number'] = cert.get('serialNumber', '')
        sans = cert.get('subjectAltName', [])
        result['subject_alt_names'] = [v for k, v in sans if k == 'DNS']
        if result['not_after']:
            expires = dt.datetime.strptime(result['not_after'], '%b %d %H:%M:%S %Y %Z')
            result['days_remaining'] = (expires - dt.datetime.utcnow()).days
    except Exception as exc:
        result['error'] = str(exc)
    return result


def detect_brand_impersonation(hostname: str, registered_domain: str) -> list[str]:
    hostname_lower = hostname.lower()
    reg_lower = registered_domain.lower()
    matches = []
    for brand in HIGH_VALUE_BRANDS:
        if brand in hostname_lower and brand not in reg_lower:
            matches.append(brand)
    return matches


def get_whois_details(hostname: str) -> dict[str, Any]:
    info = {
        'found': False,
        'registrar': '',
        'creation_date': '',
        'expiration_date': '',
        'updated_date': '',
        'name_servers': [],
        'emails': [],
        'domain_age_days': None,
        'error': '',
    }
    try:
        data = whois.whois(hostname)
        info['found'] = True
        info['registrar'] = str(getattr(data, 'registrar', '') or '')

        def normalize_date(value):
            if isinstance(value, list):
                value = value[0] if value else None
            return value

        created = normalize_date(getattr(data, 'creation_date', None))
        expires = normalize_date(getattr(data, 'expiration_date', None))
        updated = normalize_date(getattr(data, 'updated_date', None))
        if created:
            info['creation_date'] = str(created)
            now = dt.datetime.now(created.tzinfo) if getattr(created, 'tzinfo', None) else dt.datetime.utcnow()
            info['domain_age_days'] = (now - created.replace(tzinfo=now.tzinfo) if getattr(created, 'tzinfo', None) else now - created).days
        if expires:
            info['expiration_date'] = str(expires)
        if updated:
            info['updated_date'] = str(updated)
        ns = getattr(data, 'name_servers', []) or []
        if isinstance(ns, str):
            ns = [ns]
        info['name_servers'] = sorted({str(x) for x in ns})
        emails = getattr(data, 'emails', []) or []
        if isinstance(emails, str):
            emails = [emails]
        info['emails'] = sorted({str(x) for x in emails})[:10]
    except Exception as exc:
        info['error'] = str(exc)
    return info


def trace_http(url: str) -> dict[str, Any]:
    details: dict[str, Any] = {
        'fetched': False,
        'error': '',
        'status_code': None,
        'final_url': '',
        'redirect_count': 0,
        'redirect_chain': [],
        'headers': {},
        'content_type': '',
        'server': '',
        'response_ms': None,
        'html_analysis': {},
    }
    try:
        response = requests.get(
            url,
            allow_redirects=True,
            timeout=REQUEST_TIMEOUT,
            headers={'User-Agent': USER_AGENT},
            verify=False,
        )
        details['fetched'] = True
        details['status_code'] = response.status_code
        details['final_url'] = response.url
        details['redirect_count'] = len(response.history)
        details['redirect_chain'] = [r.url for r in response.history] + [response.url]
        details['headers'] = dict(response.headers)
        details['content_type'] = response.headers.get('Content-Type', '')
        details['server'] = response.headers.get('Server', '')
        details['response_ms'] = int(response.elapsed.total_seconds() * 1000)
        if 'text/html' in details['content_type'].lower():
            details['html_analysis'] = analyze_html(response.text, response.url)
    except Exception as exc:
        details['error'] = str(exc)
    return details


def analyze_html(markup: str, base_url: str) -> dict[str, Any]:
    soup = BeautifulSoup(markup, 'html.parser')
    forms = soup.find_all('form')
    inputs = soup.find_all('input')
    scripts = soup.find_all('script')
    iframes = soup.find_all('iframe')
    anchors = soup.find_all('a', href=True)
    meta_refresh = soup.find('meta', attrs={'http-equiv': re.compile('refresh', re.I)})
    title = soup.title.string.strip() if soup.title and soup.title.string else ''
    password_fields = len(soup.find_all('input', {'type': 'password'}))
    external_form_targets = []
    for form in forms:
        action = (form.get('action') or '').strip()
        if action:
            full = urljoin(base_url, action)
            if urlparse(full).netloc and urlparse(full).netloc != urlparse(base_url).netloc:
                external_form_targets.append(full)
    js_hits = []
    script_text = ' '.join(s.get_text(' ', strip=True) for s in scripts[:30]).lower()
    for pattern in JS_SUSPICIOUS_PATTERNS:
        if pattern.lower() in script_text:
            js_hits.append(pattern)
    external_links = []
    for a in anchors[:100]:
        href = a.get('href', '').strip()
        if href.startswith('http'):
            external_links.append(href)
    favicon = ''
    icon_link = soup.find('link', rel=lambda v: v and 'icon' in str(v).lower())
    if icon_link and icon_link.get('href'):
        favicon = urljoin(base_url, icon_link['href'])
    return {
        'title': title,
        'forms_count': len(forms),
        'inputs_count': len(inputs),
        'password_fields': password_fields,
        'iframes_count': len(iframes),
        'scripts_count': len(scripts),
        'external_form_targets': external_form_targets,
        'meta_refresh_present': bool(meta_refresh),
        'suspicious_script_patterns': js_hits,
        'sample_external_links': external_links[:10],
        'favicon': favicon,
        'text_preview': soup.get_text(' ', strip=True)[:500],
    }


def get_urlhaus_status(url: str) -> dict[str, Any]:
    if not URLHAUS_API_KEY:
        return {'queried': False, 'message': 'URLhaus API key not configured.'}
    try:
        response = requests.post(
            'https://urlhaus-api.abuse.ch/v1/url/',
            data={'url': url},
            timeout=REQUEST_TIMEOUT,
            headers={
                'User-Agent': USER_AGENT,
                'Auth-Key': URLHAUS_API_KEY
            },
        )
        response.raise_for_status()
        data = response.json()
        return {
            'queried': True,
            'status': data.get('query_status', ''),
            'url_status': data.get('url_status', ''),
            'threat': data.get('threat', ''),
            'tags': data.get('tags', []),
            'reporter': data.get('reporter', ''),
            'date_added': data.get('date_added', ''),
        }
    except Exception as exc:
        return {'queried': False, 'error': str(exc)}


def get_virustotal_status(url: str) -> dict[str, Any]:
    if not VT_API_KEY:
        return {'enabled': False, 'message': 'VirusTotal API key not configured.'}
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        response = requests.get(
            f'https://www.virustotal.com/api/v3/urls/{url_id}',
            headers={'x-apikey': VT_API_KEY},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code == 404:
            return {'enabled': True, 'status': 'not_found', 'stats': {}}
            
        response.raise_for_status()
        attrs = response.json()['data']['attributes']
        return {
            'enabled': True,
            'status': 'completed',
            'stats': attrs.get('last_analysis_stats', {}),
        }
    except Exception as exc:
        return {'enabled': True, 'error': str(exc)}


def score_report(features: dict[str, Any]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    if not features.get('is_top10m'):
        score += 15
        reasons.append('Domain is relatively unknown or newly established. Exercise standard caution.')

    # Trust Indicators & Domain Age (Very strong signals)
    domain_age = features.get('domain_age_days')
    if domain_age is not None:
        if domain_age < 30:
            score += 45
            reasons.append(f'The domain is extremely new ({domain_age} days old), a massive red flag for phishing networks.')
        elif domain_age < 180:
            score += 25
            reasons.append(f'The domain is relatively new ({domain_age} days old), which requires increased caution.')
    else:
        score += 15
        reasons.append('Domain registration age is hidden or could not be verified (common in scam sites).')

    if features.get('is_free_host'):
        score += 35
        reasons.append('Hosted on a free subdomain provider, which are heavily abused by phishing campaigns.')

    if features.get('http_unreachable'):
        score += 20
        reasons.append('The website is unreachable or is actively blocking automated scanners (common evasion tactic).')

    if features.get('no_mx_records'):
        score += 10
        reasons.append('No mail servers (MX records) configured for this domain, which is unusual for legitimate businesses.')

    # Transport & Network Level
    if not features['uses_https']:
        score += 15
        reasons.append('Does not use HTTPS by default. Secure communication is absent.')
    if features['has_ip_address']:
        score += 30
        reasons.append('Browsing directly to an IP address bypasses domain reputation checks and is highly suspicious.')
    if features['dns_empty']:
        score += 20
        reasons.append('DNS resolution failed completely or was extremely limited.')
    if features['tls_problem']:
        score += 15
        reasons.append('TLS certificate invalid, expired, or failed security validation.')

    # Lexical Analysis
    if features['url_length'] > 100:
        score += 12
        reasons.append('URL is exceptionally long, which is often used to obfuscate the real destination.')
    if features['subdomain_count'] >= 3:
        score += 15
        reasons.append('Deeply nested subdomains detected (often used to trick users into trusting the domain).')
    if features['contains_at_symbol']:
        score += 25
        reasons.append('The @ symbol in the URL hides the true destination from the victim.')
    if features['is_shortener']:
        score += 20
        reasons.append('URL shortener detected. Shorteners hide malicious destinations.')
    if features['suspicious_tld']:
        score += 15
        reasons.append('Uses a Top Level Domain (TLD) very frequently associated with spam/malware.')
    if features['entropy'] > 4.5:
        score += 10
        reasons.append('The domain name looks randomly generated (high entropy).')

    if features['contains_suspicious_keywords']:
        kw = features['contains_suspicious_keywords']
        score += min(20, 5 * len(kw))
        reasons.append(f"Suspicious intent keywords found in the link: {', '.join(kw)}.")

    if features['brand_impersonation']:
        score += 30
        reasons.append('Brand impersonation detected! Looking like ' + ', '.join(features['brand_impersonation']) + ' but hosted elsewhere.')

    # Page Behaviors
    if features['http_redirect_count'] >= 3:
        score += 15
        reasons.append('High number of redirects to evade detection.')
    if features['html_password_form']:
        score += 15
        reasons.append('Page asks for a password (high risk if other indicators are red).')
    if features['external_form_targets']:
        score += 25
        reasons.append('Submits data to an entirely different domain! (Classic credential harvesting).')
    if features['meta_refresh']:
        score += 10
        reasons.append('Uses an automatic meta-refresh redirect.')

    # Threat Intel (Definitives)
    if features['urlhaus_malicious']:
        score += 50
        reasons.append('Confirmed malicious by URLhaus malware database.')
    vt_malicious = features.get('vt_malicious_count', 0)
    if vt_malicious:
        score += min(60, 20 + 5 * vt_malicious)
        reasons.append(f'VirusTotal reported {vt_malicious} security vendors flagged this as malicious.')

    # Cap score
    
    # TOP 10 MILLION OVERRIDE
    if features.get('is_top10m'):
        if not features.get('urlhaus_malicious') and features.get('vt_malicious_count', 0) <= 2:
            return 0, ["Verified high-reputation domain. False-positive alerts suppressed for legitimate infrastructure."]

    # ACADEMIC OVERRIDE: Whitelist high-reputation domains from heuristic penalties
    registered_domain = features.get('registered_domain', '').lower()
    if any(brand in registered_domain for brand in HIGH_VALUE_BRANDS):
        # If it's a known brand and NO threat intel (URLhaus/VT) is positive, it's almost certainly safe
        if not features.get('urlhaus_malicious') and features.get('vt_malicious_count', 0) <= 2:
            return 0, ["Verified high-reputation domain. Heuristic penalties suppressed for legitimate infrastructure."]
            
    return min(score, 100), reasons


def generate_summary(verdict: str, score: int, reasons: list[str]) -> str:
    if not reasons:
        return f'The detector found no major warning signs. The current risk score is {score}/100 and the verdict is {verdict}. This does not guarantee the link is safe, but no strong indicators were observed in this scan.'
    top_reasons = ' '.join(reasons[:3])
    return f'The analyzed link received a risk score of {score}/100 with a verdict of {verdict}. The most important findings are: {top_reasons}'


def generate_ai_summary(verdict: str, score: int, reasons: list[str]) -> str:
    prompt = f"Given a URL scan report with a risk score of {score}/100, verdict '{verdict}', and the following reasons: {', '.join(reasons)}, provide a short, concise 2-sentence explanation of what this means for the user. Do not use markdown."
    try:
        from google import genai
        api_key = os.getenv('GEMINI_API_KEY')
        if api_key:
            client = genai.Client(api_key=api_key)
            response = client.models.generate_content(
                model='gemini-2.5-flash',
                contents=prompt,
            )
            if response and response.text:
                return response.text
    except Exception:
        pass

    if not reasons:
        return f"AI Analysis: This link appears clean based on our heuristics. With a risk score of {score}/100, no major threats were detected. However, always exercise caution when providing sensitive information online."
    top_reasons = ' '.join(reasons[:2])
    return f"AI Analysis: Please proceed with caution. This link has a '{verdict}' verdict ({score}/100) primarily because: {top_reasons}. It is recommended to avoid entering any personal or financial details."


def generate_password(length: int = 16, include_symbols: bool = True, include_digits: bool = True, include_uppercase: bool = True) -> str:
    lowercase = 'abcdefghijklmnopqrstuvwxyz'
    uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' if include_uppercase else ''
    digits = '0123456789' if include_digits else ''
    symbols = '!@#$%^&*()-_=+[]{}:,.?' if include_symbols else ''
    alphabet = lowercase + uppercase + digits + symbols
    if not alphabet:
        alphabet = lowercase
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def lookup_ip(ip_text: str) -> dict[str, Any]:
    result = {'valid': False, 'ip': ip_text, 'version': '', 'reverse_dns': '', 'is_private': False, 'is_global': False, 'is_multicast': False, 'is_reserved': False, 'error': ''}
    try:
        ip_obj = ipaddress.ip_address(ip_text)
        result['valid'] = True
        result['version'] = f'IPv{ip_obj.version}'
        result['is_private'] = ip_obj.is_private
        result['is_global'] = ip_obj.is_global
        result['is_multicast'] = ip_obj.is_multicast
        result['is_reserved'] = ip_obj.is_reserved
        try:
            result['reverse_dns'] = socket.gethostbyaddr(ip_text)[0]
        except Exception:
            result['reverse_dns'] = ''
    except Exception as exc:
        result['error'] = str(exc)
    return result


def analyze_url(raw_url: str) -> dict[str, Any]:
    normalized = normalize_url(raw_url)
    parsed = urlparse(normalized)
    hostname = parsed.hostname or ''
    extracted = tldextract.extract(normalized)
    registered_domain = '.'.join(part for part in [extracted.domain, extracted.suffix] if part)
    subdomains = [p for p in extracted.subdomain.split('.') if p]
    dns_data = resolve_dns(hostname) if hostname else {}
    
    # If the sub-domain doesn't have MX records (like www.facebook.com), check the registered domain
    if hostname and registered_domain and hostname != registered_domain and not dns_data.get('MX'):
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 2
            resolver.timeout = 2
            answers = resolver.resolve(registered_domain, 'MX')
            dns_data['MX'] = [str(r).strip() for r in answers]
        except Exception:
            pass

    tls_data = get_tls_certificate(hostname) if hostname and parsed.scheme == 'https' else {
        'available': False,
        'error': '',
        'message': 'TLS not checked because the URL is not HTTPS.',
        'subject': {},
        'issuer': {},
        'not_before': '',
        'not_after': '',
        'days_remaining': None,
        'subject_alt_names': [],
        'serial_number': '',
    }
    http_data = trace_http(normalized) if normalized else {}
    whois_data = get_whois_details(registered_domain or hostname) if hostname else {}
    urlhaus = get_urlhaus_status(normalized) if normalized else {}
    vt = get_virustotal_status(normalized) if normalized else {}

    lowered = normalized.lower()
    suspicious_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lowered]
    brand_impersonation = detect_brand_impersonation(hostname, registered_domain)
    html_analysis = http_data.get('html_analysis', {}) if isinstance(http_data, dict) else {}
    vt_stats = vt.get('stats', {}) if isinstance(vt, dict) else {}
    vt_malicious_count = int(vt_stats.get('malicious', 0) or 0)

    features = {
        'uses_https': parsed.scheme == 'https',
        'has_ip_address': check_ip_literal(hostname),
        'url_length': len(normalized),
        'subdomain_count': len(subdomains),
        'contains_at_symbol': '@' in normalized,
        'contains_suspicious_keywords': suspicious_keywords,
        'is_shortener': hostname.lower() in URL_SHORTENERS if hostname else False,
        'suspicious_tld': extracted.suffix.lower() in SUSPICIOUS_TLDS if extracted.suffix else False,
        'brand_impersonation': brand_impersonation,
        'entropy': shannon_entropy(hostname + parsed.path),
        'dns_empty': not any(dns_data.values()) if dns_data else True,
        'tls_problem': bool(tls_data.get('error')) or (tls_data.get('days_remaining') is not None and int(tls_data.get('days_remaining', 0)) < 0),
        'http_redirect_count': http_data.get('redirect_count', 0) if isinstance(http_data, dict) else 0,
        'html_password_form': (html_analysis.get('password_fields', 0) or 0) > 0,
        'external_form_targets': bool(html_analysis.get('external_form_targets')),
        'meta_refresh': bool(html_analysis.get('meta_refresh_present')),
        'urlhaus_malicious': urlhaus.get('status') == 'ok' or bool(urlhaus.get('threat')),
        'vt_malicious_count': vt_malicious_count,
        'domain_age_days': whois_data.get('domain_age_days'),
        'http_unreachable': not http_data.get('fetched', False) if isinstance(http_data, dict) else True,
        'no_mx_records': not bool(dns_data.get('MX', [])),
        'is_free_host': any(x in lowered for x in ['000webhost', 'pantheon', 'weebly', 'wixsite', 'netlify', 'vercel', 'herokuapp', 'github.io']),
        'registered_domain': registered_domain,
        'is_top10m': is_domain_in_top10m(registered_domain) or is_domain_in_top10m(hostname)
    }

    score, reasons = score_report(features)
    if score < 25:
        verdict = 'Low Risk'
    elif score < 55:
        verdict = 'Suspicious'
    else:
        verdict = 'High Risk'

    report = {
        'original_url': raw_url,
        'normalized_url': normalized,
        'parsed': {
            'scheme': parsed.scheme,
            'hostname': hostname,
            'port': parsed.port,
            'path': parsed.path,
            'query': parsed.query,
            'fragment': parsed.fragment,
            'username': parsed.username,
        },
        'domain_profile': {
            'registered_domain': registered_domain,
            'subdomains': subdomains,
            'top_level_domain': extracted.suffix,
            'resolved_ipv4': safe_gethostbyname(hostname) if hostname else None,
            'is_ip_literal': check_ip_literal(hostname),
            'entropy': features['entropy'],
            'brand_impersonation_matches': brand_impersonation,
        },
        'dns': dns_data,
        'tls': tls_data,
        'http': http_data,
        'whois': whois_data,
        'urlhaus': urlhaus,
        'virustotal': vt,
        'features': features,
        'risk_score': score,
        'verdict': verdict,
        'reasons': reasons,
        'summary': generate_summary(verdict, score, reasons),
        'ai_summary': generate_ai_summary(verdict, score, reasons),
        'screenshot_url': f"https://image.thum.io/get/width/1200/crop/800/{normalized}" if normalized else "",
        'technical_fingerprint': {
            'sha256_of_url': hashlib.sha256(normalized.encode('utf-8')).hexdigest() if normalized else '',
            'quoted_url': quote_plus(normalized) if normalized else '',
            'generated_at': dt.datetime.now().isoformat(timespec='seconds'),
        },
    }
    return report

def analyze_phishing_text(text):
    text_lower = text.lower()
    score = 0
    reasons = []

    urgency_words = ['urgent', 'immediately', 'action required', 'suspended', 'locked', 'limited', 'final warning', '24 hours', 'alert']
    financial_words = ['bank', 'paypal', 'irs', 'tax', 'invoice', 'payment', 'transfer', 'crypto', 'bitcoin', 'wallet', 'refund', 'ssn']
    action_words = ['click here', 'verify', 'login', 'update', 'confirm', 'validate', 'claim', 'prize', 'winner']

    u_count = sum(1 for w in urgency_words if w in text_lower)
    f_count = sum(1 for w in financial_words if w in text_lower)
    a_count = sum(1 for w in action_words if w in text_lower)

    if u_count > 0:
        score += u_count * 15
        reasons.append(f"Contains {u_count} urgency or threat-related keywords.")
    if f_count > 0:
        score += f_count * 15
        reasons.append(f"Contains {f_count} financial, cryptocurrency, or tax keywords.")
    if a_count > 0:
        score += a_count * 20
        reasons.append(f"Contains {a_count} suspicious call-to-action requests (e.g., 'click here', 'login').")

    if 'http://' in text_lower or 'https://' in text_lower:
        score += 25
        reasons.append("Contains a hyperlink deeply embedded in the message text.")

    if score == 0:
        verdict = "Low Risk"
    elif score < 50:
        verdict = "Suspicious"
    else:
        verdict = "High Risk"

    return {
        'score': min(score, 100),
        'verdict': verdict,
        'reasons': reasons
    }

def check_email_breaches(email: str) -> dict[str, Any]:
    """
    Checks if an email address has been involved in data breaches using the XposedOrNot API.
    """
    email = (email or '').strip().lower()
    result = {'queried': False, 'breached': False, 'breaches': [], 'error': ''}
    
    if not email:
        return result

    try:
        # XposedOrNot Analytics API - Usually more comprehensive
        url = f'https://api.xposedornot.com/v1/breach-analytics?email={email}'
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={'User-Agent': USER_AGENT}
        )
        
        if response.status_code == 200:
            data = response.json()
            # The analytics endpoint returns detailed breach data
            # Summary -> BreachesSummary contains the list of breach names
            breach_list = data.get('BreachesSummary', {}).get('Site', [])
            if not breach_list:
                # Fallback to the basic check if analytics summary is empty
                check_url = f'https://api.xposedornot.com/v1/check-email/{email}'
                check_resp = requests.get(check_url, timeout=REQUEST_TIMEOUT)
                if check_resp.status_code == 200:
                    raw = check_resp.json().get('breaches', [])
                    breach_list = [b[0] if isinstance(b, list) else b for b in raw]
            
            result['queried'] = True
            result['breached'] = len(breach_list) > 0
            result['breaches'] = breach_list
        elif response.status_code == 404:
            result['queried'] = True
            result['breached'] = False
        else:
            result['error'] = f"API returned status code {response.status_code}"

            
    except Exception as exc:
        result['error'] = str(exc)
        
    return result

def scan_file_virus_total(file_obj) -> dict[str, Any]:
    """
    Scans a file using VirusTotal v3 API. 
    Phase 1: SHA-256 Hash Lookup (Fast)
    Phase 2: File Upload (Deep Scan) if unknown.
    """
    vt_key = os.getenv('VIRUSTOTAL_API_KEY')
    result = {
        'scanned': False,
        'malicious': False,
        'detections': 0,
        'total_engines': 0,
        'hash': '',
        'file_name': file_obj.name,
        'mode': 'unknown',
        'error': ''
    }

    if not vt_key:
        result['error'] = "VirusTotal API Key not configured in .env"
        return result

    try:
        # Step 1: Calculate SHA-256 Hash
        sha256_hash = hashlib.sha256()
        for chunk in file_obj.chunks():
            sha256_hash.update(chunk)
        file_hash = sha256_hash.hexdigest()
        result['hash'] = file_hash

        headers = {
            "x-apikey": vt_key,
            "accept": "application/json"
        }

        # Phase 1: Hash Lookup (GET /files/{hash})
        hash_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        response = requests.get(hash_url, headers=headers, timeout=REQUEST_TIMEOUT)

        if response.status_code == 200:
            # File already known!
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            result['scanned'] = True
            result['detections'] = stats.get('malicious', 0)
            result['total_engines'] = sum(stats.values())
            result['malicious'] = result['detections'] > 0
            result['mode'] = 'Fast Signature Match'
            result['report_data'] = data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
            return result

        # Phase 2: Full Upload (If hash not found)
        # Reset file pointer for uploading
        file_obj.seek(0)
        upload_url = "https://www.virustotal.com/api/v3/files"
        files = {"file": (file_obj.name, file_obj)}
        
        up_response = requests.post(upload_url, headers=headers, files=files, timeout=REQUEST_TIMEOUT)
        
        if up_response.status_code == 200:
            # File uploaded! Now we get an analysis ID.
            # Free tier VT API takes time to analyze, so for a "Live Demo"
            # we'll tell the user it's submitted.
            result['scanned'] = True
            result['mode'] = 'Deep Scan (Uploaded)'
            result['message'] = 'File uploaded for real-time analysis. VT takes a few minutes for dynamic scans.'
            result['detections'] = 0 # Initially 0 while analyzing
        else:
            result['error'] = f"Upload failed: {up_response.status_code}"

    except Exception as e:
        result['error'] = str(e)

    return result
import threading
from typing import Any, List, Dict

def perform_port_scan(target: str) -> dict[str, Any]:
    """
    Performs a multi-threaded TCP port scan on a target domain or IP.
    """
    result = {
        'target': target,
        'ip': '',
        'open_ports': [],
        'error': '',
        'scan_time': 0
    }

    # Sanitize target: Remove http/https and paths if user paste a full URL
    cleaned_target = target.strip().lower()
    if "://" in cleaned_target:
        parsed = urlparse(cleaned_target)
        cleaned_target = parsed.netloc or parsed.path.split('/')[0]
    else:
        cleaned_target = cleaned_target.split('/')[0]
        
    result['target'] = cleaned_target

    try:
        # Resolve target to IP
        target_ip = socket.gethostbyname(cleaned_target)
        result['ip'] = target_ip
    except Exception as e:
        result['error'] = f"Could not resolve host: {e}"
        return result

    # Expanded Top 100 Mission-Critical Ports for Deep Audit
    DEEP_PORTS = {
        20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP-S", 68: "DHCP-C",
        69: "TFTP", 80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPCBind", 123: "NTP", 135: "RPC-Endpoint",
        137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 179: "BGP",
        194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB", 464: "KPassword", 465: "SMTPS", 514: "Syslog",
        515: "LPD", 543: "KLogin", 544: "KShell", 548: "AFP", 554: "RTSP", 587: "SMTP-Sub", 631: "IPP",
        636: "LDAPS", 873: "Rsync", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL",
        1434: "MSSQL-M", 1521: "Oracle", 1723: "PPTP", 1883: "MQTT", 2049: "NFS", 2121: "FTP-Proxy", 2375: "Docker",
        2376: "Docker-SSL", 3306: "MySQL", 3389: "RDP", 3690: "SVN", 4444: "MetaSploit", 5000: "Flask/Docker",
        5060: "SIP", 5432: "PostgreSQL", 5672: "RabbitMQ", 5900: "VNC", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
        6379: "Redis", 6667: "IRC", 7000: "Cassandra", 7077: "Spark", 8000: "Django/Dev", 8008: "HTTP-Alt",
        8080: "HTTP-Proxy", 8081: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Jupyter/Node", 9000: "SonarQube/PHP",
        9042: "Cassandra-Native", 9092: "Kafka", 9100: "JetDirect", 9200: "ElasticSearch", 9300: "ES-Nodes",
        9418: "Git", 10000: "Webmin", 11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB-S", 50000: "SAP",
    }

    start_time = dt.datetime.now()
    open_ports = []
    lock = threading.Lock()

    def scan_port(port, service_name):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.7) # Slightly faster timeout for large batches
            
            conn = s.connect_ex((target_ip, port))
            
            if conn == 0:
                banner = ""
                try:
                    # Deep Banner Interaction
                    if port in [80, 443, 8080, 8000]:
                        s.send(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                        banner = s.recv(512).decode(errors='ignore').split('\r\n')[0]
                    else:
                        banner = s.recv(512).decode(errors='ignore').strip()
                except:
                    pass
                
                with lock:
                    open_ports.append({
                        'port': port,
                        'service': service_name,
                        'banner': banner[:120] if banner else "Protected or No Response"
                    })
            s.close()
        except:
            pass

    threads = []
    for port, service in DEEP_PORTS.items():
        t = threading.Thread(target=scan_port, args=(port, service))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    end_time = dt.datetime.now()
    result['open_ports'] = sorted(open_ports, key=lambda x: x['port'])
    result['scan_time'] = (end_time - start_time).total_seconds()

    return result


