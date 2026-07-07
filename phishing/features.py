import re
import socket
import ssl
import whois
import dns.resolver
import tldextract
from urllib.parse import urlparse
from datetime import datetime
import requests
from bs4 import BeautifulSoup

# Features that originally relied on discontinued services 
# (Google PageRank API, Alexa web traffic rankings).
# We return a neutral placeholder (0) for these and document 
# this clearly as a known limitation rather than guessing.
UNAVAILABLE_FEATURES = ['web_traffic', 'Page_Rank']

SHORTENING_SERVICES = [
    'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly',
    'is.gd', 'buff.ly', 'adf.ly', 'tiny.cc', 'cutt.ly'
]

_whois_cache = {}

def get_whois_cached(domain):
    """
    Looks up WHOIS once per domain instead of once per feature.
    domain_registration_length, age_of_domain, and abnormal_url all 
    need WHOIS data — without this cache, the same slow lookup (and 
    the same timeout, for unregistered domains) happens 3 separate times.
    """
    if domain in _whois_cache:
        return _whois_cache[domain]
    try:
        result = whois.whois(domain)
    except Exception:
        result = None
    _whois_cache[domain] = result
    return result

def having_ip_address(url):
    domain = urlparse(url).netloc
    domain = domain.split(':')[0]
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return -1 if re.match(pattern, domain) else 1


def url_length(url):
    length = len(url)
    if length < 54:
        return 1
    elif 54 <= length <= 75:
        return 0
    return -1


def shortening_service(url):
    domain = urlparse(url).netloc
    return -1 if any(s in domain for s in SHORTENING_SERVICES) else 1


def having_at_symbol(url):
    return -1 if '@' in url else 1


def double_slash_redirecting(url):
    last_slash_pos = url.rfind('//')
    return -1 if last_slash_pos > 7 else 1


def prefix_suffix(url):
    domain = urlparse(url).netloc
    return -1 if '-' in domain else 1


def having_sub_domain(url):
    ext = tldextract.extract(url)
    subdomain = ext.subdomain
    if subdomain == '':
        return 1
    dots = subdomain.count('.')
    if dots == 0:
        return 0
    return -1


def ssl_final_state(url):
    try:
        domain = urlparse(url).netloc.split(':')[0]
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    return 1
    except Exception:
        return -1
    return -1


def domain_registration_length(url):
    try:
        domain = urlparse(url).netloc.split(':')[0]
        w = get_whois_cached(domain)
        if w is None:
            return -1
        exp_date = w.expiration_date
        if isinstance(exp_date, list):
            exp_date = exp_date[0]
        if exp_date is None:
            return -1
        days_left = (exp_date - datetime.now()).days
        return 1 if days_left > 365 else -1
    except Exception:
        return -1


def age_of_domain(url):
    try:
        domain = urlparse(url).netloc.split(':')[0]
        w = get_whois_cached(domain)
        if w is None:
            return -1
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation is None:
            return -1
        age_days = (datetime.now() - creation).days
        return 1 if age_days > 180 else -1
    except Exception:
        return -1


def abnormal_url(url):
    try:
        domain = urlparse(url).netloc.split(':')[0]
        w = get_whois_cached(domain)
        if w is None:
            return -1
        return 1 if w.domain_name else -1
    except Exception:
        return -1

def dns_record(url):
    try:
        domain = urlparse(url).netloc.split(':')[0]
        dns.resolver.resolve(domain, 'A')
        return 1
    except Exception:
        return -1


def google_index(url):
    # Without a live Google API, we approximate using DNS resolution
    # as a weak proxy signal (resolves = likely indexed, not a guarantee).
    # Documented limitation — see README.
    return dns_record(url)

def https_token(url):
    domain = urlparse(url).netloc
    return -1 if 'https' in domain.lower() else 1

def fetch_page_html(url):
    """Fetches the page once, reused across all HTML-based feature checks."""
    try:
        response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        return response.text, response.url
    except Exception:
        return None, None


def html_based_features(html, final_url, original_url):
    """
    Computes all HTML-parsing-dependent features in one pass over the 
    page source, since fetching the page is the slow/failure-prone part.
    """
    defaults = {
        'Favicon': -1, 'Request_URL': -1, 'URL_of_Anchor': -1,
        'Links_in_tags': -1, 'SFH': -1, 'Submitting_to_email': -1,
        'Redirect': -1, 'on_mouseover': -1, 'RightClick': -1,
        'popUpWidnow': -1, 'Iframe': -1, 'Links_pointing_to_page': -1
    }

    if html is None:
        # Page couldn't be fetched at all — treat as suspicious, 
        # since legitimate sites are usually reachable.
        return defaults

    try:
        soup = BeautifulSoup(html, 'lxml')
        domain = urlparse(original_url).netloc

        # Favicon: does it load from the same domain?
        favicon = soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')
        if favicon and favicon.get('href'):
            favicon_domain = urlparse(favicon['href']).netloc
            defaults['Favicon'] = 1 if (favicon_domain == '' or domain in favicon_domain) else -1
        else:
            defaults['Favicon'] = 1  # no favicon tag is common and not inherently suspicious

        # Request_URL: % of images/scripts/links loaded from a DIFFERENT domain
        tags = soup.find_all(['img', 'script', 'link'])
        external = 0
        total = 0
        for tag in tags:
            src = tag.get('src') or tag.get('href')
            if src and src.startswith('http'):
                total += 1
                if domain not in src:
                    external += 1
        if total > 0:
            pct_external = external / total
            defaults['Request_URL'] = 1 if pct_external < 0.22 else (0 if pct_external < 0.61 else -1)
        else:
            defaults['Request_URL'] = 1

        # URL_of_Anchor: % of <a> tags pointing elsewhere or using "#"/"javascript:void(0)"
        anchors = soup.find_all('a')
        suspicious_anchors = 0
        if anchors:
            for a in anchors:
                href = a.get('href', '')
                if href in ['#', ''] or 'javascript:void(0)' in href or (href.startswith('http') and domain not in href):
                    suspicious_anchors += 1
            pct = suspicious_anchors / len(anchors)
            defaults['URL_of_Anchor'] = 1 if pct < 0.31 else (0 if pct < 0.67 else -1)
        else:
            defaults['URL_of_Anchor'] = 1

        # Links_in_tags: meta/script/link tags pointing externally
        meta_links = soup.find_all(['meta', 'script', 'link'])
        external_meta = sum(1 for t in meta_links if t.get('content', '').startswith('http') and domain not in t.get('content', ''))
        defaults['Links_in_tags'] = 1 if external_meta == 0 else (0 if external_meta < 5 else -1)

        # SFH (Server Form Handler): does the form submit to a blank or external action?
        forms = soup.find_all('form')
        if forms:
            sfh_suspicious = False
            for form in forms:
                action = form.get('action', '')
                if action in ['', 'about:blank']:
                    sfh_suspicious = True
                elif action.startswith('http') and domain not in action:
                    sfh_suspicious = True
            defaults['SFH'] = -1 if sfh_suspicious else 1
        else:
            defaults['SFH'] = 1

        # Submitting_to_email: does any form submit via mailto:?
        mailto_found = any('mailto:' in form.get('action', '') for form in forms)
        defaults['Submitting_to_email'] = -1 if mailto_found else 1

        # Redirect: how many times did we get redirected to reach final_url?
        defaults['Redirect'] = -1 if final_url and final_url != original_url else 1

        # on_mouseover: JS that changes status bar / triggers on hover (classic phishing trick)
        page_text = html.lower()
        defaults['on_mouseover'] = -1 if 'onmouseover' in page_text else 1

        # RightClick: page disables right-click (often used to block "view source")
        defaults['RightClick'] = -1 if 'event.button==2' in page_text or 'contextmenu' in page_text else 1

        # popUpWidnow: page uses window.open / alert popups
        defaults['popUpWidnow'] = -1 if 'window.open(' in page_text or 'prompt(' in page_text else 1

        # Iframe: hidden iframes are a classic phishing/clickjacking technique
        iframes = soup.find_all('iframe')
        hidden_iframe = any('display:none' in str(f).replace(' ', '') or f.get('frameborder') == '0' for f in iframes)
        defaults['Iframe'] = -1 if hidden_iframe else (0 if iframes else 1)

        # Links_pointing_to_page: rough proxy using total anchor count found
        defaults['Links_pointing_to_page'] = 1 if len(anchors) > 2 else (0 if len(anchors) > 0 else -1)

    except Exception:
        pass

    return defaults

def extract_features(url):
    """
    Extracts a feature dictionary from a raw URL, matching the column 
    order the model was trained on. Features relying on discontinued 
    services (Page_Rank, web_traffic) return neutral placeholders (0) 
    — see README 'Known Limitations' section.
    """
    html, final_url = fetch_page_html(url)
    html_features = html_based_features(html, final_url, url)

    features = {
        'having_IP_Address': having_ip_address(url),
        'URL_Length': url_length(url),
        'Shortining_Service': shortening_service(url),
        'having_At_Symbol': having_at_symbol(url),
        'double_slash_redirecting': double_slash_redirecting(url),
        'Prefix_Suffix': prefix_suffix(url),
        'having_Sub_Domain': having_sub_domain(url),
        'SSLfinal_State': ssl_final_state(url),
        'Domain_registeration_length': domain_registration_length(url),
        'Favicon': html_features['Favicon'],
        'port': 1,
        'HTTPS_token': https_token(url),
        'Request_URL': html_features['Request_URL'],
        'URL_of_Anchor': html_features['URL_of_Anchor'],
        'Links_in_tags': html_features['Links_in_tags'],
        'SFH': html_features['SFH'],
        'Submitting_to_email': html_features['Submitting_to_email'],
        'Abnormal_URL': abnormal_url(url),
        'Redirect': html_features['Redirect'],
        'on_mouseover': html_features['on_mouseover'],
        'RightClick': html_features['RightClick'],
        'popUpWidnow': html_features['popUpWidnow'],
        'Iframe': html_features['Iframe'],
        'age_of_domain': age_of_domain(url),
        'DNSRecord': dns_record(url),
        'web_traffic': 0,   # UNAVAILABLE — Alexa API discontinued
        'Page_Rank': 0,     # UNAVAILABLE — Google PageRank API discontinued
        'Google_Index': google_index(url),
        'Links_pointing_to_page': html_features['Links_pointing_to_page'],
        'Statistical_report': 1
    }
    return features
