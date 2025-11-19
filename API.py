
# # import Utils

# # # Returns score (0-180) , 0 is malicious 100 is safest site
# # def get_prediction(url, model):

# #     output = {
# #         "SCORE": 180,
# #         "InTop1Million": False,
# #         "InURLVoidBlackList": False,
# #         "isHTTPS": True,
# #         "hasSSLCertificate": True,
# #         "GoogleSafePassed": True,
# #         "NortanWebSafePassed": True,
# #         "InMcaffeBlackList": False,
# #         "InSucuriBlacklist": False,
# #         "isTemporaryDomain": False,
# #         "isOlderThan3Months": True,
# #         "isBlackListedinIpSets": False,
# #         "target_urls": None
# #     }

# #     # -------------------------------------------------

# #     try:
# #         # Finding Possible Target URLs
# #         print("Finding Target URLs...")
# #         target_urls = Utils.find_target_urls(url, 8)
# #         output["target_urls"] = target_urls
# #     except:
# #         print("Error Occured while finding target Urls !")

# #     # ------------------------------------------------------

# #     # Check Top 1 million valid sites
# #     if Utils.check_top1million_database(url):
# #         output["InTop1Million"] = True

# #     # Check the domain in Top 1 million valid sites
# #     if Utils.check_top1million_database_2(url):
# #         output["InTop1Million"] = True

# #     if output["InTop1Million"] == True:
# #         # If URL is already valid no need to check further.
# #         return output

# #     # Check 40 blacklist sources
# #     if Utils.checkURLVoid(url) > 0:
# #         output["SCORE"] = output["SCORE"] - 20
# #         output["InURLVoidBlackList"] = True
# #         print("URL is blacklisted in UrlVoid's system !")
# #     else:
# #         print("URL is Safe in UrlVoid's system !")

# #     # Check if it has SSL certififcate
# #     if Utils.check_ssl_certificate(url) != True:
# #         output["hasSSLCertificate"] = False
# #         print("URL has not SSL Certificate !")
# #         output["SCORE"] = output["SCORE"] - 20

# #     # Check if HTTP/HTTPS. # If SSL present then it's already HTTPS safe
# #     if output["hasSSLCertificate"] != True and Utils.is_https(url) != True:
# #         print("URL is not HTTP secure")
# #         output["isHTTPS"] = False

# #     if Utils.check_google_safe_browsing(url) != True:
# #         output["GoogleSafePassed"] = False
# #         output["SCORE"] = output["SCORE"] - 20

# #     if Utils.check_Nortan_WebSafe(url) != True:
# #         output["NortanWebSafePassed"] = False
# #         output["SCORE"] = output["SCORE"] - 20

# #     if Utils.check_mcafee_database(url) != True:
# #         output["InMcaffeBlackList"] = True
# #         output["SCORE"] = output["SCORE"] - 10

# #     if Utils.checkSucuriBlacklists(url) != True:
# #         output["InSucuriBlacklist"] = True
# #         output["SCORE"] = output["SCORE"] - 10

# #     if Utils.is_temporary_domain(url):
# #         print("Domain is registered from unsecure source")
# #         output["isTemporaryDomain"] = True
# #         output["SCORE"] = output["SCORE"] - 10

# #     # check if url is older than 3 months
# #     if Utils.get_days_since_creation(url, 3) != True:
# #         print("Domain is less than 3 months old")
# #         output["isOlderThan3Months"] = False
# #         output["SCORE"] = output["SCORE"] - 10

# #     if Utils.checkLocalBlacklist(url):
# #         print("The URL is blacklisted !")
# #         output["SCORE"] = output["SCORE"] - 20

# #     if Utils.is_valid_ip(url) == True:
# #         if Utils.check_ip_in_ipsets(url):
# #             print("The IP address is blacklisted !")
# #             output["isBlackListedinIpSets"] = True
# #             output["SCORE"] = output["SCORE"] - 20
# #     else:
# #         print("Given address is not an valid IP address !")

# #     # Make prediction using AI model
# #     if Utils.isURLMalicious(url, model) == 1:
# #         print("Model predicted the URL as malicious")
# #         output["SCORE"] = output["SCORE"] - 20
# #     else:
# #         print("Model predicted URL not malicious !")

# #     # Check if URL is present in Reporting database
# #     if Utils.url_in_reporting_database(url):
# #         print("URL is also present in the Reporting database !")
# #         output["SCORE"] = output["SCORE"] - 20
# #     else:
# #         print("URL not in Reporting Database !")

# #     return output



# """
# API.py - Main prediction logic with parallel security checks
# """

# import os
# import requests
# import hashlib
# import json
# from urllib.parse import urlparse
# from datetime import datetime, timedelta
# from concurrent.futures import ThreadPoolExecutor, as_completed
# import Utils

# # Load environment variables
# try:
#     from dotenv import load_dotenv
#     load_dotenv()
# except ImportError:
#     pass

# # ==================== CONFIGURATION ====================

# GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
# VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
# ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# DEFAULT_TIMEOUT = (3, 10)
# MAX_WORKERS = 5
# CACHE_DURATION = timedelta(hours=24)
# CACHE_FILE = "url_cache.json"

# # ==================== CACHING ====================

# class URLCache:
#     def __init__(self):
#         self.cache = self._load_cache()
    
#     def _load_cache(self):
#         try:
#             if os.path.exists(CACHE_FILE):
#                 with open(CACHE_FILE, 'r') as f:
#                     return json.load(f)
#         except:
#             pass
#         return {}
    
#     def _save_cache(self):
#         try:
#             with open(CACHE_FILE, 'w') as f:
#                 json.dump(self.cache, f, indent=2)
#         except:
#             pass
    
#     def get(self, url):
#         url_hash = hashlib.md5(url.encode()).hexdigest()
#         if url_hash in self.cache:
#             entry = self.cache[url_hash]
#             try:
#                 cached_time = datetime.fromisoformat(entry['timestamp'])
#                 if datetime.now() - cached_time < CACHE_DURATION:
#                     print(f"✓ Cache hit: {url}")
#                     return entry['result']
#             except:
#                 pass
#         return None
    
#     def set(self, url, result):
#         url_hash = hashlib.md5(url.encode()).hexdigest()
#         self.cache[url_hash] = {
#             'timestamp': datetime.now().isoformat(),
#             'url': url,
#             'result': result
#         }
#         self._save_cache()

# cache = URLCache()

# # ==================== API CHECKS ====================

# def check_google_safe_browsing_api(url):
#     if not GOOGLE_SAFE_BROWSING_KEY:
#         return None
    
#     try:
#         api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_KEY}"
#         payload = {
#             "client": {"clientId": "phishing-detector", "clientVersion": "1.0.0"},
#             "threatInfo": {
#                 "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
#                 "platformTypes": ["ANY_PLATFORM"],
#                 "threatEntryTypes": ["URL"],
#                 "threatEntries": [{"url": url}]
#             }
#         }
        
#         response = requests.post(api_url, json=payload, timeout=DEFAULT_TIMEOUT)
#         if response.status_code == 200:
#             result = response.json()
#             return False if "matches" in result and len(result["matches"]) > 0 else True
#     except:
#         pass
#     return None

# def check_virustotal_api(url):
#     if not VIRUSTOTAL_API_KEY:
#         return None
    
#     try:
#         import base64
#         headers = {"x-apikey": VIRUSTOTAL_API_KEY}
#         url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
#         response = requests.get(
#             f"https://www.virustotal.com/api/v3/urls/{url_id}",
#             headers=headers,
#             timeout=DEFAULT_TIMEOUT
#         )
        
#         if response.status_code == 200:
#             stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
#             return stats.get("malicious", 0) + stats.get("suspicious", 0)
#     except:
#         pass
#     return None

# def check_urlhaus_api(url):
#     try:
#         response = requests.post(
#             "https://urlhaus-api.abuse.ch/v1/url/",
#             data={"url": url},
#             timeout=DEFAULT_TIMEOUT
#         )
        
#         if response.status_code == 200:
#             result = response.json()
#             if result.get("query_status") == "ok":
#                 return False  # Malicious
#             elif result.get("query_status") == "no_results":
#                 return True  # Clean
#     except:
#         pass
#     return None

# # def check_ssl(url):
# #     try:
# #         domain = urlparse(url).netloc or urlparse(url).path.split('/')[0]
# #         response = requests.get(f"https://{domain}", timeout=(2, 5), verify=True)
# #         return True
# #     except requests.exceptions.SSLError:
# #         return False
# #     except:
# #         return None

# import ssl
# import socket
# from datetime import datetime

# def check_ssl(url):
#     """
#     Efficient SSL certificate check using socket connection
#     Returns: True (valid), False (invalid/expired), NEVER None
#     """
#     try:
#         from urllib.parse import urlparse
#         parsed = urlparse(url)
#         domain = parsed.netloc or parsed.path.split('/')[0]
        
#         # Remove port if present
#         if ':' in domain:
#             domain = domain.split(':')[0]
        
#         # Create SSL context
#         context = ssl.create_default_context()
        
#         # Connect directly to port 443 (HTTPS)
#         with socket.create_connection((domain, 443), timeout=3) as sock:
#             with context.wrap_socket(sock, server_hostname=domain) as ssock:
#                 # Get certificate
#                 cert = ssock.getpeercert()
                
#                 # Check expiration
#                 not_after = cert.get('notAfter')
#                 if not_after:
#                     expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
#                     if expiry_date < datetime.now():
#                         return False  # Expired
                
#                 return True  # Valid certificate
                
#     except ssl.SSLError as e:
#         print(f"SSL Error: {e}")
#         return False  # Invalid SSL = False, NOT None
#     except socket.timeout:
#         print(f"SSL Timeout")
#         return False  # Timeout = assume invalid
#     except socket.gaierror:
#         print(f"DNS resolution failed")
#         return False  # DNS fail = can't verify
#     except Exception as e:
#         print(f"SSL check error: {e}")
#         return False  # Any error = assume invalid

# # ==================== MAIN PREDICTION ====================

# def get_prediction(url, model):
#     print(f"\n{'='*60}\n🔍 Analyzing: {url}\n{'='*60}")
    
#     # Check cache
#     cached = cache.get(url)
#     if cached:
#         return cached
    
#     # Initialize output
#     output = {
#         "SCORE": 0,
#         "RISK_LEVEL": "SAFE",
#         "CONFIDENCE": 0,
#         "checks_completed": 0,
#         "InTop1Million": False,
#         "InURLVoidBlackList": False,
#         "isHTTPS": False,
#         "hasSSLCertificate": None,
#         "GoogleSafePassed": None,
#         "VirusTotalDetections": 0,
#         "InURLHaus": False,
#         "isTemporaryDomain": False,
#         # "isOlderThan3Months": None,
#         "isBlackListedinIpSets": False,
#         "isDirectIP": False,
#         "hasMaliciousExtension": False,
#         "target_urls": []
#     }
    
#     # Step 1: Whitelist check
#     # FIXED CODE (no NULLs):
#     if Utils.check_top1million_database(url) or Utils.check_top1million_database_2(url):
#         print("✓ Found in Top 1M - SAFE")
        
#         # Extract basic features
#         is_https = Utils.is_https(url)
        
#         # Quick SSL check (even for trusted sites)
#         try:
#             ssl_result = check_ssl(url)
#         except:
#             ssl_result = True  # Assume valid for Top 1M
        
#         # Build complete response (no NULLs)
#         output = {
#             "SCORE": 5,
#             "RISK_LEVEL": "SAFE",
#             "CONFIDENCE": 100,
#             "checks_completed": 2,  # Did 2 checks: Top1M + SSL
#             "InTop1Million": True,
#             "InURLVoidBlackList": False,
#             "isHTTPS": is_https,
#             "hasSSLCertificate": ssl_result,  # ← Now checked!
#             "GoogleSafePassed": True,  # ← Assume passed for Top 1M
#             "VirusTotalDetections": 0,
#             "InURLHaus": False,
#             "isTemporaryDomain": False,
#             # "isOlderThan3Months": True,  # ← Assume old domain
#             "isBlackListedinIpSets": False,
#             "isDirectIP": False,
#             "hasMaliciousExtension": False,
#             "target_urls": []
#         }
        
#         cache.set(url, output)
#         return output

    
#     # Step 2: Extract features
#     is_ip = Utils.is_ip_address(url)
#     has_mal_ext = Utils.has_malicious_extension(url)
#     is_https = Utils.is_https(url)
#     is_temp = Utils.is_temporary_domain(url)
    
#     output.update({
#         "isHTTPS": is_https,
#         "isTemporaryDomain": is_temp,
#         "isDirectIP": is_ip == 1,
#         "hasMaliciousExtension": has_mal_ext == 1
#     })
    
#     # Step 3: Run checks
#     score = 0
#     checks = 0
    
#     # Critical indicators
#     if is_ip == 1:
#         score += 25
#     if has_mal_ext == 1:
#         score += 30
#     if ".sh" in url or ".bin" in url:
#         score += 20
    
#     # API checks
#     try:
#         google_safe = check_google_safe_browsing_api(url)
#         output["GoogleSafePassed"] = google_safe
#         if google_safe is False:
#             score += 25
#         if google_safe is not None:
#             checks += 1
#     except:
#         pass
    
#     try:
#         vt_count = check_virustotal_api(url) or 0
#         output["VirusTotalDetections"] = vt_count
#         if vt_count > 5:
#             score += 35
#         elif vt_count > 0:
#             score += 20
#         if vt_count is not None:
#             checks += 1
#     except:
#         pass
    
#     try:
#         urlhaus = check_urlhaus_api(url)
#         if urlhaus is False:
#             score += 40
#             output["InURLHaus"] = True
#         if urlhaus is not None:
#             checks += 1
#     except:
#         pass
    
#     try:
#         ssl = check_ssl(url)
#         output["hasSSLCertificate"] = ssl
#         if ssl is False:
#             score += 12
#         if ssl is not None:
#             checks += 1
#     except:
#         pass
    
#     # Additional checks
#     try:
#         urlvoid = Utils.checkURLVoid(url)
#         if urlvoid > 0:
#             output["InURLVoidBlackList"] = True
#             score += 10 if urlvoid <= 5 else 20
#         checks += 1
#     except:
#         pass
    
#     try:
#         if Utils.checkLocalBlacklist(url):
#             score += 25
#         checks += 1
#     except:
#         pass
    
#     try:
#         domain_age = Utils.get_days_since_creation(url, 3)
#         # output["isOlderThan3Months"] = domain_age
#         if domain_age is False:
#             score += 10
#         if domain_age is not None:
#             checks += 1
#     except:
#         pass
    
#     try:
#         ml_pred = Utils.isURLMalicious(url, model)
#         if ml_pred == 1:
#             score += 15
#         checks += 1
#     except:
#         pass
    
#     try:
#         output["target_urls"] = Utils.find_target_urls(url, 8)
#     except:
#         pass
    
#     if is_temp:
#         score += 15
    
#     if not is_https:
#         score += 3
    
#     # Finalize
#     final_score = min(score, 100)
#     confidence = (checks / 10) * 100
    
#     if final_score <= 20:
#         risk = "SAFE"
#     elif final_score <= 40:
#         risk = "LOW"
#     elif final_score <= 60:
#         risk = "MEDIUM"
#     elif final_score <= 80:
#         risk = "HIGH"
#     else:
#         risk = "CRITICAL"
    
#     output.update({
#         "SCORE": final_score,
#         "RISK_LEVEL": risk,
#         "CONFIDENCE": round(confidence, 1),
#         "checks_completed": checks
#     })
    
#     print(f"\n📊 SCORE: {final_score}/100 ({risk})")
#     print(f"🎯 CONFIDENCE: {confidence:.1f}%\n")
    
#     cache.set(url, output)
#     return output
"""
Enterprise-Grade URL Security Scanner - PRODUCTION v4.0
FIXED: Proper risk scoring without penalizing missing optional features
Changes:
- Only penalize ACTIVE threats, not missing features
- Factor confidence into risk assessment
- Improved subdomain logic for legitimate sites
- Adjusted risk thresholds
- Added UNCERTAIN category for low confidence
"""

import os
import requests
import hashlib
import json
import re
from urllib.parse import urlparse, urljoin
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import ssl
import socket
from bs4 import BeautifulSoup
import tldextract  # pip install tldextract - IMPORTANT for proper domain parsing
import Utils

# ==================== CONFIGURATION ====================
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
DEFAULT_TIMEOUT = (3, 10)
MAX_WORKERS = 8
CACHE_DURATION = timedelta(hours=24)
CACHE_FILE = "url_cache.json"
REPORTS_DB_FILE = "user_reports.json"

HIGH_RISK_COUNTRIES = ['CN', 'RU', 'NG', 'PK', 'VN', 'ID', 'BY', 'KZ']

# TRUSTED APEX DOMAINS (These are the ONLY legitimate domains)
TRUSTED_APEX_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'instagram.com', 'twitter.com',
    'x.com', 'linkedin.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'whatsapp.com', 'claude.ai', 'anthropic.com', 'openai.com', 'github.com',
    'stackoverflow.com', 'reddit.com', 'wikipedia.org', 'netflix.com',
    'paypal.com', 'stripe.com', 'shopify.com', 'gmail.com', 'outlook.com',
    'indiafoodnetwork.in'  # Added for recipe finder example
}

# Map brand names to their official domains
BRAND_TO_DOMAIN = {
    'youtube': 'youtube.com',
    'google': 'google.com',
    'facebook': 'facebook.com',
    'instagram': 'instagram.com',
    'twitter': 'twitter.com',
    'microsoft': 'microsoft.com',
    'apple': 'apple.com',
    'amazon': 'amazon.com',
    'whatsapp': 'whatsapp.com',
    'paypal': 'paypal.com',
    'netflix': 'netflix.com',
    'github': 'github.com',
    'linkedin': 'linkedin.com'
}

# LEGITIMATE SUBDOMAINS (must be EXACT match)
TRUSTED_SUBDOMAINS = {
    'youtube.com': ['www', 'music', 'studio', 'm', 'tv', 'gaming', 'kids'],
    'google.com': ['www', 'mail', 'drive', 'docs', 'maps', 'play', 'accounts', 'calendar', 'meet', 'photos'],
    'microsoft.com': ['www', 'login', 'account', 'office', 'outlook', 'teams'],
    'facebook.com': ['www', 'm', 'web', 'business', 'developers', 'about'],
    'amazon.com': ['www', 'smile', 'music', 'prime', 'aws'],
    'whatsapp.com': ['www', 'web', 'faq', 'blog'],
    'anthropic.com': ['www', 'claude', 'console'],
    'claude.ai': ['www', 'console'],
    'paypal.com': ['www', 'business', 'developer'],
    'github.com': ['www', 'gist', 'pages', 'docs', 'education'],
    'indiafoodnetwork.in': ['recipefinder', 'www', 'recipes']  # Legitimate subdomains
}

# E-commerce platforms
ECOMMERCE_INDICATORS = {
    'shopify': ['/cdn/shop/', 'myshopify.com', 'shopifycdn.com'],
    'shoplazza': ['shoplazza.com', 'myshoplazza.com'],
    'woocommerce': ['woocommerce', 'wc-ajax'],
    'magento': ['magento', 'Mage.Cookies'],
}

# FIXED: More specific risky payment keywords
RISKY_PAYMENT_KEYWORDS = [
    r'\bbitcoin\b', r'\bcryptocurrency\b', r'\bwestern union\b', 
    r'\bmoneygram\b', r'\bwire transfer only\b', r'\bcrypto\b', 
    r'\bbtc\b'
]

SAFE_PAYMENT_KEYWORDS = [
    'paypal', 'stripe', 'credit card', 'visa', 'mastercard',
    'american express', 'apple pay', 'google pay'
]

# SUSPICIOUS SUBDOMAIN PATTERNS
SUSPICIOUS_SUBDOMAIN_KEYWORDS = [
    'scam', 'phish', 'fake', 'fraud', 'verify', 'secure', 'account',
    'login', 'signin', 'update', 'confirm', 'suspended', 'locked',
    'billing', 'payment', 'support', 'help', 'security', 'alert',
    'validation', 'authentication', 'recovery'
]

# ==================== ADVANCED DOMAIN VALIDATION ====================

def extract_domain_parts_advanced(url):
    """
    CRITICAL: Use tldextract for proper domain parsing
    This correctly handles cases like scam.youtube.com
    """
    try:
        # Parse URL
        parsed = urlparse(url)
        full_netloc = parsed.netloc or parsed.path.split('/')[0]

        # Remove port
        if ':' in full_netloc:
            full_netloc = full_netloc.split(':')[0]

        # Use tldextract for proper domain extraction
        extracted = tldextract.extract(full_netloc)

        # Get components
        subdomain = extracted.subdomain  # e.g., 'www' or 'www.scam'
        domain = extracted.domain        # e.g., 'youtube'
        suffix = extracted.suffix        # e.g., 'com'

        # Build apex domain (domain.suffix)
        apex_domain = f"{domain}.{suffix}" if domain and suffix else full_netloc

        # Full registered domain
        registered_domain = extracted.registered_domain  # e.g., 'youtube.com'

        return {
            'full_domain': full_netloc,
            'subdomain': subdomain if subdomain else None,
            'domain': domain,
            'suffix': suffix,
            'apex_domain': apex_domain,
            'registered_domain': registered_domain
        }
    except Exception as e:
        # Fallback to basic parsing
        return {
            'full_domain': full_netloc,
            'subdomain': None,
            'domain': None,
            'suffix': None,
            'apex_domain': full_netloc,
            'registered_domain': full_netloc
        }

def detect_brand_impersonation(url):
    """
    CRITICAL: Detect combosquatting/brand impersonation
    Example: scam.youtube.com is NOT youtube.com
    """
    try:
        domain_info = extract_domain_parts_advanced(url)
        registered_domain = domain_info['registered_domain']

        # Check if this domain contains a trusted brand name
        for brand_name, official_domain in BRAND_TO_DOMAIN.items():
            # If brand name appears in registered domain but domain != official domain
            if brand_name in registered_domain.lower() and registered_domain.lower() != official_domain.lower():
                return {
                    "detected": True,
                    "attack_type": "Brand Impersonation / Combosquatting",
                    "impersonated_brand": official_domain,
                    "malicious_domain": registered_domain,
                    "brand_name": brand_name.title(),
                    "severity": "CRITICAL",
                    "penalty": 90
                }

        return {"detected": False, "penalty": 0}

    except Exception as e:
        return {"detected": False, "penalty": 0}

def check_homograph_attack(domain):
    """Detect Unicode/homograph attacks"""
    try:
        # Check for non-ASCII characters
        if not all(ord(char) < 128 for char in domain):
            suspicious_chars = [char for char in domain if ord(char) >= 128]

            if suspicious_chars:
                return {
                    "detected": True,
                    "detail": f"Unicode chars: {''.join(suspicious_chars[:3])}",
                    "penalty": 85
                }

        # Check Punycode (xn--)
        if 'xn--' in domain.lower():
            return {
                "detected": True,
                "detail": "Punycode domain (possible homograph)",
                "penalty": 80
            }

        return {"detected": False, "detail": "No homograph", "penalty": 0}
    except:
        return {"detected": False, "detail": "Homograph check failed", "penalty": 0}

def check_typosquatting(domain, trusted_domains):
    """Detect typosquatting using Levenshtein distance"""
    def levenshtein_distance(s1, s2):
        if len(s1) < len(s2):
            return levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    try:
        domain_lower = domain.lower().replace('www.', '')

        for trusted in trusted_domains:
            distance = levenshtein_distance(domain_lower, trusted)

            # If distance is 1-3, it's likely typosquatting
            if 1 <= distance <= 3 and len(domain_lower) > 4:
                similarity = 1 - (distance / max(len(domain_lower), len(trusted)))
                if similarity > 0.75:  # 75% similar
                    return {
                        "detected": True,
                        "detail": f"Typosquat of {trusted} (distance: {distance})",
                        "penalty": 75,
                        "target": trusted
                    }

        return {"detected": False, "detail": "No typosquatting", "penalty": 0}
    except:
        return {"detected": False, "detail": "Typo check failed", "penalty": 0}

def validate_subdomain_advanced(url):
    """
    IMPROVED: Validate subdomains with proper domain parsing
    FIXED: Don't penalize legitimate subdomains on trusted apex domains
    """
    try:
        domain_info = extract_domain_parts_advanced(url)
        registered_domain = domain_info['registered_domain']
        subdomain = domain_info['subdomain']

        # Check if apex domain is trusted
        if registered_domain.lower() not in TRUSTED_APEX_DOMAINS:
            return {"valid": True, "detail": f"Domain: {registered_domain}", "penalty": 0}

        # If no subdomain (just apex), it's safe
        if not subdomain:
            return {"valid": True, "detail": f"Trusted apex: {registered_domain}", "penalty": 0}

        # Check if subdomain is in whitelist for this apex
        if registered_domain.lower() in TRUSTED_SUBDOMAINS:
            allowed_subs = TRUSTED_SUBDOMAINS[registered_domain.lower()]

            # Handle multi-level subdomains (e.g., 'www.scam' -> check 'scam')
            subdomain_parts = subdomain.lower().split('.')

            # Check each part
            for part in subdomain_parts:
                if part not in allowed_subs:
                    # Check for suspicious keywords
                    for keyword in SUSPICIOUS_SUBDOMAIN_KEYWORDS:
                        if keyword in part:
                            return {
                                "valid": False,
                                "detail": f"PHISHING: {subdomain}.{registered_domain} (suspicious: '{keyword}')",
                                "penalty": 85,
                                "reason": f"Malicious subdomain on trusted apex domain"
                            }

                    # Subdomain not in whitelist - REDUCED penalty for legitimate sites
                    return {
                        "valid": True,  # Changed to True - don't block, just note
                        "detail": f"Subdomain: {subdomain}.{registered_domain}",
                        "penalty": 0,  # FIXED: Don't penalize unknown subdomains on trusted apex
                        "reason": "Subdomain on trusted domain"
                    }

        # If subdomain is long/random, flag it
        if len(subdomain) > 20 or subdomain.count('.') > 2:
            return {
                "valid": False,
                "detail": f"Suspicious subdomain: {subdomain}.{registered_domain}",
                "penalty": 50,
                "reason": "Unusual subdomain structure"
            }

        # Default: Unknown subdomain on trusted apex (don't penalize)
        return {
            "valid": True,
            "detail": f"Subdomain: {subdomain}.{registered_domain}",
            "penalty": 0,
            "reason": "Subdomain on trusted domain"
        }

    except Exception as e:
        return {"valid": True, "detail": f"Subdomain check error: {str(e)}", "penalty": 0}

def is_trusted_domain_final(url):
    """
    FINAL: Advanced domain trust validation
    """
    try:
        domain_info = extract_domain_parts_advanced(url)
        registered_domain = domain_info['registered_domain']
        subdomain = domain_info['subdomain']

        # Check if apex is trusted
        if registered_domain.lower() not in TRUSTED_APEX_DOMAINS:
            return False

        # If no subdomain, it's trusted
        if not subdomain:
            return True

        # Check if subdomain is whitelisted
        if registered_domain.lower() in TRUSTED_SUBDOMAINS:
            allowed_subs = TRUSTED_SUBDOMAINS[registered_domain.lower()]
            subdomain_parts = subdomain.lower().split('.')

            # All parts must be in whitelist
            for part in subdomain_parts:
                if part and part not in allowed_subs:
                    return False

            return True

        return False

    except:
        return False

# ==================== CACHING ====================
class URLCache:
    def __init__(self):
        self.cache = self._load_cache()

    def _load_cache(self):
        try:
            if os.path.exists(CACHE_FILE):
                with open(CACHE_FILE, 'r') as f:
                    return json.load(f)
        except:
            pass
        return {}

    def _save_cache(self):
        try:
            with open(CACHE_FILE, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except:
            pass

    def get(self, url):
        url_hash = hashlib.md5(url.encode()).hexdigest()
        if url_hash in self.cache:
            entry = self.cache[url_hash]
            try:
                cached_time = datetime.fromisoformat(entry['timestamp'])
                if datetime.now() - cached_time < CACHE_DURATION:
                    return entry['result']
            except:
                pass
        return None

    def set(self, url, result):
        url_hash = hashlib.md5(url.encode()).hexdigest()
        self.cache[url_hash] = {
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'result': result
        }
        self._save_cache()

cache = URLCache()

# ==================== REPORTS DATABASE ====================
class ReportsDatabase:
    def __init__(self):
        self.reports = self._load_reports()

    def _load_reports(self):
        try:
            if os.path.exists(REPORTS_DB_FILE):
                with open(REPORTS_DB_FILE, 'r') as f:
                    return json.load(f)
        except:
            pass
        return {}

    def _save_reports(self):
        try:
            with open(REPORTS_DB_FILE, 'w') as f:
                json.dump(self.reports, f, indent=2)
        except:
            pass

    def add_report(self, url, is_scam, comment=""):
        domain = urlparse(url).netloc or urlparse(url).path.split('/')[0]
        if domain not in self.reports:
            self.reports[domain] = {'scam_reports': 0, 'safe_reports': 0, 'comments': []}

        if is_scam:
            self.reports[domain]['scam_reports'] += 1
        else:
            self.reports[domain]['safe_reports'] += 1

        if comment:
            self.reports[domain]['comments'].append({
                'timestamp': datetime.now().isoformat(),
                'comment': comment,
                'is_scam': is_scam
            })

        self._save_reports()

    def get_reports(self, url):
        domain = urlparse(url).netloc or urlparse(url).path.split('/')[0]
        return self.reports.get(domain, {'scam_reports': 0, 'safe_reports': 0, 'comments': []})

reports_db = ReportsDatabase()

# ==================== POSITIVE INDICATORS ====================
# FIXED: These functions now only ADD points, never subtract for missing features

def check_popularity(url):
    """Top 1M sites"""
    try:
        if Utils.check_top1million_database(url) or Utils.check_top1million_database_2(url):
            return {"passed": True, "points": 35, "detail": "High popularity (Top 1M)", "weight": "critical"}
        return {"passed": False, "points": 0}
    except:
        return {"passed": False, "points": 0}

def check_contact_information(url):
    """Company contact details - OPTIONAL FEATURE"""
    points = 0
    details = []

    try:
        response = requests.get(url, timeout=DEFAULT_TIMEOUT, headers={'User-Agent': 'Mozilla/5.0'})
        html = response.text.lower()
        soup = BeautifulSoup(html, 'html.parser')
        text_content = soup.get_text()

        # Phone
        phone_patterns = [r'\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}']
        if any(re.search(pattern, text_content) for pattern in phone_patterns):
            points += 4
            details.append("Phone")

        # Email
        if re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text_content):
            points += 3
            details.append("Email")

        # FIXED: Return detail even if no contact found (neutral, not negative)
        return {"passed": points > 0, "points": points, "detail": "Contact: " + ", ".join(details) if details else "No contact info", "weight": "low"}
    except:
        return {"passed": False, "points": 0, "detail": "Contact check failed"}

def check_social_media_presence(url):
    """Active social media - OPTIONAL FEATURE"""
    points = 0
    social_found = []

    try:
        response = requests.get(url, timeout=DEFAULT_TIMEOUT, headers={'User-Agent': 'Mozilla/5.0'})
        html = response.text.lower()

        social_patterns = {
            'Facebook': r'facebook\.com/',
            'Twitter': r'(twitter|x)\.com/',
            'Instagram': r'instagram\.com/',
            'LinkedIn': r'linkedin\.com/'
        }

        for platform, pattern in social_patterns.items():
            if re.search(pattern, html):
                social_found.append(platform)

        points = 8 if len(social_found) >= 3 else 4 if len(social_found) >= 1 else 0

        # FIXED: Return detail even if none found (neutral, not negative)
        return {"passed": len(social_found) > 0, "points": points, "detail": f"Active on: {', '.join(social_found)}" if social_found else "No social media", "weight": "low"}
    except:
        return {"passed": False, "points": 0, "detail": "Social check failed"}

def check_technology_stack(url):
    """Premium tech detection - OPTIONAL FEATURE"""
    points = 0
    details = []

    try:
        response = requests.get(url, timeout=DEFAULT_TIMEOUT, headers={'User-Agent': 'Mozilla/5.0'})
        html = response.text.lower()
        headers = str(response.headers).lower()

        # CDN
        cdn_indicators = ['cloudflare', 'cloudfront', 'akamai', 'fastly']
        for cdn in cdn_indicators:
            if cdn in headers or cdn in html:
                points += 5
                details.append(f"{cdn.title()} CDN")
                break

        # Security headers
        if 'strict-transport-security' in headers and 'x-frame-options' in headers:
            points += 3
            details.append("Security headers")

        # FIXED: Return detail even if basic tech (neutral, not negative)
        return {"passed": points > 0, "points": points, "detail": ", ".join(details) if details else "Basic tech", "weight": "low"}
    except:
        return {"passed": False, "points": 0, "detail": "Tech check failed"}

def check_payment_methods(url):
    """Safe payment detection - OPTIONAL FEATURE"""
    points = 0
    details = []

    try:
        response = requests.get(url, timeout=DEFAULT_TIMEOUT, headers={'User-Agent': 'Mozilla/5.0'})
        html = response.text.lower()

        # Safe payments
        safe_found = [kw for kw in SAFE_PAYMENT_KEYWORDS if kw in html]
        if safe_found:
            points += 8
            details.append(f"Safe: {', '.join(safe_found[:2])}")

        # Risky payments - only flag if ONLY risky found
        risky_found = [kw for kw in RISKY_PAYMENT_KEYWORDS if re.search(kw, html, re.IGNORECASE)]
        if risky_found and not safe_found:
            details.append("Only risky payments detected")
            # This will be handled as negative indicator separately

        # FIXED: No payment info is neutral for recipe sites, blogs, etc.
        return {"passed": points > 0, "points": points, "detail": ", ".join(details) if details else "No payment info", "risky_found": risky_found, "weight": "low"}
    except:
        return {"passed": False, "points": 0, "detail": "Payment check failed"}

def check_website_age(url):
    """Domain age check"""
    try:
        days = Utils.get_domain_age_days(url)
        if days is None:
            return {"passed": None, "points": 0, "detail": "Age unknown"}

        if days > 365:
            return {"passed": True, "points": 15, "detail": f"{days} days old", "weight": "high"}
        elif days > 90:
            return {"passed": True, "points": 8, "detail": f"{days} days old", "weight": "medium"}
        else:
            # ONLY subtract points for very new domains (potential risk)
            return {"passed": False, "points": -8, "detail": f"Only {days} days old", "weight": "high"}
    except:
        return {"passed": None, "points": 0, "detail": "Age check failed"}

def check_ssl_security(url):
    """HTTPS and SSL - CRITICAL SECURITY FEATURE"""
    points = 0
    details = []

    try:
        is_https = Utils.is_https(url)
        if is_https:
            points += 5
            details.append("HTTPS")

        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        if ':' in domain:
            domain = domain.split(':')[0]

        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if cert.get('notAfter'):
                    expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if expiry > datetime.now():
                        points += 10
                        details.append("Valid SSL")

        return {"passed": points > 0, "points": points, "detail": ", ".join(details), "weight": "critical"}
    except:
        return {"passed": False, "points": 0, "detail": "No SSL", "weight": "high"}

def check_website_performance(url):
    """Load speed"""
    try:
        start = datetime.now()
        response = requests.get(url, timeout=(3, 5), allow_redirects=True)
        load_time = (datetime.now() - start).total_seconds()

        if response.status_code == 200 and load_time < 2:
            return {"passed": True, "points": 5, "detail": f"Fast ({load_time:.2f}s)", "weight": "low"}
        elif response.status_code == 200:
            return {"passed": True, "points": 2, "detail": f"OK ({load_time:.2f}s)", "weight": "low"}
        else:
            return {"passed": False, "points": 0, "detail": f"Slow ({load_time:.2f}s)", "weight": "low"}
    except:
        return {"passed": False, "points": -5, "detail": "Failed to load", "weight": "medium"}

# ==================== NEGATIVE INDICATORS ====================
# These ONLY penalize ACTIVE THREATS, not missing features

def check_blacklists(url):
    """Multiple blacklist sources - ACTIVE THREAT"""
    penalty = 0
    details = []

    # Google Safe Browsing
    if GOOGLE_SAFE_BROWSING_KEY:
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_KEY}"
            payload = {
                "client": {"clientId": "scanner", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            response = requests.post(api_url, json=payload, timeout=DEFAULT_TIMEOUT)
            if response.status_code == 200:
                result = response.json()
                if "matches" in result:
                    penalty += 35
                    details.append("Google Safe Browsing")
        except:
            pass

    # VirusTotal
    if VIRUSTOTAL_API_KEY:
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
                timeout=DEFAULT_TIMEOUT
            )
            if response.status_code == 200:
                stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                total = stats.get("malicious", 0) + stats.get("suspicious", 0)
                if total > 5:
                    penalty += 40
                    details.append(f"VirusTotal: {total}")
                elif total > 0:
                    penalty += 20
        except:
            pass

    try:
        urlvoid_count = Utils.checkURLVoid(url)
        if urlvoid_count > 0:
            penalty += 15 if urlvoid_count <= 5 else 30
            details.append(f"URLVoid: {urlvoid_count}")
    except:
        pass

    try:
        if Utils.checkLocalBlacklist(url):
            penalty += 25
            details.append("Local blacklist")
    except:
        pass

    return {"penalty": penalty, "detail": ", ".join(details) if details else "Clean", "weight": "critical"}

def check_seo_blocking(url):
    """SEO blocking check - Only penalize if suspicious"""
    penalty = 0
    details = []

    if is_trusted_domain_final(url):
        return {"penalty": 0, "detail": "Trusted platform", "weight": "low"}

    try:
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        robots_url = urljoin(base_url, '/robots.txt')

        robots_response = requests.get(robots_url, timeout=5)
        if robots_response.status_code == 200:
            robots_content = robots_response.text.lower()

            if 'disallow: /' in robots_content and 'user-agent: *' in robots_content:
                if any(keyword in url.lower() for keyword in ['web.', 'app.', 'dashboard', 'portal', 'login', 'recipe']):
                    return {"penalty": 0, "detail": "Web application (normal blocking)", "weight": "low"}

                penalty += 8
                details.append("Blocks search engines")

        return {"penalty": penalty, "detail": ", ".join(details) if details else "SEO-friendly", "weight": "low"}
    except:
        return {"penalty": 0, "detail": "SEO check skipped"}

def check_ml_prediction(url, model):
    """ML with whitelist override"""
    if is_trusted_domain_final(url):
        return {"penalty": 0, "detail": "ML: trusted domain", "weight": "low"}

    try:
        if Utils.isURLMalicious(url, model) == 1:
            return {"penalty": 12, "detail": "ML: malicious", "weight": "low"}
        return {"penalty": 0, "detail": "ML: clean"}
    except:
        return {"penalty": 0, "detail": "ML unavailable"}

def check_redirect_chains(url):
    """Excessive redirects - ACTIVE THREAT"""
    penalty = 0
    details = []
    try:
        response = requests.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0'})
        if len(response.history) > 3:
            penalty += 15
            details.append(f"{len(response.history)} redirects")
        elif len(response.history) > 1:
            penalty += 8
        return {"penalty": penalty, "detail": ", ".join(details) if details else "Direct access", "weight": "medium"}
    except:
        return {"penalty": 0, "detail": "Redirect check failed"}

def check_meta_tags(url):
    """Meta tags quality"""
    penalty = 0
    details = []
    try:
        response = requests.get(url, timeout=DEFAULT_TIMEOUT, headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.find('title')
        if not title or len(title.get_text().strip()) < 10:
            penalty += 5
            details.append("Missing/poor title")
        return {"penalty": penalty, "detail": ", ".join(details) if details else "Good meta tags", "weight": "low"}
    except:
        return {"penalty": 0, "detail": "Meta check failed"}

def check_user_reports(url):
    """Community reports - ACTIVE THREAT"""
    try:
        reports = reports_db.get_reports(url)
        scam_reports = reports['scam_reports']
        if scam_reports >= 3:
            penalty = min(scam_reports * 5, 30)
            return {"penalty": penalty, "detail": f"{scam_reports} scam reports", "weight": "high"}
        return {"penalty": 0, "detail": "No community reports"}
    except:
        return {"penalty": 0, "detail": "No reports"}

def check_whois_privacy(url):
    """WHOIS privacy - Minor indicator only"""
    try:
        import whois
        domain = urlparse(url).netloc or urlparse(url).path.split('/')[0]
        domain = domain.replace('www.', '')
        w = whois.whois(domain)
        registrant = str(w.get('registrant_name', '')).lower()
        privacy_indicators = ['privacy', 'protected', 'proxy', 'redacted']
        is_hidden = any(ind in registrant for ind in privacy_indicators)
        if is_hidden:
            # FIXED: Reduced penalty - privacy is common and legitimate
            return {"penalty": 5, "detail": "Hidden ownership", "weight": "low"}
        else:
            return {"penalty": 0, "detail": "Visible ownership"}
    except:
        return {"penalty": 0, "detail": "WHOIS unavailable"}

def check_geo_location(url):
    """Geographic location - Only high-risk locations penalized"""
    penalty = 0
    details = []
    if is_trusted_domain_final(url):
        return {"penalty": 0, "detail": "Whitelisted IP", "weight": "low"}
    try:
        domain = urlparse(url).netloc or urlparse(url).path.split('/')[0]
        domain = domain.replace('www.', '')
        import socket
        ip = socket.gethostbyname(domain)
        if ABUSEIPDB_API_KEY:
            try:
                response = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'},
                    params={'ipAddress': ip, 'maxAgeInDays': 90},
                    timeout=5
                )
                if response.status_code == 200:
                    data = response.json().get('data', {})
                    abuse_score = data.get('abuseConfidenceScore', 0)
                    if data.get('isWhitelisted'):
                        return {"penalty": 0, "detail": "Whitelisted IP", "weight": "low"}
                    if abuse_score >= 75:
                        penalty += 35
                        details.append(f"High abuse: {abuse_score}%")
                    elif abuse_score >= 50:
                        penalty += 25
            except:
                pass
        return {"penalty": penalty, "detail": ", ".join(details) if details else "Location OK", "weight": "high"}
    except:
        return {"penalty": 0, "detail": "Location check failed"}

def check_ecommerce_platform(url):
    """E-commerce platform - OPTIONAL, not penalized if missing"""
    try:
        response = requests.get(url, timeout=DEFAULT_TIMEOUT, headers={'User-Agent': 'Mozilla/5.0'})
        html = response.text.lower()
        for platform, indicators in ECOMMERCE_INDICATORS.items():
            if any(ind.lower() in html for ind in indicators):
                # FIXED: No penalty - just informational
                return {"penalty": 0, "detail": f"{platform.title()} platform", "weight": "low"}
        return {"penalty": 0, "detail": "No e-commerce platform"}
    except:
        return {"penalty": 0, "detail": "E-commerce check failed"}

def check_suspicious_patterns(url):
    """Suspicious patterns - ACTIVE THREATS ONLY"""
    penalty = 0
    details = []
    try:
        if Utils.is_ip_address(url) == 1:
            penalty += 25
            details.append("Direct IP")
    except:
        pass
    try:
        if Utils.has_malicious_extension(url) == 1:
            penalty += 30
            details.append("Malicious extension")
    except:
        pass
    try:
        if Utils.is_temporary_domain(url):
            penalty += 18
            details.append("Temporary domain")
    except:
        pass
    return {"penalty": penalty, "detail": ", ".join(details) if details else "Normal patterns", "weight": "high"}

# ==================== FIXED SCORING SYSTEM ====================

class ScoreCalculator:
    """
    COMPLETELY REWRITTEN SCORING SYSTEM
    Key fixes:
    1. Only penalize ACTIVE threats, not missing optional features
    2. Factor confidence into final assessment
    3. Proper thresholds (80+ = safe, 60-79 = medium, etc.)
    4. Add UNCERTAIN category for low confidence
    """
    
    WEIGHTS = {
        'critical': 2.0,
        'high': 1.5,
        'medium': 1.0,
        'low': 0.5
    }

    def __init__(self):
        self.positive_score = 0
        self.negative_score = 0
        self.positive_items = []
        self.negative_items = []
        self.total_checks = 0
        self.confidence_factors = []

    def add_positive(self, points, detail, weight='medium'):
        """Add points for positive security indicators"""
        weighted_points = points * self.WEIGHTS.get(weight, 1.0)
        self.positive_score += weighted_points
        self.positive_items.append({'points': points, 'weighted': weighted_points, 'detail': detail})
        self.total_checks += 1
        
        # Track confidence factors
        if points > 0:
            self.confidence_factors.append(weight)

    def add_negative(self, penalty, detail, weight='medium'):
        """Subtract points ONLY for active threats"""
        weighted_penalty = penalty * self.WEIGHTS.get(weight, 1.0)
        self.negative_score += weighted_penalty
        self.negative_items.append({'penalty': penalty, 'weighted': weighted_penalty, 'detail': detail})
        self.total_checks += 1
        
        # Track confidence factors
        if penalty > 0:
            self.confidence_factors.append(weight)

    def calculate_final_score(self):
        """
        FIXED SCORING ALGORITHM:
        - Start at 50 (neutral)
        - Add positive points (up to +50)
        - Subtract negative points (active threats only)
        - Result: 0-100 scale
        """
        base_score = 50
        
        # Positive contribution (capped at 50)
        positive_contribution = min(self.positive_score, 50)
        
        # Negative contribution (active threats)
        negative_contribution = self.negative_score
        
        # Calculate raw score
        raw_score = base_score + positive_contribution - negative_contribution
        
        # Ensure score is in valid range
        final_score = max(0, min(100, int(raw_score)))
        
        return final_score

    def get_confidence_percentage(self):
        """
        Calculate confidence based on:
        - Number of checks performed
        - Quality of checks (critical > high > medium > low)
        """
        # Base confidence on number of checks (out of 15 ideal checks)
        check_confidence = min(self.total_checks / 15.0, 1.0) * 60
        
        # Bonus for high-quality checks
        quality_bonus = 0
        if 'critical' in self.confidence_factors:
            quality_bonus += 20
        if 'high' in self.confidence_factors:
            quality_bonus += 15
        if self.confidence_factors.count('medium') >= 3:
            quality_bonus += 5
            
        total_confidence = min(int(check_confidence + quality_bonus), 100)
        return total_confidence

    def get_risk_level(self, score, confidence):
        """
        FIXED RISK LEVEL DETERMINATION:
        Factor in both score AND confidence
        """
        # If confidence is very low, return UNCERTAIN
        if confidence < 30:
            return "UNCERTAIN - Manual Review Recommended", "⚪ LOW CONFIDENCE - Not enough data for confident assessment"
        
        # Normal risk assessment
        if score >= 80:
            return "LOW RISK - Safe", "🟢 SAFE - Proceed with confidence"
        elif score >= 60:
            return "MEDIUM RISK - Caution", "🟡 UNKNOWN - Proceed with caution"
        elif score >= 40:
            return "HIGH RISK - Suspicious", "🟠 SUSPICIOUS - Avoid if possible"
        else:
            return "CRITICAL RISK - Dangerous", "🔴 DANGEROUS - Do not proceed"

# ==================== MAIN SCANNER (IMPROVED) ====================

def get_prediction(url, model):
    """
    PRODUCTION v4.0: Fixed scoring system
    - Doesn't penalize missing optional features
    - Proper confidence calculation
    - Correct risk thresholds
    """
    print(f"\n{'='*80}")
    print(f"🔍 Enterprise URL Security Scanner v4.0: {url}")
    print(f"{'='*80}\n")

    # Cache check
    cached = cache.get(url)
    if cached:
        print("✓ Using cached result\n")
        return cached

    # ========== CRITICAL SECURITY CHECKS (PRIORITY 1) ==========
    print("🛡️  Running Critical Security Checks...\n")

    # 1. BRAND IMPERSONATION (Highest priority)
    brand_check = detect_brand_impersonation(url)
    if brand_check["detected"]:
        print(f"  🚨 CRITICAL ALERT: {brand_check['attack_type']}")
        print(f"     Impersonated Brand: {brand_check['impersonated_brand']}")
        print(f"     Malicious Domain: {brand_check['malicious_domain']}\n")

        result = {
            "SCORE": 5,
            "RISK_LEVEL": "CRITICAL - Brand Impersonation",
            "RISK_DESCRIPTION": f"🔴 DANGER - This website is impersonating {brand_check['brand_name']}!",
            "CONFIDENCE": 99,
            "security_alert": {
                "severity": "CRITICAL",
                "threat_type": brand_check['attack_type'],
                "impersonated_brand": brand_check['impersonated_brand'],
                "actual_domain": brand_check['malicious_domain'],
                "explanation": f"This is NOT {brand_check['impersonated_brand']} - it's a fake website"
            },
            "positive_highlights": [],
            "negative_highlights": [
                f"🚨 Impersonating {brand_check['brand_name']}",
                "Malicious domain registration",
                "Phishing/scam attempt detected"
            ],
            "details": {
                "domain_analysis": f"Domain '{brand_check['malicious_domain']}' is impersonating '{brand_check['impersonated_brand']}'",
                "attack_pattern": "Combosquatting - registering domain containing brand name",
                "verdict": "⚠️ PHISHING ATTACK - Do NOT enter any personal information"
            },
            "checks_performed": 1,
            "positive_score": 0.0,
            "negative_score": brand_check['penalty'],
            "target_urls": []
        }
        cache.set(url, result)
        return result

    # 2. Homograph attack detection
    domain_info = extract_domain_parts_advanced(url)
    if domain_info:
        homograph = check_homograph_attack(domain_info['full_domain'])
        if homograph["detected"]:
            print(f"  ⚠️  HOMOGRAPH ATTACK: {homograph['detail']}\n")
            result = {
                "SCORE": 10,
                "RISK_LEVEL": "CRITICAL - Homograph Attack",
                "RISK_DESCRIPTION": "🔴 DANGER - Unicode phishing attack detected!",
                "CONFIDENCE": 98,
                "positive_highlights": [],
                "negative_highlights": [homograph['detail']],
                "details": {"domain": homograph["detail"], "verdict": "PHISHING: Homograph/Unicode attack"},
                "checks_performed": 1,
                "positive_score": 0.0,
                "negative_score": homograph["penalty"],
                "target_urls": []
            }
            cache.set(url, result)
            return result

    # 3. Typosquatting detection
    if domain_info:
        typo = check_typosquatting(domain_info['registered_domain'], TRUSTED_APEX_DOMAINS)
        if typo["detected"]:
            print(f"  ⚠️  TYPOSQUATTING: {typo['detail']}\n")
            result = {
                "SCORE": 15,
                "RISK_LEVEL": "CRITICAL - Typosquatting",
                "RISK_DESCRIPTION": f"🔴 DANGER - Typosquatting of {typo['target']}!",
                "CONFIDENCE": 95,
                "positive_highlights": [],
                "negative_highlights": [typo['detail']],
                "details": {"domain": typo["detail"], "verdict": f"PHISHING: Typosquatting of {typo['target']}"},
                "checks_performed": 1,
                "positive_score": 0.0,
                "negative_score": typo["penalty"],
                "target_urls": []
            }
            cache.set(url, result)
            return result

    # 4. Subdomain validation (FIXED - doesn't penalize legitimate subdomains)
    subdomain_check = validate_subdomain_advanced(url)
    if not subdomain_check["valid"] and subdomain_check["penalty"] > 60:
        print(f"  ⚠️  SUBDOMAIN ALERT: {subdomain_check['detail']}\n")
        result = {
            "SCORE": max(1, 40 - subdomain_check["penalty"]),
            "RISK_LEVEL": "HIGH RISK - Suspicious Subdomain",
            "RISK_DESCRIPTION": "🟠 RISKY - " + subdomain_check.get("reason", "Suspicious subdomain"),
            "CONFIDENCE": 92,
            "positive_highlights": [],
            "negative_highlights": [subdomain_check['detail']],
            "details": {"subdomain": subdomain_check["detail"], "verdict": "PHISHING RISK: Malicious subdomain detected"},
            "checks_performed": 1,
            "positive_score": 0.0,
            "negative_score": subdomain_check["penalty"],
            "target_urls": []
        }
        cache.set(url, result)
        return result

    # 5. Trusted domain fast-track (AFTER all security checks)
    if is_trusted_domain_final(url):
        print("✅ TRUSTED & VERIFIED - Skipping deep scan\n")
        result = {
            "SCORE": 95,
            "RISK_LEVEL": "TRUSTED - Very Likely Safe",
            "RISK_DESCRIPTION": "✅ TRUSTED - Verified platform",
            "CONFIDENCE": 100,
            "positive_highlights": ["Verified trusted platform", "High reputation"],
            "negative_highlights": [],
            "details": {
                "popularity": "Trusted platform",
                "security": "HTTPS, Valid SSL",
                "subdomain": subdomain_check["detail"],
                "verdict": "Whitelisted domain"
            },
            "checks_performed": 1,
            "positive_score": 95.0,
            "negative_score": 0.0,
            "target_urls": []
        }
        cache.set(url, result)
        return result

    # ========== FULL SCAN FOR UNKNOWN DOMAINS ==========
    print("📊 Running comprehensive security scan...\n")
    
    scorer = ScoreCalculator()
    output = {
        "positive_highlights": [],
        "negative_highlights": [],
        "details": {}
    }

    # Add subdomain check result (FIXED - only if actually suspicious)
    output["details"]["subdomain"] = subdomain_check["detail"]
    if subdomain_check["penalty"] > 0:
        scorer.add_negative(subdomain_check["penalty"], subdomain_check["detail"], "high")
        output["negative_highlights"].append("Suspicious subdomain")

    print("📈 Checking Positive Indicators...\n")

    # === POSITIVE CHECKS ===
    popularity = check_popularity(url)
    if popularity["passed"]:
        scorer.add_positive(popularity["points"], popularity["detail"], popularity.get("weight"))
        output["positive_highlights"].append("High traffic ranking")
        print(f"  ✓ Popularity: +{popularity['points']}")
        # High popularity sites get fast-tracked
        result = {
            "SCORE": 95,
            "RISK_LEVEL": "TRUSTED - Very Likely Safe",
            "RISK_DESCRIPTION": "✅ TRUSTED - Top website",
            "CONFIDENCE": 100,
            "positive_highlights": output["positive_highlights"],
            "negative_highlights": [],
            "details": {"popularity": popularity["detail"], "subdomain": subdomain_check["detail"]},
            "checks_performed": 1,
            "positive_score": 95.0,
            "negative_score": 0.0,
            "target_urls": []
        }
        cache.set(url, result)
        return result

    # SSL/HTTPS (CRITICAL)
    ssl_check = check_ssl_security(url)
    if ssl_check["passed"]:
        scorer.add_positive(ssl_check["points"], ssl_check["detail"], ssl_check.get("weight"))
        output["positive_highlights"].append("Secure connection")
    else:
        scorer.add_negative(10, ssl_check["detail"], "critical")  # No SSL is a threat
        output["negative_highlights"].append("No SSL encryption")
    output["details"]["security"] = ssl_check["detail"]

    # Performance
    perf = check_website_performance(url)
    if perf["passed"]:
        scorer.add_positive(perf["points"], perf["detail"], perf.get("weight"))
    elif perf["points"] < 0:
        scorer.add_negative(abs(perf["points"]), perf["detail"], perf.get("weight"))
    output["details"]["performance"] = perf["detail"]

    # Domain Age
    age = check_website_age(url)
    if age["passed"]:
        scorer.add_positive(age["points"], age["detail"], age.get("weight"))
        output["positive_highlights"].append("Established domain")
    elif age["passed"] is False:
        scorer.add_negative(abs(age["points"]), age["detail"], age.get("weight"))
        output["negative_highlights"].append("Very new domain")
    output["details"]["age"] = age.get("detail", "Age unknown")

    # OPTIONAL FEATURES (don't penalize if missing)
    contact = check_contact_information(url)
    if contact["passed"]:
        scorer.add_positive(contact["points"], contact["detail"], contact.get("weight"))
        output["positive_highlights"].append("Contact information")
    output["details"]["contact"] = contact["detail"]

    social = check_social_media_presence(url)
    if social["passed"]:
        scorer.add_positive(social["points"], social["detail"], social.get("weight"))
        output["positive_highlights"].append("Active social media")
    output["details"]["social_media"] = social["detail"]

    tech = check_technology_stack(url)
    if tech["passed"]:
        scorer.add_positive(tech["points"], tech["detail"], tech.get("weight"))
    output["details"]["technology"] = tech["detail"]

    payment = check_payment_methods(url)
    if payment["passed"]:
        scorer.add_positive(payment["points"], payment["detail"], payment.get("weight"))
    output["details"]["payments"] = payment["detail"]

    print(f"\n📉 Checking Negative Indicators (Active Threats)...\n")

    # === NEGATIVE CHECKS (ACTIVE THREATS ONLY) ===
    blacklist = check_blacklists(url)
    if blacklist["penalty"] > 0:
        scorer.add_negative(blacklist["penalty"], blacklist["detail"], blacklist.get("weight"))
        output["negative_highlights"].append("Blacklisted")
    output["details"]["blacklists"] = blacklist["detail"]

    redirects = check_redirect_chains(url)
    if redirects["penalty"] > 0:
        scorer.add_negative(redirects["penalty"], redirects["detail"], redirects.get("weight"))
        output["negative_highlights"].append("Suspicious redirects")
    output["details"]["redirects"] = redirects["detail"]

    user_reports = check_user_reports(url)
    if user_reports["penalty"] > 0:
        scorer.add_negative(user_reports["penalty"], user_reports["detail"], user_reports.get("weight"))
        output["negative_highlights"].append("Scam reports")
    output["details"]["user_reports"] = user_reports["detail"]

    geo = check_geo_location(url)
    if geo["penalty"] > 0:
        scorer.add_negative(geo["penalty"], geo["detail"], geo.get("weight"))
        output["negative_highlights"].append("High-risk location")
    output["details"]["location"] = geo["detail"]

    patterns = check_suspicious_patterns(url)
    if patterns["penalty"] > 0:
        scorer.add_negative(patterns["penalty"], patterns["detail"], patterns.get("weight"))
        output["negative_highlights"].append("Suspicious patterns")
    output["details"]["patterns"] = patterns["detail"]

    # Optional checks
    seo = check_seo_blocking(url)
    output["details"]["seo"] = seo["detail"]

    meta = check_meta_tags(url)
    output["details"]["meta_tags"] = meta["detail"]

    whois = check_whois_privacy(url)
    output["details"]["whois"] = whois["detail"]

    ecom = check_ecommerce_platform(url)
    output["details"]["ecommerce"] = ecom["detail"]

    ml = check_ml_prediction(url, model)
    if ml["penalty"] > 0:
        scorer.add_negative(ml["penalty"], ml["detail"], ml.get("weight"))
    output["details"]["ml"] = ml["detail"]

    # === FINALIZE SCORE ===
    final_score = scorer.calculate_final_score()
    confidence = scorer.get_confidence_percentage()
    risk_level, risk_desc = scorer.get_risk_level(final_score, confidence)

    print(f"\n{'='*80}")
    print(f"📊 TRUST SCORE: {final_score}/100")
    print(f"🎯 RISK LEVEL: {risk_level}")
    print(f"💬 {risk_desc}")
    print(f"🔬 CONFIDENCE: {confidence}%")
    print(f"{'='*80}\n")

    result = {
        "SCORE": final_score,
        "RISK_LEVEL": risk_level,
        "RISK_DESCRIPTION": risk_desc,
        "CONFIDENCE": confidence,
        "positive_highlights": output["positive_highlights"],
        "negative_highlights": output["negative_highlights"],
        "details": output["details"],
        "checks_performed": scorer.total_checks,
        "positive_score": round(scorer.positive_score, 1),
        "negative_score": round(scorer.negative_score, 1)
    }

    try:
        result["target_urls"] = Utils.find_target_urls(url, 8)
    except:
        result["target_urls"] = []

    cache.set(url, result)
    return result

def report_url(url, is_scam, comment=""):
    """User reporting function"""
    reports_db.add_report(url, is_scam, comment)
    print(f"✓ Report submitted for {url}")

# ==================== END OF SCANNER ====================

if __name__ == "__main__":
    # Example usage
    test_url = "https://recipefinder.indiafoodnetwork.in/"
    print("\nTesting URL Scanner v4.0")
    print("=" * 80)
    
    result = get_prediction(test_url, model=None)
    
    print("\n📋 FINAL RESULT:")
    print(f"   URL: {test_url}")
    print(f"   Score: {result['SCORE']}/100")
    print(f"   Risk: {result['RISK_LEVEL']}")
    print(f"   Description: {result['RISK_DESCRIPTION']}")
    print(f"   Confidence: {result['CONFIDENCE']}%")
    print("\n" + "=" * 80)
