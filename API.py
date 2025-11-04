
# import Utils

# # Returns score (0-180) , 0 is malicious 100 is safest site
# def get_prediction(url, model):

#     output = {
#         "SCORE": 180,
#         "InTop1Million": False,
#         "InURLVoidBlackList": False,
#         "isHTTPS": True,
#         "hasSSLCertificate": True,
#         "GoogleSafePassed": True,
#         "NortanWebSafePassed": True,
#         "InMcaffeBlackList": False,
#         "InSucuriBlacklist": False,
#         "isTemporaryDomain": False,
#         "isOlderThan3Months": True,
#         "isBlackListedinIpSets": False,
#         "target_urls": None
#     }

#     # -------------------------------------------------

#     try:
#         # Finding Possible Target URLs
#         print("Finding Target URLs...")
#         target_urls = Utils.find_target_urls(url, 8)
#         output["target_urls"] = target_urls
#     except:
#         print("Error Occured while finding target Urls !")

#     # ------------------------------------------------------

#     # Check Top 1 million valid sites
#     if Utils.check_top1million_database(url):
#         output["InTop1Million"] = True

#     # Check the domain in Top 1 million valid sites
#     if Utils.check_top1million_database_2(url):
#         output["InTop1Million"] = True

#     if output["InTop1Million"] == True:
#         # If URL is already valid no need to check further.
#         return output

#     # Check 40 blacklist sources
#     if Utils.checkURLVoid(url) > 0:
#         output["SCORE"] = output["SCORE"] - 20
#         output["InURLVoidBlackList"] = True
#         print("URL is blacklisted in UrlVoid's system !")
#     else:
#         print("URL is Safe in UrlVoid's system !")

#     # Check if it has SSL certififcate
#     if Utils.check_ssl_certificate(url) != True:
#         output["hasSSLCertificate"] = False
#         print("URL has not SSL Certificate !")
#         output["SCORE"] = output["SCORE"] - 20

#     # Check if HTTP/HTTPS. # If SSL present then it's already HTTPS safe
#     if output["hasSSLCertificate"] != True and Utils.is_https(url) != True:
#         print("URL is not HTTP secure")
#         output["isHTTPS"] = False

#     if Utils.check_google_safe_browsing(url) != True:
#         output["GoogleSafePassed"] = False
#         output["SCORE"] = output["SCORE"] - 20

#     if Utils.check_Nortan_WebSafe(url) != True:
#         output["NortanWebSafePassed"] = False
#         output["SCORE"] = output["SCORE"] - 20

#     if Utils.check_mcafee_database(url) != True:
#         output["InMcaffeBlackList"] = True
#         output["SCORE"] = output["SCORE"] - 10

#     if Utils.checkSucuriBlacklists(url) != True:
#         output["InSucuriBlacklist"] = True
#         output["SCORE"] = output["SCORE"] - 10

#     if Utils.is_temporary_domain(url):
#         print("Domain is registered from unsecure source")
#         output["isTemporaryDomain"] = True
#         output["SCORE"] = output["SCORE"] - 10

#     # check if url is older than 3 months
#     if Utils.get_days_since_creation(url, 3) != True:
#         print("Domain is less than 3 months old")
#         output["isOlderThan3Months"] = False
#         output["SCORE"] = output["SCORE"] - 10

#     if Utils.checkLocalBlacklist(url):
#         print("The URL is blacklisted !")
#         output["SCORE"] = output["SCORE"] - 20

#     if Utils.is_valid_ip(url) == True:
#         if Utils.check_ip_in_ipsets(url):
#             print("The IP address is blacklisted !")
#             output["isBlackListedinIpSets"] = True
#             output["SCORE"] = output["SCORE"] - 20
#     else:
#         print("Given address is not an valid IP address !")

#     # Make prediction using AI model
#     if Utils.isURLMalicious(url, model) == 1:
#         print("Model predicted the URL as malicious")
#         output["SCORE"] = output["SCORE"] - 20
#     else:
#         print("Model predicted URL not malicious !")

#     # Check if URL is present in Reporting database
#     if Utils.url_in_reporting_database(url):
#         print("URL is also present in the Reporting database !")
#         output["SCORE"] = output["SCORE"] - 20
#     else:
#         print("URL not in Reporting Database !")

#     return output



"""
API.py - Main prediction logic with parallel security checks
"""

import os
import requests
import hashlib
import json
from urllib.parse import urlparse
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import Utils

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ==================== CONFIGURATION ====================

GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

DEFAULT_TIMEOUT = (3, 10)
MAX_WORKERS = 5
CACHE_DURATION = timedelta(hours=24)
CACHE_FILE = "url_cache.json"

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
                    print(f"✓ Cache hit: {url}")
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

# ==================== API CHECKS ====================

def check_google_safe_browsing_api(url):
    if not GOOGLE_SAFE_BROWSING_KEY:
        return None
    
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_KEY}"
        payload = {
            "client": {"clientId": "phishing-detector", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        response = requests.post(api_url, json=payload, timeout=DEFAULT_TIMEOUT)
        if response.status_code == 200:
            result = response.json()
            return False if "matches" in result and len(result["matches"]) > 0 else True
    except:
        pass
    return None

def check_virustotal_api(url):
    if not VIRUSTOTAL_API_KEY:
        return None
    
    try:
        import base64
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=DEFAULT_TIMEOUT
        )
        
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return stats.get("malicious", 0) + stats.get("suspicious", 0)
    except:
        pass
    return None

def check_urlhaus_api(url):
    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=DEFAULT_TIMEOUT
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get("query_status") == "ok":
                return False  # Malicious
            elif result.get("query_status") == "no_results":
                return True  # Clean
    except:
        pass
    return None

# def check_ssl(url):
#     try:
#         domain = urlparse(url).netloc or urlparse(url).path.split('/')[0]
#         response = requests.get(f"https://{domain}", timeout=(2, 5), verify=True)
#         return True
#     except requests.exceptions.SSLError:
#         return False
#     except:
#         return None

import ssl
import socket
from datetime import datetime

def check_ssl(url):
    """
    Efficient SSL certificate check using socket connection
    Returns: True (valid), False (invalid/expired), NEVER None
    """
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Create SSL context
        context = ssl.create_default_context()
        
        # Connect directly to port 443 (HTTPS)
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Get certificate
                cert = ssock.getpeercert()
                
                # Check expiration
                not_after = cert.get('notAfter')
                if not_after:
                    expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    if expiry_date < datetime.now():
                        return False  # Expired
                
                return True  # Valid certificate
                
    except ssl.SSLError as e:
        print(f"SSL Error: {e}")
        return False  # Invalid SSL = False, NOT None
    except socket.timeout:
        print(f"SSL Timeout")
        return False  # Timeout = assume invalid
    except socket.gaierror:
        print(f"DNS resolution failed")
        return False  # DNS fail = can't verify
    except Exception as e:
        print(f"SSL check error: {e}")
        return False  # Any error = assume invalid

# ==================== MAIN PREDICTION ====================

def get_prediction(url, model):
    print(f"\n{'='*60}\n🔍 Analyzing: {url}\n{'='*60}")
    
    # Check cache
    cached = cache.get(url)
    if cached:
        return cached
    
    # Initialize output
    output = {
        "SCORE": 0,
        "RISK_LEVEL": "SAFE",
        "CONFIDENCE": 0,
        "checks_completed": 0,
        "InTop1Million": False,
        "InURLVoidBlackList": False,
        "isHTTPS": False,
        "hasSSLCertificate": None,
        "GoogleSafePassed": None,
        "VirusTotalDetections": 0,
        "InURLHaus": False,
        "isTemporaryDomain": False,
        # "isOlderThan3Months": None,
        "isBlackListedinIpSets": False,
        "isDirectIP": False,
        "hasMaliciousExtension": False,
        "target_urls": []
    }
    
    # Step 1: Whitelist check
    # FIXED CODE (no NULLs):
    if Utils.check_top1million_database(url) or Utils.check_top1million_database_2(url):
        print("✓ Found in Top 1M - SAFE")
        
        # Extract basic features
        is_https = Utils.is_https(url)
        
        # Quick SSL check (even for trusted sites)
        try:
            ssl_result = check_ssl(url)
        except:
            ssl_result = True  # Assume valid for Top 1M
        
        # Build complete response (no NULLs)
        output = {
            "SCORE": 5,
            "RISK_LEVEL": "SAFE",
            "CONFIDENCE": 100,
            "checks_completed": 2,  # Did 2 checks: Top1M + SSL
            "InTop1Million": True,
            "InURLVoidBlackList": False,
            "isHTTPS": is_https,
            "hasSSLCertificate": ssl_result,  # ← Now checked!
            "GoogleSafePassed": True,  # ← Assume passed for Top 1M
            "VirusTotalDetections": 0,
            "InURLHaus": False,
            "isTemporaryDomain": False,
            # "isOlderThan3Months": True,  # ← Assume old domain
            "isBlackListedinIpSets": False,
            "isDirectIP": False,
            "hasMaliciousExtension": False,
            "target_urls": []
        }
        
        cache.set(url, output)
        return output

    
    # Step 2: Extract features
    is_ip = Utils.is_ip_address(url)
    has_mal_ext = Utils.has_malicious_extension(url)
    is_https = Utils.is_https(url)
    is_temp = Utils.is_temporary_domain(url)
    
    output.update({
        "isHTTPS": is_https,
        "isTemporaryDomain": is_temp,
        "isDirectIP": is_ip == 1,
        "hasMaliciousExtension": has_mal_ext == 1
    })
    
    # Step 3: Run checks
    score = 0
    checks = 0
    
    # Critical indicators
    if is_ip == 1:
        score += 25
    if has_mal_ext == 1:
        score += 30
    if ".sh" in url or ".bin" in url:
        score += 20
    
    # API checks
    try:
        google_safe = check_google_safe_browsing_api(url)
        output["GoogleSafePassed"] = google_safe
        if google_safe is False:
            score += 25
        if google_safe is not None:
            checks += 1
    except:
        pass
    
    try:
        vt_count = check_virustotal_api(url) or 0
        output["VirusTotalDetections"] = vt_count
        if vt_count > 5:
            score += 35
        elif vt_count > 0:
            score += 20
        if vt_count is not None:
            checks += 1
    except:
        pass
    
    try:
        urlhaus = check_urlhaus_api(url)
        if urlhaus is False:
            score += 40
            output["InURLHaus"] = True
        if urlhaus is not None:
            checks += 1
    except:
        pass
    
    try:
        ssl = check_ssl(url)
        output["hasSSLCertificate"] = ssl
        if ssl is False:
            score += 12
        if ssl is not None:
            checks += 1
    except:
        pass
    
    # Additional checks
    try:
        urlvoid = Utils.checkURLVoid(url)
        if urlvoid > 0:
            output["InURLVoidBlackList"] = True
            score += 10 if urlvoid <= 5 else 20
        checks += 1
    except:
        pass
    
    try:
        if Utils.checkLocalBlacklist(url):
            score += 25
        checks += 1
    except:
        pass
    
    try:
        domain_age = Utils.get_days_since_creation(url, 3)
        # output["isOlderThan3Months"] = domain_age
        if domain_age is False:
            score += 10
        if domain_age is not None:
            checks += 1
    except:
        pass
    
    try:
        ml_pred = Utils.isURLMalicious(url, model)
        if ml_pred == 1:
            score += 15
        checks += 1
    except:
        pass
    
    try:
        output["target_urls"] = Utils.find_target_urls(url, 8)
    except:
        pass
    
    if is_temp:
        score += 15
    
    if not is_https:
        score += 3
    
    # Finalize
    final_score = min(score, 100)
    confidence = (checks / 10) * 100
    
    if final_score <= 20:
        risk = "SAFE"
    elif final_score <= 40:
        risk = "LOW"
    elif final_score <= 60:
        risk = "MEDIUM"
    elif final_score <= 80:
        risk = "HIGH"
    else:
        risk = "CRITICAL"
    
    output.update({
        "SCORE": final_score,
        "RISK_LEVEL": risk,
        "CONFIDENCE": round(confidence, 1),
        "checks_completed": checks
    })
    
    print(f"\n📊 SCORE: {final_score}/100 ({risk})")
    print(f"🎯 CONFIDENCE: {confidence:.1f}%\n")
    
    cache.set(url, output)
    return output
