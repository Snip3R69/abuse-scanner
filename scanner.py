import tldextract
import whois
import dns.resolver
import socket
import requests

def normalize_url(user_input):
    ext = tldextract.extract(user_input)
    return ext.top_domain_under_public_suffix

def extract_info_deep(data):
    """Deeply searches RDAP JSON for emails and organization names."""
    email = None
    org = None
    
    # Search entities
    entities = data.get('entities', [])
    for entity in entities:
        vcard = entity.get('vcardArray', [])
        if len(vcard) > 1:
            for entry in vcard[1]:
                if entry[0] == 'email' and not email:
                    email = entry[3]
                if entry[0] == 'fn' and not org:
                    org = entry[3]
        
        # Check sub-entities
        if entity.get('entities'):
            sub_email, sub_org = extract_info_deep(entity)
            if not email: email = sub_email
            if not org: org = sub_org

    return email, org

def get_host_abuse(ip):
    if not ip or ip in ["N/A", "DNS Resolution Failed"]:
        return "N/A", "Unknown"
    
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AbuseScanner/1.0'}
    
    try:
        response = requests.get(f"https://rdap.org/ip/{ip}", headers=headers, timeout=10)
        if response.status_code == 200:
            rdap_data = response.json()
            rdap_str = str(rdap_data).lower()
            
            if "cloudflare" in rdap_str:
                return "Use Web Form", "Cloudflare"

            email, org = extract_info_deep(rdap_data)
            
            # Fallback for Org Name if fn is missing
            if not org:
                org = rdap_data.get('name', 'Unknown Provider')

            return (email if email else "Not Found"), org
    except Exception as e:
        print(f"RDAP Error: {e}")
    
    return "Not Found", "Unknown"

def scan_target(user_input):
    domain = normalize_url(user_input)
    if not domain:
        return {"error": "Invalid URL or Domain."}

    data = {
        "target": domain,
        "registrar": "N/A",
        "registrar_abuse": "N/A",
        "ip_address": "N/A",
        "host_provider": "Unknown",
        "host_abuse": "N/A",
        "is_cloudflare": False,
        "nameservers": []
    }

    try:
        w = whois.whois(domain)
        data["registrar"] = w.registrar
        if w.emails:
            data["registrar_abuse"] = w.emails if isinstance(w.emails, str) else ", ".join(w.emails)
        
        if w.name_servers:
            data["nameservers"] = [ns.lower() for ns in w.name_servers]
            if any("cloudflare.com" in ns for ns in data["nameservers"]):
                data["is_cloudflare"] = True

        try:
            result = dns.resolver.resolve(domain, 'A')
            data["ip_address"] = str(result[0])
            abuse_email, provider_name = get_host_abuse(data["ip_address"])
            
            data["host_abuse"] = abuse_email
            data["host_provider"] = provider_name
            
            if "cloudflare" in provider_name.lower():
                data["is_cloudflare"] = True
        except:
            data["ip_address"] = "DNS Resolution Failed"

    except Exception as e:
        data["error"] = str(e)
    return data
