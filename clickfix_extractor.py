import os
import subprocess
import re
import sys
import argparse
import warnings
from urllib.parse import urlparse

def install_package(package_name):
    try:
        print(f"[*] Installing required package: {package_name}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package_name], 
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"[+] Successfully installed {package_name}")
        return True
    except subprocess.CalledProcessError:
        print(f"[!] Failed to install {package_name}. Please install manually: pip install {package_name}")
        return False

try:
    import requests
except ImportError:
    print("[!] 'requests' module not found. Attempting to install...")
    if not install_package("requests"):
        sys.exit(1)
    import requests

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[!] 'urllib3' module not found. Attempting to install...")
    if not install_package("urllib3"):
        sys.exit(1)
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


PATTERNS = {
    # MSIEXEC invoking external URL/IP
    'msiexec': r'msiexec\s*[\/\\]i\s*(https?:\/\/[^\s\"\'\<\>\)\]]+)',
    # MSHTA executing HTTP-based payloads  
    'mshta': r'mshta\s+(https?:\/\/[^\s\"\'\<\>\)\]]+)',
    # PowerShell with URL extraction (iwr, Invoke-WebRequest, wget, curl)
    'powershell_iwr': r'(?:iwr|Invoke-WebRequest|wget|curl)[^\n]*[\'\"](https?:\/\/[^\s\"\'\<\>\)\]]+)[\'\"]',
    # PowerShell direct URL assignment
    'powershell_url': r'\$\w+\s*=\s*[\'\"](https?:\/\/[^\s\"\'\<\>\)\]]+)[\'\"]',
    # PowerShell downloadstring/downloadfile
    'powershell_download': r'(?:DownloadString|DownloadFile)\s*\(\s*[\'\"](https?:\/\/[^\s\"\'\<\>\)\]]+)[\'\"]',
    # Generic HTTP/HTTPS URL with IP address pattern
    'ip_url': r'https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?[^\s\"\'\<\>\)\]]*',
    # CMD with URL (requires word boundary and proper cmd syntax)
    'cmd_url': r'(?:^|[\s\"\'\;])cmd(?:\.exe)?\s*[\/\\][^\n]*?(https?:\/\/[^\s\"\'\<\>\)\]]+)',
    
    # Full PowerShell command patterns (with powershell prefix)
    # powershell -c iex(iwr -Uri IP/URL -UseBasicParsing)
    'ps_iex_iwr': r'powershell[^\n]*?(?:iex|Invoke-Expression)\s*\(\s*(?:iwr|Invoke-WebRequest)[^\)]*?(?:-Uri\s+)?[\'\"]*?(https?:\/\/[^\s\"\'\)\]]+|[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}[^\s\"\'\)\]]*)',
    # powershell -c "IEX(New-Object Net.WebClient).DownloadString('URL')"
    'ps_iex_webclient': r'powershell[^\n]*?(?:IEX|Invoke-Expression)\s*\(\s*(?:\(?\s*New-Object\s+)?(?:System\.)?Net\.WebClient[^\)]*?\.DownloadString\s*\(\s*[\'\"](https?:\/\/[^\s\"\'\)\]]+)[\'\"]',
    # powershell with -Uri parameter and IP or URL
    'ps_uri_param': r'powershell[^\n]*?-Uri\s+[\'\"]*?(https?:\/\/[^\s\"\'\)\]]+|[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}(?::\d+)?[^\s\"\'\)\]]*)',
    # powershell with Invoke-RestMethod
    'ps_irm': r'powershell[^\n]*?(?:Invoke-RestMethod|irm)\s+[\'\"]*?(https?:\/\/[^\s\"\'\)\]]+)',
    # powershell with Start-BitsTransfer
    'ps_bits': r'powershell[^\n]*?Start-BitsTransfer[^\n]*?-Source\s+[\'\"](https?:\/\/[^\s\"\'\)\]]+)[\'\"]',
    
    # IEX with DownloadString (standalone in embedded code)
    'iex_downloadstring': r'(?:IEX|Invoke-Expression)\s*\([^\)]*?\.DownloadString\s*\(\s*[\'\"](https?:\/\/[^\s\"\'\)\]]+)[\'\"]',
    # Invoke-RestMethod standalone
    'irm_standalone': r'(?:Invoke-RestMethod|irm)\s+[\'\"]*?(https?:\/\/[^\s\"\'\)\]]+)[\'\"]?',
    
    # certutil download
    'certutil': r'certutil[^\n]*?-urlcache[^\n]*?-(?:split\s+-)?f\s+[\'\"]*?(https?:\/\/[^\s\"\'\)\]]+)',
    # bitsadmin download
    'bitsadmin': r'bitsadmin[^\n]*?\/transfer[^\n]*?(https?:\/\/[^\s\"\'\)\]]+)',
    # curl.exe (Windows)
    'curl_exe': r'curl(?:\.exe)?\s+[^\n]*?[\'\"]*?(https?:\/\/[^\s\"\'\)\]]+)',
    
    # New-Object Net.WebClient with DownloadFile
    'webclient_downloadfile': r'Net\.WebClient[^\n]*?\.DownloadFile\s*\(\s*[\'\"](https?:\/\/[^\s\"\'\)\]]+)[\'\"]',
    # WebRequest.Create
    'webrequest': r'\[?(?:System\.)?Net\.WebRequest\]?::Create\s*\(\s*[\'\"](https?:\/\/[^\s\"\'\)\]]+)[\'\"]',
}

# command extraction
COMMAND_PATTERNS = {
    'msiexec_full': r'(msiexec\s*[\/\\][^\n\r\<\>\"\'\;]{10,})',
    'mshta_full': r'(mshta\s+[^\n\r\<\>\"\'\;]{10,})',
    'powershell_full': r'(powershell[^\n\r\<\>\"\'\;]{20,})',
    'cmd_full': r'(cmd\s*[\/\\][^\n\r\<\>\"\'\;]{20,})',
}

def is_valid_c2_url(url):
    """Validate that extracted URL looks like a real C2 URL, not garbage"""
    if not url:
        return False
    url = url.strip()
    if not url.startswith('http://') and not url.startswith('https://'):
        return False
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return False
        domain = parsed.netloc.split(':')[0]
        if len(domain) < 3:
            return False
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$', domain):
            return False
        if '..' in domain or domain.startswith('.') or domain.endswith('.'):
            return False
        if len(url) > 2048:
            return False
    except:
        return False
    return True

def normalize_url(target):
    """Normalize a domain or URL to a proper URL format"""
    target = target.strip()
    if not target:
        return None
    if not target.startswith('http://') and not target.startswith('https://'):
        target = 'https://' + target
    return target

def fetch_page_content(url, timeout=30):
    """Fetch HTML content from a URL"""
    request_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    }
    try:
        response = requests.get(url, headers=request_headers, timeout=timeout, verify=False, allow_redirects=True)
        response.raise_for_status()
        return response.text
    except requests.exceptions.SSLError:
        # Try HTTP if HTTPS fails
        if url.startswith('https://'):
            http_url = url.replace('https://', 'http://', 1)
            try:
                response = requests.get(http_url, headers=request_headers, timeout=timeout, verify=False, allow_redirects=True)
                response.raise_for_status()
                return response.text
            except Exception as e:
                print(f"[!] Error fetching {http_url}: {e}")
                return None
        return None
    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching {url}: {e}")
        return None

def extract_c2_from_content(content, source_url=""):
    """Extract C2 URLs and commands from page content"""
    results = []
    
    if not content:
        return results
    
    # Decode common HTML entities and escape sequences
    content_decoded = content
    content_decoded = content_decoded.replace('\\/', '/')
    content_decoded = content_decoded.replace('&amp;', '&')
    content_decoded = content_decoded.replace('&quot;', '"')
    content_decoded = content_decoded.replace('&#39;', "'")
    content_decoded = content_decoded.replace('&lt;', '<')
    content_decoded = content_decoded.replace('&gt;', '>')
    
    # Also check for hex-encoded or unicode-escaped URLs
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', DeprecationWarning)
            content_decoded = content_decoded.encode().decode('unicode_escape')
    except:
        pass
    
    # Extract C2 URLs
    c2_urls = set()
    
    for pattern_name, pattern in PATTERNS.items():
        matches = re.findall(pattern, content_decoded, re.IGNORECASE)
        for match in matches:
            if isinstance(match, tuple):
                match = match[0] if match[0] else match[1] if len(match) > 1 else ""
            if match:
                url = match.strip()
                if is_valid_c2_url(url):
                    c2_urls.add(url)
    
    # Extract full commands
    commands = []
    for pattern_name, pattern in COMMAND_PATTERNS.items():
        matches = re.findall(pattern, content_decoded, re.IGNORECASE)
        for match in matches:
            # Clean up the command
            cmd = match.strip()
            cmd = re.sub(r'\s+', ' ', cmd)  # Normalize whitespace
            if len(cmd) > 20:  # Only include substantial commands
                commands.append(cmd)
    
    # Build results
    for c2_url in c2_urls:
        # Extract domain/IP from C2 URL
        try:
            parsed = urlparse(c2_url)
            c2_domain = parsed.netloc if parsed.netloc else c2_url
        except:
            c2_domain = c2_url
        
        result = {
            'source': source_url,
            'c2_url': c2_url,
            'c2_domain': c2_domain,
            'commands': []
        }
        
        # Associate commands that contain this C2 URL
        for cmd in commands:
            if c2_url in cmd or c2_domain in cmd:
                result['commands'].append(cmd)
        
        results.append(result)
    
    # Also add commands that might have URLs we missed
    for cmd in commands:
        # Check if this command has a URL not already captured
        urls_in_cmd = re.findall(r'https?:\/\/[^\s\"\'\<\>\)\]]+', cmd, re.IGNORECASE)
        for url in urls_in_cmd:
            if url not in c2_urls and is_valid_c2_url(url):
                try:
                    parsed = urlparse(url)
                    c2_domain = parsed.netloc if parsed.netloc else url
                except:
                    c2_domain = url
                results.append({
                    'source': source_url,
                    'c2_url': url,
                    'c2_domain': c2_domain,
                    'commands': [cmd]
                })
                c2_urls.add(url)
    
    return results

def defang_url(url):
    """Defang a URL for safe display/storage"""
    return url.replace(".", "[.]").replace("http", "hxxp")

def process_single_target(target, verbose=False):
    """Process a single domain/URL and extract C2 information"""
    url = normalize_url(target)
    if not url:
        return []
    
    if verbose:
        print(f"[*] Fetching: {url}")
    
    content = fetch_page_content(url)
    if not content:
        if verbose:
            print(f"[!] Failed to fetch content from {url}")
        return []
    
    if verbose:
        print(f"[*] Analyzing content ({len(content)} bytes)...")
    
    results = extract_c2_from_content(content, url)
    
    if verbose:
        if results:
            print(f"[+] Found {len(results)} C2 indicator(s)")
        else:
            print(f"[-] No ClickFix indicators found")
    
    return results

def process_file(filepath, verbose=False):
    """Process a file containing list of domains/URLs"""
    all_results = []
    
    if not os.path.exists(filepath):
        print(f"[!] Error: File '{filepath}' not found")
        return all_results
    
    with open(filepath, 'r') as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    print(f"[*] Processing {len(targets)} target(s) from {filepath}")
    
    for i, target in enumerate(targets, 1):
        if verbose:
            print(f"\n[{i}/{len(targets)}] Processing: {target}")
        else:
            print(f"[{i}/{len(targets)}] {target}", end=" ... ")
        
        results = process_single_target(target, verbose=verbose)
        
        if not verbose:
            if results:
                print(f"found {len(results)} C2(s)")
            else:
                print("no C2 found")
        
        all_results.extend(results)
    
    return all_results

def output_results(results, unique=False, output_file=None, defang=True, show_commands=True):
    """Output results to stdout and optionally to file"""
    
    if unique:
        # Deduplicate by C2 URL
        seen_urls = set()
        unique_results = []
        for r in results:
            if r['c2_url'] not in seen_urls:
                seen_urls.add(r['c2_url'])
                unique_results.append(r)
        results = unique_results
        print(f"\n[*] Unique C2s: {len(results)}")
    
    if not results:
        print("\n[!] No ClickFix C2 indicators found")
        return
    
    print("\n" + "=" * 70)
    print("CLICKFIX C2 EXTRACTION RESULTS")
    print("=" * 70)
    
    output_lines = []
    
    for r in results:
        c2_display = defang_url(r['c2_url']) if defang else r['c2_url']
        domain_display = defang_url(r['c2_domain']) if defang else r['c2_domain']
        
        print(f"\nSource: {r['source']}")
        print(f"C2 Domain: {domain_display}")
        print(f"C2 URL: {c2_display}")
        
        # For file output, just the C2 URL (or domain)
        output_lines.append(r['c2_url'])
        
        if show_commands and r['commands']:
            print("Commands:")
            for cmd in r['commands']:
                # Truncate very long commands for display
                display_cmd = cmd[:200] + "..." if len(cmd) > 200 else cmd
                print(f"  {display_cmd}")
    
    print("\n" + "=" * 70)
    
    if output_file:
        with open(output_file, 'w') as f:
            for line in output_lines:
                f.write(line + '\n')
        print(f"\n[+] C2 URLs saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description='ClickFix Campaign C2 Extractor - Extracts C2 URLs from MSHTA/MSIEXEC/PowerShell payloads',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Single domain:
    python clickfix_extractor.py -d example.com
    python clickfix_extractor.py -d example.com/malicious/path

  File with list of domains:
    python clickfix_extractor.py -l domains.txt -o c2_results.txt
    python clickfix_extractor.py -l domains.txt -o c2_results.txt --unique

  Additional options:
    python clickfix_extractor.py -d example.com --no-defang
    python clickfix_extractor.py -l domains.txt -o results.txt --unique -v

Detection patterns:
  - msiexec /i https://...  (MSIEXEC external URL)
  - mshta https://...       (MSHTA HTTP payloads)
  - powershell iwr/Invoke-WebRequest with URLs
  - PowerShell DownloadString/DownloadFile
  - URLs with IP addresses
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--domain', '-d',
                      help='Single domain or domain/path to analyze (e.g., example.com or example.com/path)')
    
    group.add_argument('--list', '-l',
                      help='Text file containing list of domains/paths (one per line)')
    
    parser.add_argument('--output', '-o',
                       default=None,
                       help='Output file for C2 URLs (default: stdout only)')
    
    parser.add_argument('--unique', '-u',
                       action='store_true',
                       help='Deduplicate results (output unique C2s only)')
    
    parser.add_argument('--no-defang',
                       action='store_true',
                       help='Do not defang URLs in output (show raw URLs)')
    
    parser.add_argument('--no-commands',
                       action='store_true',
                       help='Do not show extracted commands in output')
    
    parser.add_argument('--verbose', '-v',
                       action='store_true',
                       help='Verbose output')
    
    parser.add_argument('--timeout', '-t',
                       type=int,
                       default=30,
                       help='Request timeout in seconds (default: 30)')
    
    args = parser.parse_args()
    
    print("[*] ClickFix C2 Extractor")
    print("[*] Searching for MSHTA/MSIEXEC/PowerShell C2 indicators\n")
    
    results = []
    
    if args.domain:
        results = process_single_target(args.domain, verbose=args.verbose)
    elif args.list:
        results = process_file(args.list, verbose=args.verbose)
    
    output_results(
        results,
        unique=args.unique,
        output_file=args.output,
        defang=not args.no_defang,
        show_commands=not args.no_commands
    )

if __name__ == "__main__":
    main()



