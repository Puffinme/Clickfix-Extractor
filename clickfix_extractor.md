# CLICKFIX EXTRACTOR DOCUMENTATION

## OVERVIEW

ClickFix Extractor is a Python script designed to analyze web pages and extract Command and Control (C2) URLs from ClickFix campaign indicators. The script searches for malicious patterns involving MSHTA, MSIEXEC, PowerShell, and CMD commands that point to external C2 servers.

## FEATURES

- Automatic installation of required Python libraries (requests, urllib3)
- Single domain, full URL, or IP target; batch processing from file
- 45 URL extraction patterns: MSHTA, MSIEXEC, PowerShell, CMD, certutil, bitsadmin, hex/encoded IPs, macOS curl|bash, WinHttp/VBScript, steganography/image payloads, JavaScript embedded commands
- Full command extraction for context (7 command patterns)
- Optional deduplication of results
- URL defanging for safe handling
- Output to console and/or file

## DETECTION PATTERNS

The script uses 45 URL extraction patterns and 7 command extraction patterns. It searches for the following:

1. MSIEXEC and MSHTA:
   - msiexec /i or \i with https://...
   - mshta with https://...
   - mshta with hex-encoded IPs (e.g. https://0x7f.0x0.0.0.1/...)

2. PowerShell download and execution:
   - iwr, Invoke-WebRequest, curl, wget with URLs
   - irm, Invoke-RestMethod with URLs; irm/curl/wget ... | iex
   - DownloadString, DownloadFile with URLs
   - New-Object Net.WebClient and WebRequest.Create
   - Start-BitsTransfer -Source URL
   - -OutFile with URL; -Uri parameter
   - Hidden, noprofile, bypass, encodedcommand variants
   - cmd /c start /min powershell with URL

3. CMD and certutil/bitsadmin:
   - cmd commands containing URLs
   - certutil -urlcache -f URL
   - bitsadmin /transfer with URL
   - curl.exe with URL

4. IP and encoded IP URLs:
   - Standard IPv4 URLs (e.g. http://151.243.18.246/...)
   - Hex-encoded IPs (https://0x7f.0x0.0.0.1/...)
   - Decimal and octal encoded IP URLs

5. macOS terminal attack patterns:
   - curl URL | bash/sh, wget URL | bash/sh
   - osascript -e with URL

6. WinHttp and VBScript:
   - .Open "GET" with URL; wscript //E:VBScript with URL

7. Steganography and image payloads:
   - iwr/Invoke-WebRequest/curl/wget with .jpg, .png, .gif, .bmp, .webp
   - New-Object System.Drawing.Bitmap with URL
   - DownloadFile with image URL

8. JavaScript embedded commands:
   - const/var/let command = or cmd = or text = with https://... in same assignment

9. Command extraction (full command capture for context):
   - msiexec, mshta, powershell, cmd full commands
   - curl ... | bash/sh, wget ... | bash/sh
   - UNC paths (\\server\share\file.ps1|bat|cmd|hta)

## INSTALLATION

No manual installation required. The script will automatically install required packages on first run:

- requests
- urllib3

## USAGE

Single Domain Analysis:

    python clickfix_extractor.py -d example.com
    python clickfix_extractor.py --domain example.com/malicious/path

Batch Processing from File:

    python clickfix_extractor.py -l domains.txt -o c2_results.txt
    python clickfix_extractor.py --list domains.txt --output results.txt

With Deduplication:

    python clickfix_extractor.py -l domains.txt -o results.txt --unique

Verbose Mode:

    python clickfix_extractor.py -d example.com -v
    python clickfix_extractor.py -l domains.txt -v

Timeout:

    python clickfix_extractor.py -d example.com -t 15
    python clickfix_extractor.py -l domains.txt -t 10

## COMMAND LINE ARGUMENTS

Required (one of):

    --domain, -d    Single domain or domain/path to analyze
                    Example: example.com or example.com/path

    --list, -l      Text file containing list of domains/paths (one per line)
                    Example: domains.txt

Optional:

    --output, -o    Output file for C2 URLs (default: stdout only)
                    Example: c2_results.txt

    --unique, -u    Deduplicate results (output unique C2s only)
                    Default: outputs all results including duplicates

    --no-defang     Do not defang URLs in output (show raw URLs)
                    Default: URLs are defanged (dots replaced with [.])

    --no-commands   Do not show extracted commands in output
                    Default: shows associated commands

    --verbose, -v   Verbose output mode
                    Default: minimal output

    --timeout, -t   Request timeout in seconds
                    Default: 30 seconds

## INPUT FILE FORMAT

When using --list option, provide a text file with one target per line. Each line may be a bare domain, a domain with path, or a full URL:

    example1.com
    example2.com/suspicious/page
    https://compromised-site.org/update
    http://192.168.1.1/path

Lines starting with # are treated as comments and ignored.
Empty lines are ignored.

## OUTPUT FORMAT

Console Output:  
The script displays:

- Source URL where C2 was found
- C2 Domain (extracted from URL)
- C2 URL (defanged by default)
- Associated commands (if found and --no-commands not used)

File Output:  
When --output is specified, the file contains one C2 URL per line.  
URLs are written in their raw form (not defanged) for easy processing.

## EXAMPLE OUTPUT

Console:

    [*] ClickFix C2 Extractor
    [*] Searching for MSHTA/MSIEXEC/PowerShell C2 indicators

    [*] Fetching: https://example.com
    [*] Analyzing content (15234 bytes)...
    [+] Found 2 C2 indicator(s)

    ======================================================================
    CLICKFIX C2 EXTRACTION RESULTS
    ======================================================================

    Source: https://example.com
    C2 Domain: 151[.]243[.]18[.]246
    C2 URL: hxxp://151[.]243[.]18[.]246/bcvv.wav
    Commands:
      powershell -w h -nop -c "$z=Join-Path $env:APPDATA 'e1zh\z10t.ps1'...

    ======================================================================

    [+] C2 URLs saved to: c2_results.txt

File (c2_results.txt):

    http://151.243.18.246/bcvv.wav
    https://malicious-c2.com/payload.exe

## ERROR HANDLING

- If a domain cannot be reached, the script continues with next target
- SSL errors automatically fall back to HTTP
- Missing files are reported with clear error messages
- Failed requests are logged but do not stop batch processing

## NOTES

- The script makes actual HTTP requests to the target domains
- SSL certificate verification is disabled (verify=False)
- URLs are defanged by default for safe handling
- The script handles HTML entity decoding and escape sequences
- Commands are extracted and associated with their C2 URLs

## AUTHOR

Based on SocGholish analyzer script (sganalyzerv2.py)

## VERSION

1.1
