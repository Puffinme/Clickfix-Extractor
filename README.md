# CLICKFIX EXTRACTOR DOCUMENTATION

## OVERVIEW

ClickFix Extractor is a Python script designed to analyze web pages and extract Command and Control (C2) URLs from ClickFix campaign indicators. The script searches for malicious patterns involving MSHTA, MSIEXEC, PowerShell, and CMD commands that point to external C2 servers.

## FEATURES

- Automatic installation of required Python libraries (requests, urllib3)
- Single domain analysis or batch processing from file
- Detection of multiple ClickFix campaign patterns
- Optional deduplication of results
- URL defanging for safe handling
- Extraction of full malicious commands
- Output to console and/or file

## DETECTION PATTERNS

The script searches for the following malicious patterns:

1. MSIEXEC patterns:

   - msiexec /i https://...
   - msiexec \i https://...

2. MSHTA patterns:

   - mshta https://...

3. PowerShell patterns:

   - iwr (Invoke-WebRequest) with URLs
   - DownloadString with URLs
   - DownloadFile with URLs
   - Direct URL assignments in PowerShell variables

4. CMD patterns:

   - cmd commands containing URLs

5. IP address URLs:
   - URLs containing direct IP addresses (e.g., http://151.243.18.246/...)

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

When using --list option, provide a text file with one domain or domain/path per line:

    example1.com
    example2.com/suspicious/page
    compromised-site.org/update
    malicious-domain.net/path/to/page

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

- The script makes actual HTTP requests to the target domains and stores the response in memory only
- SSL certificate verification is disabled (verify=False)
- URLs are defanged by default for safe handling
- The script handles HTML entity decoding and escape sequences
- Commands are extracted and associated with their C2 URLs

## AUTHOR

Lucas Linkowski

## VERSION

1.0
