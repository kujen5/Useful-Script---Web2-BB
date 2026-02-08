#!/bin/bash
# Generate consolidated reports for existing scan directories
# Usage: ./generate_consolidated_reports.sh <scan_directory>

count_lines() {
    local file="$1"
    if [[ -f "$file" && -s "$file" ]]; then
        wc -l < "$file" | tr -d ' '
    else
        echo "0"
    fi
}

generate_report() {
    local OUTDIR="$1"
    local DOMAIN=$(basename $(dirname "$OUTDIR"))
    local PROGRAM=$(basename $(dirname $(dirname "$OUTDIR")))

    echo "Generating report for $DOMAIN..."

    local consolidated="${OUTDIR}/${DOMAIN}_consolidated_report.txt"

    {
        echo "╔══════════════════════════════════════════════════════════════════════════╗"
        echo "║                    CONSOLIDATED RECONNAISSANCE REPORT                     ║"
        echo "╚══════════════════════════════════════════════════════════════════════════╝"
        echo ""
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  BASIC INFORMATION"
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "Program:          ${PROGRAM}"
        echo "Target Domain:    ${DOMAIN}"
        echo "Scan Date:        $(basename "$OUTDIR" | sed 's/_/ /; s/-/:/3; s/-/:/3')"
        echo "Output Directory: ${OUTDIR}"
        echo ""

        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  DISCOVERY SUMMARY"
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "Total Subdomains:     $(count_lines "${OUTDIR}/master_subdomains.txt")"
        echo "Live Web Assets:      $(count_lines "${OUTDIR}/phase6_web/live_urls.txt")"
        echo "Open Ports:           $(count_lines "${OUTDIR}/phase5_ports/naabu_scan.txt")"
        echo "URLs Discovered:      $(count_lines "${OUTDIR}/phase7_content/all_urls.txt")"
        echo "JS Files Analyzed:    $(count_lines "${OUTDIR}/phase7_content/js_files.txt")"
        echo "Vulnerabilities:      $(count_lines "${OUTDIR}/phase8_vulns/nuclei_all.txt")"
        echo ""

        # ASN Information
        if [[ -f "${OUTDIR}/phase1_rootdomain/asn_info.json" ]]; then
            echo "═══════════════════════════════════════════════════════════════════════════"
            echo "  ASN INFORMATION"
            echo "═══════════════════════════════════════════════════════════════════════════"
            python3 -c "
import json, sys
try:
    with open('${OUTDIR}/phase1_rootdomain/asn_info.json') as f:
        data = json.load(f)
    print('ASN Number:       {}'.format(data.get('asn', 'N/A')))
    print('ASN Name:         {}'.format(data.get('name', 'N/A')))
    print('ASN Description:  {}'.format(data.get('description', 'N/A')))
    print('IP Ranges:        {} CIDR blocks'.format(len(data.get('prefixes', []))))
except:
    print('ASN information not available')
" 2>/dev/null || echo "ASN information not available"
            echo ""
        fi

        # All Discovered Subdomains
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  ALL DISCOVERED SUBDOMAINS ($(count_lines "${OUTDIR}/master_subdomains.txt"))"
        echo "═══════════════════════════════════════════════════════════════════════════"
        if [[ -f "${OUTDIR}/master_subdomains.txt" ]]; then
            head -100 "${OUTDIR}/master_subdomains.txt" 2>/dev/null || echo "No subdomains found"
            local total_subs
            total_subs=$(count_lines "${OUTDIR}/master_subdomains.txt")
            if [[ $total_subs -gt 100 ]]; then
                echo ""
                echo "... and $((total_subs - 100)) more subdomains"
                echo "(See master_subdomains.txt for full list)"
            fi
        else
            echo "No subdomains discovered"
        fi
        echo ""

        # Live Web URLs
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  LIVE WEB URLS ($(count_lines "${OUTDIR}/phase6_web/live_urls.txt"))"
        echo "═══════════════════════════════════════════════════════════════════════════"
        if [[ -f "${OUTDIR}/phase6_web/live_urls.txt" && -s "${OUTDIR}/phase6_web/live_urls.txt" ]]; then
            head -50 "${OUTDIR}/phase6_web/live_urls.txt" 2>/dev/null || echo "No live URLs found"
            local total_urls
            total_urls=$(count_lines "${OUTDIR}/phase6_web/live_urls.txt")
            if [[ $total_urls -gt 50 ]]; then
                echo ""
                echo "... and $((total_urls - 50)) more URLs"
                echo "(See phase6_web/live_urls.txt for full list)"
            fi
        else
            echo "No live URLs found"
        fi
        echo ""

        # Status Code Breakdown
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  STATUS CODE BREAKDOWN"
        echo "═══════════════════════════════════════════════════════════════════════════"
        if [[ -d "${OUTDIR}/phase6_web/by_status" ]]; then
            for status_file in "${OUTDIR}/phase6_web/by_status"/*.txt; do
                if [[ -f "$status_file" && -s "$status_file" ]]; then
                    local status_code
                    status_code=$(basename "$status_file" .txt)
                    printf "  Status %-4s: %s URLs\n" "$status_code" "$(count_lines "$status_file")"
                fi
            done
        else
            echo "No status code data available"
        fi
        echo ""

        # Open Ports Summary
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  OPEN PORTS (Top 20)"
        echo "═══════════════════════════════════════════════════════════════════════════"
        if [[ -f "${OUTDIR}/phase5_ports/naabu_scan.txt" && -s "${OUTDIR}/phase5_ports/naabu_scan.txt" ]]; then
            head -20 "${OUTDIR}/phase5_ports/naabu_scan.txt" 2>/dev/null
            local total_ports
            total_ports=$(count_lines "${OUTDIR}/phase5_ports/naabu_scan.txt")
            if [[ $total_ports -gt 20 ]]; then
                echo "... and $((total_ports - 20)) more open ports"
                echo "(See phase5_ports/naabu_scan.txt for full list)"
            fi
        else
            echo "No open ports found"
        fi
        echo ""

        # JavaScript Analysis - Endpoints
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  JAVASCRIPT ANALYSIS - API ENDPOINTS"
        echo "═══════════════════════════════════════════════════════════════════════════"
        if [[ -f "${OUTDIR}/phase7_content/js_endpoints.txt" && -s "${OUTDIR}/phase7_content/js_endpoints.txt" ]]; then
            echo "Total Endpoints: $(count_lines "${OUTDIR}/phase7_content/js_endpoints.txt")"
            echo ""
            head -30 "${OUTDIR}/phase7_content/js_endpoints.txt" 2>/dev/null
            local total_endpoints
            total_endpoints=$(count_lines "${OUTDIR}/phase7_content/js_endpoints.txt")
            if [[ $total_endpoints -gt 30 ]]; then
                echo "... and $((total_endpoints - 30)) more endpoints"
                echo "(See phase7_content/js_endpoints.txt for full list)"
            fi
        else
            echo "No endpoints found in JavaScript files"
            echo "(Note: JS analysis may not have been run on this scan)"
        fi
        echo ""

        # JavaScript Analysis - URLs
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  JAVASCRIPT ANALYSIS - URLS"
        echo "═══════════════════════════════════════════════════════════════════════════"
        if [[ -f "${OUTDIR}/phase7_content/js_urls.txt" && -s "${OUTDIR}/phase7_content/js_urls.txt" ]]; then
            echo "Total URLs: $(count_lines "${OUTDIR}/phase7_content/js_urls.txt")"
            echo ""
            head -20 "${OUTDIR}/phase7_content/js_urls.txt" 2>/dev/null
            local total_js_urls
            total_js_urls=$(count_lines "${OUTDIR}/phase7_content/js_urls.txt")
            if [[ $total_js_urls -gt 20 ]]; then
                echo "... and $((total_js_urls - 20)) more URLs"
                echo "(See phase7_content/js_urls.txt for full list)"
            fi
        else
            echo "No URLs found in JavaScript files"
            echo "(Note: JS analysis may not have been run on this scan)"
        fi
        echo ""

        # JavaScript Analysis - Secrets
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  JAVASCRIPT ANALYSIS - SECRETS & API KEYS (*** HIGH PRIORITY ***)"
        echo "═══════════════════════════════════════════════════════════════════════════"
        if [[ -f "${OUTDIR}/phase7_content/js_secrets.txt" && -s "${OUTDIR}/phase7_content/js_secrets.txt" ]]; then
            echo "⚠️  TOTAL SECRETS FOUND: $(count_lines "${OUTDIR}/phase7_content/js_secrets.txt")"
            echo ""
            cat "${OUTDIR}/phase7_content/js_secrets.txt" 2>/dev/null
        else
            echo "✓ No secrets found in JavaScript files"
            echo "(Note: JS analysis may not have been run on this scan)"
        fi
        echo ""

        # JavaScript Analysis - Emails
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  JAVASCRIPT ANALYSIS - EMAIL ADDRESSES"
        echo "═══════════════════════════════════════════════════════════════════════════"
        if [[ -f "${OUTDIR}/phase7_content/js_emails.txt" && -s "${OUTDIR}/phase7_content/js_emails.txt" ]]; then
            echo "Total Emails: $(count_lines "${OUTDIR}/phase7_content/js_emails.txt")"
            echo ""
            head -20 "${OUTDIR}/phase7_content/js_emails.txt" 2>/dev/null
            local total_emails
            total_emails=$(count_lines "${OUTDIR}/phase7_content/js_emails.txt")
            if [[ $total_emails -gt 20 ]]; then
                echo "... and $((total_emails - 20)) more emails"
                echo "(See phase7_content/js_emails.txt for full list)"
            fi
        else
            echo "No email addresses found"
            echo "(Note: JS analysis may not have been run on this scan)"
        fi
        echo ""

        # JavaScript Analysis - Interesting Files
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  JAVASCRIPT ANALYSIS - INTERESTING FILES"
        echo "═══════════════════════════════════════════════════════════════════════════"
        if [[ -f "${OUTDIR}/phase7_content/js_files_found.txt" && -s "${OUTDIR}/phase7_content/js_files_found.txt" ]]; then
            echo "Total Files: $(count_lines "${OUTDIR}/phase7_content/js_files_found.txt")"
            echo ""
            cat "${OUTDIR}/phase7_content/js_files_found.txt" 2>/dev/null
        else
            echo "No interesting file paths found"
            echo "(Note: JS analysis may not have been run on this scan)"
        fi
        echo ""

        # CNAME Records (Subdomain Takeover Candidates)
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  CNAME RECORDS (Potential Subdomain Takeover)"
        echo "═══════════════════════════════════════════════════════════════════════════"
        if [[ -f "${OUTDIR}/phase3_dns/cnames.txt" && -s "${OUTDIR}/phase3_dns/cnames.txt" ]]; then
            echo "Total CNAMEs: $(count_lines "${OUTDIR}/phase3_dns/cnames.txt")"
            echo ""
            head -30 "${OUTDIR}/phase3_dns/cnames.txt" 2>/dev/null
            local total_cnames
            total_cnames=$(count_lines "${OUTDIR}/phase3_dns/cnames.txt")
            if [[ $total_cnames -gt 30 ]]; then
                echo "... and $((total_cnames - 30)) more CNAMEs"
                echo "(See phase3_dns/cnames.txt for full list)"
            fi
        else
            echo "No CNAME records found"
        fi
        echo ""

        # Vulnerabilities - Critical
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  CRITICAL VULNERABILITIES (*** IMMEDIATE ACTION REQUIRED ***)"
        echo "═══════════════════════════════════════════════════════════════════════════"
        if [[ -f "${OUTDIR}/phase8_vulns/nuclei_critical.json" && -s "${OUTDIR}/phase8_vulns/nuclei_critical.json" ]]; then
            echo "⚠️  CRITICAL FINDINGS: $(count_lines "${OUTDIR}/phase8_vulns/nuclei_critical.json")"
            echo ""
            python3 -c "
import json
try:
    with open('${OUTDIR}/phase8_vulns/nuclei_critical.json') as f:
        for line in f:
            try:
                obj = json.loads(line)
                tid = obj.get('template-id', 'unknown')
                name = obj.get('info', {}).get('name', 'Unknown')
                matched = obj.get('matched-at', 'N/A')
                print(f'[{tid}] {name}')
                print(f'  → {matched}')
                print()
            except:
                pass
except:
    print('No critical vulnerabilities')
" 2>/dev/null
        else
            echo "✓ No critical vulnerabilities found"
        fi
        echo ""

        # Vulnerabilities - High
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  HIGH SEVERITY VULNERABILITIES"
        echo "═══════════════════════════════════════════════════════════════════════════"
        if [[ -f "${OUTDIR}/phase8_vulns/nuclei_high.json" && -s "${OUTDIR}/phase8_vulns/nuclei_high.json" ]]; then
            echo "⚠️  HIGH SEVERITY FINDINGS: $(count_lines "${OUTDIR}/phase8_vulns/nuclei_high.json")"
            echo ""
            python3 -c "
import json
try:
    with open('${OUTDIR}/phase8_vulns/nuclei_high.json') as f:
        for line in f:
            try:
                obj = json.loads(line)
                tid = obj.get('template-id', 'unknown')
                name = obj.get('info', {}).get('name', 'Unknown')
                matched = obj.get('matched-at', 'N/A')
                print(f'[{tid}] {name}')
                print(f'  → {matched}')
                print()
            except:
                pass
except:
    print('No high severity vulnerabilities')
" 2>/dev/null
        else
            echo "✓ No high severity vulnerabilities found"
        fi
        echo ""

        # Vulnerability Summary
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  VULNERABILITY SUMMARY (All Severities)"
        echo "═══════════════════════════════════════════════════════════════════════════"
        for sev in critical high medium low info; do
            local sev_file="${OUTDIR}/phase8_vulns/nuclei_${sev}.json"
            if [[ -f "$sev_file" ]]; then
                printf "  %-10s: %s findings\n" "${sev^^}" "$(count_lines "$sev_file")"
            fi
        done
        echo ""
        echo "See phase8_vulns/ for detailed vulnerability reports"
        echo ""

        # Next Steps
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  RECOMMENDED NEXT STEPS"
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "1. Review and validate all CRITICAL and HIGH severity vulnerabilities"
        echo "2. Check for exposed secrets in phase7_content/js_secrets.txt"
        echo "3. Test CNAME records for subdomain takeover vulnerabilities"
        echo "4. Manually verify interesting API endpoints from JavaScript analysis"
        echo "5. Review open ports for unnecessary services"
        echo "6. Test discovered admin/debug/internal endpoints"
        echo "7. Analyze URLs for potential injection points"
        echo "8. Check for outdated software versions in httpx output"
        echo ""

        # File Locations
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  DETAILED OUTPUT LOCATIONS"
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "Master Subdomains:    master_subdomains.txt"
        echo "Live URLs:            phase6_web/live_urls.txt"
        echo "Open Ports:           phase5_ports/naabu_scan.txt"
        echo "JS Endpoints:         phase7_content/js_endpoints.txt"
        echo "JS Secrets:           phase7_content/js_secrets.txt"
        echo "Critical Vulns:       phase8_vulns/nuclei_critical.json"
        echo "High Vulns:           phase8_vulns/nuclei_high.json"
        echo "Full Summary:         report/summary.txt"
        echo "Statistics (JSON):    report/stats.json"
        echo ""
        echo "╔══════════════════════════════════════════════════════════════════════════╗"
        echo "║                         END OF CONSOLIDATED REPORT                        ║"
        echo "╚══════════════════════════════════════════════════════════════════════════╝"
    } > "$consolidated"

    echo "✓ Generated: $consolidated"
}

# Main execution
if [[ $# -eq 0 ]]; then
    echo "Usage: $0 <scan_directory> [<scan_directory2> ...]"
    echo "       $0 all  # Generate for all ant-group scans"
    exit 1
fi

if [[ "$1" == "all" ]]; then
    # Find all scan directories in ant-group-security-response-center
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    for scan_dir in "${SCRIPT_DIR}/ant-group-security-response-center"/*/*/; do
        if [[ -d "$scan_dir" && -f "${scan_dir}/master_subdomains.txt" ]]; then
            generate_report "$(realpath "$scan_dir")"
        fi
    done
else
    # Process specified directories
    for scan_dir in "$@"; do
        if [[ -d "$scan_dir" ]]; then
            generate_report "$(realpath "$scan_dir")"
        else
            echo "Error: Directory not found: $scan_dir"
        fi
    done
fi

echo ""
echo "Done! All consolidated reports have been generated."
