#!/bin/bash

set -euo pipefail

#check that there's an argument and give error if not an issue
if [[ $# != 1 ]]; then
    echo "Must have a target IP. Format: $0 <target ip>" >&2
    exit 1
fi

#declaring some variables for later
OUTPUT=output.txt
TARGET=$1
NMOUTPUT=nmoutput.xml
OTHER=otherworld.txt

#function that runs all the otherfunctions and creates the needed files
function main {

touch "$NMOUTPUT"

touch "$OUTPUT"
#clear output
echo "" > $OUTPUT

touch "$OTHER"

#I'm not going to lie to you, I did this part so long ago I don't remember why the functions are in brackets but it works so who cares
{
header

runthing

ports

vulns

recommend

summary

footer

generate_html
}

}

#pretty standard header. Tells who the target is
function header {
	echo "----Network Security Scan Report----" >> $OUTPUT
	echo "" >> $OUTPUT
	echo "Target IP: $TARGET" >> $OUTPUT
	echo "" >> $OUTPUT
}

#run nmap and save the output as xml document and as human readable document
function runthing {
	nmap -A --script vuln -oN $OTHER $TARGET >> /dev/null 2>&1
}
#Read the human readable version and print open ports
function ports {
	echo "--Open Ports and Detected Services--" >> $OUTPUT
	awk '$2 == "open" { print }' "$OTHER" >> "$OUTPUT"
}

#funky one here so we look at the human readable version for the product the version and the other little stuff and then query the CVE database for it
function vulns {
	echo "--Potential Vulnerabilities Identified--" >> $OUTPUT
	echo "" >> $OUTPUT
	#This checks agaisnt nmaps built in cve database
	echo "Checking nmap's built in database" >> $OUTPUT
	echo "" >> $OUTPUT
	awk '/VULNERABLE:/ {flag=1} /^\|_/ {flag=0} flag {print}' otherworld.txt >> $OUTPUT

	echo "" >> $OUTPUT
	echo "Parsing results for the online CVE query" >> $OUTPUT
	#this checks against the online nist thing
	awk '$2 == "open" {
    product = $4;
    version = $5;
    # If version is unknown, skip
    if (version == "?" || product == "?") next;
    # Remove extra trailing words from version (keep only first part)
	gsub(/[()].*$/, "", version); 
	sub(/p[0-9]+$/, "", version); 
	print product, version;
	}' "$OTHER" | while read -r product version; do
	#print to terminal

	display_version="$version"

	echo "Detected: $product $display_version"

    # Print to output file
	if [[ "$product" == "tcpwrapped" ]]; then
    	echo "Detected: tcpwrapped (no product info, cannot query NVD)" >> "$OUTPUT"
	else
    	echo "Detected: $product $display_version" >> "$OUTPUT"

    # Query NVD for this product/version
    	query_nvd "$product" "$display_version"
	fi
	done

	echo "" >> $OUTPUT
}
#Go through detected products and make a recomendation based on the like 20 most common things to show up (according to chatgpt)
#I'm not going to lie this is the best way I could think of :/ 
function recommend {
	echo "--Recommendations for Remediation--" >> $OUTPUT
	echo "" >> $OUTPUT

	awk '$2 == "open" { 
        product = $4
        version = $5
		extra = $6
        # Replace "?" with empty string
        if (version == "?") version = ""
		if (extra == "?") extra = ""
        if (product != "") { 
		print product, version, extra } 
    }' "$OTHER" | while read -r product version extra; do

		product=$(echo "$product" | tr '[:upper:]' '[:lower:]')

		case "$product" in 
  		"Apache"*) echo "Recommendation: Update Apache and check httpd.conf for security best practices." >> "$OUTPUT" ;;
  		"OpenSSH"*) echo "Recommendation: Patch OpenSSH and disable root login over SSH." >> "$OUTPUT" ;;
	    "smbd"*) echo "Recommendation: Disable SMBv1 and enforce signing/encryption." >> "$OUTPUT" ;;
		"nping"*) echo "Recommendation: Disable or restrict Nping. It's a diagnostic tool, not meant for production exposure. Limit usage to controlled testing environments." >> "$OUTPUT" ;;
		"ftp"*)       echo "Recommendation: Replace FTP with SFTP/FTPS, or disable if not needed. Avoid cleartext credentials." >> "$OUTPUT" ;;
	  	"telnet"*)    echo "Recommendation: Disable Telnet completely. Use SSH instead." >> "$OUTPUT" ;;
  		"ssh"*)       echo "Recommendation: Keep SSH patched, disable root login, and use key-based authentication." >> "$OUTPUT" ;;
  		"smtp"*)      echo "Recommendation: Patch mail daemon, enforce STARTTLS, and enable spam/relay restrictions." >> "$OUTPUT" ;;
  		"domain"*)    echo "Recommendation: Restrict DNS recursion to internal clients. Harden against cache poisoning & amplification." >> "$OUTPUT" ;;
		"http"*)      echo "Recommendation: Enforce HTTPS. Check for outdated web servers or CMS software." >> "$OUTPUT" ;;
		"https"*)     echo "Recommendation: Use strong TLS configs (disable SSLv2/3, weak ciphers). Keep certificates up-to-date." >> "$OUTPUT" ;;
  		"microsoft-ds"*) echo "Recommendation: Disable SMBv1, restrict SMB access to internal networks, and patch against EternalBlue-class issues." >> "$OUTPUT" ;;
  		"netbios-ssn"*)  echo "Recommendation: Restrict NetBIOS/SMB to internal networks only." >> "$OUTPUT" ;;
  		"rdp"*)       echo "Recommendation: Restrict RDP access (VPN only), enable NLA, enforce strong passwords & MFA." >> "$OUTPUT" ;;
  		"mysql"*)     echo "Recommendation: Bind MySQL to localhost or VPN only. Patch regularly." >> "$OUTPUT" ;;
  		"postgresql"*) echo "Recommendation: Restrict PostgreSQL exposure to trusted networks only." >> "$OUTPUT" ;;
  		"mongodb"*)   echo "Recommendation: Disable external MongoDB access unless secured. Require authentication." >> "$OUTPUT" ;;
  		"snmp"*)      echo "Recommendation: Change SNMP community strings, restrict access, and use SNMPv3 if possible." >> "$OUTPUT" ;;
  		"ntp"*)       echo "Recommendation: Restrict NTP usage to internal clients. Harden against amplification attacks." >> "$OUTPUT" ;;
  		"vnc"*)       echo "Recommendation: Do not expose VNC to the internet. Require VPN + strong authentication." >> "$OUTPUT" ;;
  		"elasticsearch"*) echo "Recommendation: Do not expose Elasticsearch directly. Secure with authentication and keep patched." >> "$OUTPUT" ;;
  		"redis"*)     echo "Recommendation: Bind Redis to localhost only. Enable AUTH and don’t expose to internet." >> "$OUTPUT" ;;
  		"docker"*)    echo "Recommendation: Never expose Docker API without TLS/auth. Restrict to root/admin use only." >> "$OUTPUT" ;;
		       *)              echo "Recommendation: Review and patch $product $version as needed. Apply vendor updates and follow security best practices." >> "$OUTPUT" ;;


		esac
		done
}

function footer {
	echo "----This Concludes Scan of $TARGET----" >> $OUTPUT
	echo "----Report Created $(date)----" >> $OUTPUT
}

query_nvd() {
	local product="$1"
	local version="$2"

	local results_limit=10

	echo
	echo "Querying NVD for vulnerabilities in: $product $version...."

	local search_query
	search_query=$(echo "$product $version" | sed 's/ /%20/g')

	local nvd_api_url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${search_query}&resultsPerPage=${results_limit}"

	local vulnerabilities_json
	vulnerabilities_json=$(curl -s "$nvd_api_url")

	#error checking

	if [[ -z "$vulnerabilities_json" ]]; then
		echo " [!] NVD API ERROR: $(echo "$vulnerabilities_json" | jq -r '.message')"
		return
	fi
	if ! echo "$vulnerabilities_json" | jq -e '.vulnerabilities[0]' > /dev/null; then
        echo "  [+] No vulnerabilities found in NVD for this keyword search."
        return
    fi
	#no more error checking
	 echo "$vulnerabilities_json" | jq -r \
        '.vulnerabilities[] | "  CVE ID: \(.cve.id)\n  Description: \((.cve.descriptions[] | select(.lang=="en")).value | gsub("\n"; " "))\n  Severity: \(.cve.metrics.cvssMetricV31[0].cvssData.baseSeverity // .cve.metrics.cvssMetricV2[0].cvssData.baseSeverity // "N/A")\n---"' >> $OUTPUT
}

function summary {

	 echo "--Scan Summary--" >> $OUTPUT

        # Count lines with open ports correctly
        open_ports=$(awk '/\/tcp.*open/ {count++} END {print count+0}' "$OTHER")

        # Count vulnerabilities from output
        vuln_count=$(grep -c "CVE ID:" "$OUTPUT" 2>/dev/null || echo "0")
        high_count=$(grep -c "Severity: HIGH" "$OUTPUT" 2>/dev/null || echo "0")
        medium_count=$(grep -c "Severity: MEDIUM" "$OUTPUT" 2>/dev/null || echo "0")
        low_count=$(grep -c "Severity: LOW" "$OUTPUT" 2>/dev/null || echo "0")
        na_count=$(grep -c "Severity: N/A" "$OUTPUT" 2>/dev/null || echo "0")

        echo "Total open ports: $open_ports" >> "$OUTPUT"
        echo "Detected vulnerabilities: $vuln_count (High: $high_count, Medium: $medium_count, Low: $low_count, N/A: $na_count)" >> "$OUTPUT"
        echo "" >> "$OUTPUT"
}

function generate_html {
    local html_file="report_$TARGET.html"

    echo "<!DOCTYPE html>
<html>
<head>
<meta charset='UTF-8'>
<title>Network Scan Report - $TARGET</title>
<style>
body { font-family: Arial, serif; margin: 20px; }
h1 { color: #333; }
h2 { color: #555; }
pre { background: #f0f0f0; padding: 10px; border-radius: 5px; }
</style>
</head>
<body>
<h1>Network Security Scan Report</h1>
<h2>Target: $TARGET</h2>
<pre>" > "$html_file"

    cat "$OUTPUT" >> "$html_file"

    echo "</pre>
</body>
</html>" >> "$html_file"

    echo "HTML report generated: $html_file"
}


main "$TARGET"
