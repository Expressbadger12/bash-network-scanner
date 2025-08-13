#!/bin/bash

OUTPUT=output.txt
TARGET=$1

function main {

if [[ $# != 1 ]]; then
    echo "Must have a target IP. Format: $0 <target ip>" >&2
    exit 1
fi

touch "$OUTPUT"

{
header

ports

vulns

recommend

footer
} > "$OUTPUT"

}

function header {
	echo "----Network Security Scan Report----"
	echo ""
	echo "Target IP: $TARGET"
	echo ""
}

function ports {
	echo "--Open Ports and Detected Services--"
	nmap -sV --script vuln $TARGET | grep "open"
}

function vulns {
	echo "--Potential Vulnerabilities Identified--"
	echo ""
	SCAN_RESULTS=$(nmap -sV --script vuln "$TARGET")
	echo "$SCAN_RESULTS" | grep "VULNERABLE"
	echo "$SCAN_RESULTS" | grep "CVE"
	echo ""
}

function recommend {
	echo "--Recommendations for Remediation--"
	echo ""
	echo "Update drivers"
	echo "Vanquishing spell"
	echo "Change passwords"
	echo ""
	#Note these are also hardcoded for now
}

function footer {
	echo "----This Concludes Scan of $TARGET----"
	echo "----Report Created $(date)----"
}

query_nvd() {
	local product="$1"
	local version="$2"

	local results_limit=3

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
        '.vulnerabilities[] | "  CVE ID: \(.cve.id)\n  Description: \((.cve.descriptions[] | select(.lang=="en")).value | gsub("\n"; " "))\n  Severity: \(.cve.metrics.cvssMetricV31[0].cvssData.baseSeverity // .cve.metrics.cvssMetricV2[0].cvssData.baseSeverity // "N/A")\n---"'
}

main "$TARGET"  > $OUTPUT
