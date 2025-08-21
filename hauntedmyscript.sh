#!/bin/bash

set -euo pipefail

if [[ $# != 1 ]]; then
    echo "Must have a target IP. Format: $0 <target ip>" >&2
    exit 1
fi

OUTPUT=output.txt
TARGET=$1
NMOUTPUT=nmoutput.xml
OTHER=otherworld.txt
declare -a DETECTED_VULNS=()


function main {

# if [[ $# != 1 ]]; then
#     echo "Must have a target IP. Format: $0 <target ip>" >&2
#     exit 1
# fi

touch "$NMOUTPUT"

touch "$OUTPUT"

echo "" > $OUTPUT

touch "$OTHER"

{
header

runthing

ports

vulns

recommend

footer
}

}

function header {
	echo "----Network Security Scan Report----" >> $OUTPUT
	echo "" >> $OUTPUT
	echo "Target IP: $TARGET" >> $OUTPUT
	echo "" >> $OUTPUT
}

function runthing {
	echo "runthing nmap going"
	nmap -sV --script vuln -oX $NMOUTPUT -oN $OTHER $TARGET >> /dev/null 2>&1
	echo "runthing nmap done"
}

function ports {
	echo "--Open Ports and Detected Services--" >> $OUTPUT
	awk '$2 == "open" { print }' "$OTHER" >> "$OUTPUT"
}

function vulns {
	echo "--Potential Vulnerabilities Identified--" >> $OUTPUT
	echo "" >> $OUTPUT
	# echo "$SCAN_RESULTS" | grep "VULNERABLE"
	# echo "$SCAN_RESULTS" | grep "CVE"
	echo "-- Analyzing Service Versions --" >> $OUTPUT
	echo "" >> $OUTPUT
	# echo "$SCAN_RESULTS" | grep "open" | while read -r line; do 
	# 	product=$(echo "$line" | awk '{print $4}')
	# 	version=$(echo "$line" | awk '{print $5}' | sed 's/([^)]*)//g')

	# 	if [[ -z "$product" || -z "$version" ]]; then
    # 		continue
	# 	fi

	# 	echo "Detected: $product $version"
	# 	query_nvd "$product" "$version"
	# done

	# grep '<service.*product=.*version=' "$NMOUTPUT" | \
	# sed -n 's/.*product="\([^"]*\)".*version="\([^"]*\)".*/\1 \2/p' | \
	# while read -r product version; do
	# echo $product 
	# echo $version
    # # Clean up version string (remove parenthetical info)
    # #version=$(echo "$version" | sed 's/([^)]*)//g' | xargs)
    # version=${version:-""}

    # # if [[ -n "$product" && -n "$version" && "$version" != "?" ]]; then
    # #     echo "Detected: $product $version" >> $OUTPUT
    # #     query_nvd "$product" "$version"
    # # fi

	# if [[ -n "$product" ]]; then
    #         # Clean up version string
    #         version=$(echo "$version" | sed 's/([^)]*)//g' | xargs)
    #         echo "Detected: $product $version" >> $OUTPUT
    #         query_nvd "$product" "$version"
    #     fi
	# done

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
	#print to terminal

	display_version="$version"
    [[ -n "$extra" ]] && display_version="$display_version $extra"

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


	# echo "-- Analyzing Service Versions --"

	# echo "$SCAN_RESULTS" | grep "open" | while read -r line; do 
	# 	product=$(echo "$line" | awk '{print $4}')
	# 	version=$(echo "$line" | awk '{print $5}')
	# 	echo "Detected: $product $version"
	# 	query_nvd "$product" "$version"
	# done

function recommend {
	echo "--Recommendations for Remediation--" >> $OUTPUT
	echo "" >> $OUTPUT
	if [ ${#DETECTED_VULNS[@]} -eq 0 ]; then
        echo "No known vulnerabilities detected. Keep system updated." >> $OUTPUT
        return
    fi

	
    for vuln in "${DETECTED_VULNS[@]}"; do
        IFS="|" read -r cve severity desc <<< "$vuln"
        echo "CVE: $cve ($severity)" >> $OUTPUT

        case "$severity" in
            CRITICAL|HIGH)
                echo "  Recommendation: Patch immediately and restrict access to vulnerable service." >> $OUTPUT
                ;;
            MEDIUM)
                echo "  Recommendation: Schedule patch/update soon and monitor logs." >> $OUTPUT
                ;;
            LOW)
                echo "  Recommendation: Monitor system for unusual behavior." >> $OUTPUT
                ;;
            N/A)
                echo "  Recommendation: Investigate manually; severity unknown." >> $OUTPUT
                ;;
        esac
        echo "" >> $OUTPUT
    done

	echo "" >> $OUTPUT
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
	#  echo "$vulnerabilities_json" | jq -r \
    #     '.vulnerabilities[] | "  CVE ID: \(.cve.id)\n  Description: \((.cve.descriptions[] | select(.lang=="en")).value | gsub("\n"; " "))\n  Severity: \(.cve.metrics.cvssMetricV31[0].cvssData.baseSeverity // .cve.metrics.cvssMetricV2[0].cvssData.baseSeverity // "N/A")\n---"' >> $OUTPUT
	 while IFS= read -r line; do
        DETECTED_VULNS+=("$line")
    done < <(echo "$vulnerabilities_json" | jq -r \
        '.vulnerabilities[] | "\(.cve.id)|\(.cve.metrics.cvssMetricV31[0].cvssData.baseSeverity // .cve.metrics.cvssMetricV2[0].cvssData.baseSeverity // "N/A")|\( .cve.descriptions[] | select(.lang=="en") | .value)"')

}

main "$TARGET"
