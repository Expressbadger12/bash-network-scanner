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

main "$TARGET"  > $OUTPUT
