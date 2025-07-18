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
	nmap -sV $TARGET | grep "open"
}

function vulns {
	echo "--Potential Vulnerabilities Identified--"
	echo ""
	echo "CVE-2023-573 -- Outdated Internal Server"
	echo "CVE-2009-420 -- Potential Locust Infestation"
	echo ""
	#note: these are hardcoded values because I can't read nmap input yet, nor can I access CVE lists on the internet. 
}

function recommend {
	echo "--Recommendations for Remediation--"
	echo ""
	echo "Update drivers"
	echo "Vanquishing spell"
	echo "Change passwords"
	echo ""
	#Note these are also hardcoded for the same reasons the above ones are.
}

function footer {
	echo "----This Concludes Scan of $TARGET----"
	echo "----Report Created $(date)----"
}

main "$TARGET"  > $OUTPUT
