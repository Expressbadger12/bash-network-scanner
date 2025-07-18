# bash-network-scanner
A bash script to scan for network vulnerabilities

This project aims to use nmap to scan a given network and parse through the results to find vulnerabilities on the network and then finds those vulnerabilities on a CVE list. 

The scanner does not work completely yet, but it performs an nmap scan and displays the open ports. It does not yet look through the CVE list. 

The future goal is to make the program find the active CVEs on the network and report them. 

Requires nmap to run.
