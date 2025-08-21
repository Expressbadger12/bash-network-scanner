# bash-network-scanner

A bash script to scan for network vulnerabilities

## Overview

This script uses nmap to scan a given network for preexisting vulnerabilities by comparing the output of the nmap scan to the contents of a CVE database. It then takes the data it gathered and formats it in a professional report to be easily digested. 

## Features

**Network scanning**: Scans ports and invesntigates services
**Automated report**: Makes a report based on the information gathered from the scan with no effort required on the user's end
**HTML Report option**: The script also makes an html version of the report to be viewed in browser
**CVE database querying**: Checks scan results against trusted CVE databases
**Appropriate recommendations**: Gives accurate recommendations based on the vulnerabilities found
**Easy to use**: I break the whole thing down in this readme
**Made with love**: and maybe a little bit of frustration 

## Requirements

Requires nmap, jq, and curl to run.

### Installation of Dependencies

we're doing -y 'cause you trust me, don't you?

**Ubuntu/Debian (the normal distro):**

```bash
sudo apt update
sudo apt install -y nmap jq curl
```

**Fedora**

```bash
sudo dnf install -y nmap jq curl
```

**CentOS / RHEL (I haven't even heard of this one)**

```bash
sudo yum install -y nmap jq curl
```

**Arch Linux**

```bash
sudo pacman -Sy --noconfirm nmap jq curl
```

**openSUSE**

```bash
sudo zypper install -y nmap jq curl
```

**macOS (with Homebrew)**

```bash
brew install nmap jq curl
```

## Installation of script

Download the script from gethub and unzip the file

## Usage

The script must be run in the directory in which they exist

### Syntax

```bash
./myscript.sh <target IP or hostname>
```

### Output

The script creates a file called output.txt that contains the report and data from the scan. 
The script will also create an html file called report_<target>.html if you prefer html
The script also creates a file called outherworld.txt which are used by the script for formatting. They can be ignored by and even deleted by the user.

## Disclaimer

This tool is designed to be used for security purposes only. Only use this script on networks you have permission to use it on. I am not responsible for anything you do with this. 