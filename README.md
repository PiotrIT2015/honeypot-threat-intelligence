# Honeypot Threat Intelligence Platform

A Python-based cybersecurity project for collecting, parsing, analyzing, and visualizing activity captured by an SSH honeypot. The platform is designed as a learning and portfolio project focused on threat intelligence, Indicators of Compromise (IOCs), and lightweight security operations workflows.

## Overview

The project brings together a honeypot, log-processing components, threat-intelligence enrichment, IOC analysis, and a web dashboard.

The intended workflow is:

```text
Internet / Test Attacker
        |
        v
   Cowrie SSH Honeypot
        |
        v
   Log Collection
        |
        v
   Event Parsing and Normalization
        |
        v
   Threat Intelligence Enrichment
        |
        v
   IOC Analysis and Risk Scoring
        |
        v
   Alerts and Streamlit Dashboard
```

> **Important:** Run the honeypot only in an isolated, controlled environment. Do not expose administrative services or the dashboard to the public Internet.

## Main Features

- SSH honeypot deployment using Cowrie.
- Collection of honeypot events and logs.
- Parsing and normalization of captured events.
- Extraction and analysis of Indicators of Compromise (IOCs), including IP addresses.
- Optional threat-intelligence enrichment using the VirusTotal API.
- Behavioral analysis, including authentication activity and executed commands.
- Risk scoring and severity classification.
- Security alert generation.
- Streamlit dashboard for reviewing events, IOC analysis, risk levels, and alerts.

## Technology Stack

- Python
- Ubuntu Linux / WSL2
- Cowrie SSH Honeypot
- Streamlit
- Pandas
- Plotly
- Requests
- python-dotenv
- VirusTotal API (optional)
- Git and GitHub

## Requirements

- Windows 10/11 with WSL2, or a Linux system.
- Ubuntu installed in WSL2 or available as a standalone Linux environment.
- Python 3.10 or newer.
- Git.
- Internet access for installing Python dependencies and, if configured, querying threat-intelligence services.

The commands below assume that the project is located at:

```text
~/honeypot-threat-intelligence
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/PiotrIT2015/honeypot-threat-intelligence.git
cd honeypot-threat-intelligence
```

If you already have the project directory, enter it instead:

```bash
cd ~/honeypot-threat-intelligence
```

### 2. Create a Python virtual environment

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

When the environment is active, your terminal prompt should normally display `(.venv)`.

### 3. Install dependencies

If the repository contains `requirements.txt`, install the dependencies with:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If `requirements.txt` has not been created yet, install the dashboard dependencies:

```bash
pip install streamlit pandas plotly requests python-dotenv
```

## Configuration

Some integrations require external configuration. Keep credentials and API keys outside the source code.

If the project uses a `.env` file, create it in the repository root:

```bash
touch .env
```

Add the configuration variables required by the relevant integration. For example, if the VirusTotal integration reads an environment variable named `VIRUSTOTAL_API_KEY`:

```dotenv
VIRUSTOTAL_API_KEY=replace_with_your_own_api_key
```

The variable name must match the one expected by the project's VirusTotal integration. Check the relevant source file if the project uses a different name.

Make sure `.env` is listed in `.gitignore`. **Never commit API keys, passwords, private SSH keys, or other secrets to GitHub.**

VirusTotal enrichment is optional. The dashboard and local analysis components may still be useful when external enrichment is not configured. Local addresses such as `127.0.0.1` are loopback addresses and do not represent public attacker IP addresses suitable for public-IP reputation lookups.

## Running the Dashboard

Start the dashboard from the project root, with the virtual environment activated:

```bash
streamlit run dashboard/app.py
```

Streamlit normally prints a local address similar to:

```text
http://localhost:8501
```

Open that address in your web browser.

To stop the dashboard, return to the terminal and press:

```text
Ctrl+C
```

If Streamlit is not found, check that the virtual environment is active and install the dependencies:

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

## Running the Honeypot and Data Pipeline

The dashboard displays data produced by the project's collection, parsing, and analysis components. The exact commands for starting those components depend on the current project configuration and the Cowrie installation.

A typical workflow is:

1. Start Cowrie in the isolated honeypot environment.
2. Confirm that Cowrie is writing event logs.
3. Run the project's log collector and parser.
4. Run the IOC analysis component.
5. Start the Streamlit dashboard to inspect the generated analysis and alerts.

Use the entry-point scripts and configuration files present in this repository for the collector, parser, and analysis engine. Do not assume that the dashboard itself starts Cowrie or processes raw logs automatically.

## Data and Generated Files

The project may generate local data such as:

- Raw honeypot logs.
- Parsed and normalized events.
- Threat-intelligence lookup results or cache files.
- IOC analysis output.
- Security alerts and summary files.

Treat captured logs as potentially sensitive. They can contain attacker-supplied usernames, passwords, commands, IP addresses, and other data. Do not publish raw logs or real credentials in the public repository.

For a public portfolio repository, use synthetic or sanitized sample data.

## Security Notes

- Keep the Streamlit dashboard private. Do not expose port `8501` directly to the public Internet.
- Restrict SSH access to trusted administrator IP addresses where possible.
- Expose only the honeypot service ports that are intentionally required for the experiment.
- Use a cloud firewall and host firewall.
- Do not run the honeypot on a system containing personal or production data.
- Keep API keys in environment variables or a local `.env` file.
- Exclude `.env`, virtual environments, private keys, and sensitive generated data from Git.
- Review staged files before committing:

```bash
git status
git diff --cached --name-only
```

## Development

Activate the virtual environment before running Python tools:

```bash
cd ~/honeypot-threat-intelligence
source .venv/bin/activate
```

To update the dependency list after installing or changing packages:

```bash
pip freeze > requirements.txt
```

Review the resulting file before committing it.

## Project Status

This repository is an educational cybersecurity and portfolio project. Components and integrations may evolve as the project is developed and deployed.

## Disclaimer

This project is intended for educational purposes, defensive security research, and controlled laboratory use only. Deploy and operate the honeypot only on systems and networks that you own or are explicitly authorized to use. You are responsible for complying with applicable laws, service-provider terms, and security requirements.
