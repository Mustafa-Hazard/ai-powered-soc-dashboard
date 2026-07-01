# Phase 1 — Environment Setup

## Goal
Stand up the log-generating "victim" infrastructure and a local Splunk instance to
receive and search logs.

## Architecture Decision

Originally planned to run Splunk directly on an AWS EC2 free-tier instance. Free-tier
instances (1GB RAM) are undersized for Splunk (recommends 8GB+, struggles below 2GB).

**Revised approach:** split the two roles —
- **Victim server** (lightweight, log-generating target) → AWS EC2 free tier
- **Splunk** (the SIEM itself, needs more RAM) → local VirtualBox VM

Logs will be shipped from the EC2 victim server to the local Splunk instance using a
Splunk Universal Forwarder — a lightweight agent, not full Splunk.

This is architecturally closer to how real SOCs operate anyway: a centralized SIEM
ingesting from multiple remote sources, rather than co-locating detection and target.

## Steps Taken

1. **Launched EC2 instance** `victim-server`:
   - AMI: Ubuntu Server 24.04 LTS (free tier eligible)
   - Instance type: `t3.micro` (free tier eligible)
   - Storage: 8 GiB (default)
   - Security group: SSH (port 22) restricted to my IP only
   - Created and downloaded a new key pair (`victim-server-key.pem`) for SSH access

2. **Connected via SSH from WSL (Ubuntu on Windows)**:
   - Copied the `.pem` key into the WSL filesystem (`~/aws-keys/`)
   - Set correct permissions (`chmod 400`)
   - Connected successfully: `ssh -i ~/aws-keys/victim-server-key.pem ubuntu@<public-ip>`

3. **Set up project repository** on GitHub (`ai-powered-soc-dashboard`, public) for
   ongoing documentation and code, with a `.gitignore` to prevent committing any
   credentials, keys, or secrets.

## Still To Do

- [ ] Set up Splunk in a local VirtualBox VM
- [ ] Install and configure Splunk Universal Forwarder on the victim server
- [ ] Confirm logs are flowing from victim server → local Splunk
- [ ] Install a small web app / generate baseline SSH activity for realistic log volume

## Lessons Learned

- Free-tier EC2 RAM (1GB) is not sufficient for running Splunk itself — worth
  confirming a tool's minimum requirements against free-tier limits before assuming
  "free tier" and "runs this tool" are compatible.
- WSL paths for Windows drives other than `C:` are mounted at `/mnt/<letter>/`,
  e.g. `E:\folder` becomes `/mnt/e/folder` in WSL.
- GitHub no longer accepts account passwords for git operations over HTTPS — a
  Personal Access Token (or an authenticated client like VS Code's Git integration)
  is required instead.
