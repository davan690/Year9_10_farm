# Security Audit

Date: 2026-02-13

## Summary

- Audit status: setup complete
- Findings: not yet run in this repo
- Report: security_audit_report.json

## Scope

- Working tree files (excluding common binary formats and very large files)
- Full git history (all blobs)

## Limitations

- Binary formats (images, PDFs, archives, etc.) are not scanned.
- Files over 2 MB are skipped to keep the scan fast.
- If you need deeper binary scanning, use a specialized tool and update the script accordingly.

## Solutions Implemented

1. Automated scan script at scripts/security_audit.py
2. Pre-commit hook at .githooks/pre-commit
3. GitHub Actions workflow at .github/workflows/security_scan.yml

## Required Setup (One-Time)

Enable the repo hook path so the pre-commit scan runs locally:

- git config core.hooksPath .githooks

## GitHub Pages Setup

This repo includes .github/workflows/publish.yml to deploy the site to GitHub Pages using GitHub Actions.

In GitHub:

1. Go to Settings > Pages.
2. Under Build and deployment, select GitHub Actions.
3. Save the settings.

## Recommended Repo Protections (GitHub Settings)

1. Protect the main branch:
   - Require pull request reviews
   - Require status checks to pass (Security Scan, Publish Site)
   - Require signed commits
   - Require linear history

2. Require signed commits locally:
   - git config commit.gpgsign true
   - Use either GPG or SSH signing (GitHub supports both)

## If a Secret Is Found

1. Rotate or revoke the credential immediately.
2. Remove the secret from the repository.
3. Purge it from history using git filter-repo:
   - https://github.com/newren/git-filter-repo
4. Force-push the cleaned history and notify collaborators.

## How To Run The Scan

- Full scan (worktree + history):
  - python scripts/security_audit.py
- Staged-only scan (pre-commit mode):
  - python scripts/security_audit.py --staged --no-history
