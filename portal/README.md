# CyberPatriot Lead Hub

An open source web dashboard for CyberPatriot lead-finder scripts and collaborative report sharing. This directory deploys independently to Vercel from the parent GitHub repository.

## Contents

- `scripts/Leads.ps1` — Windows 11 and Server 2022 lead finder
- `scripts/leads.sh` — Debian lead finder
- `index.html`, `styles.css`, `app.js` — responsive browser interface
- `api/paste.js` — public link-editable paste API backed by **private Vercel Blob storage**

## Hosting

Create a Vercel project connected to this repository, with **Root Directory = portal**, and connect a **private Blob** store. The Blob integration automatically supplies `BLOB_READ_WRITE_TOKEN` to server-side functions. The token must never be put in frontend code or committed to Git.

A pasted report gets a random share link such as `https://example.vercel.app/?paste=<id>`. Anyone with that link can read and edit without signing in. Readers poll for a new revision every 6 seconds; saves explicitly update the shared version. Concurrent edits require a refresh before saving. The files are not indexed or listed publicly, but **a link is not a secret access-control mechanism**.

Public anonymous writes have abuse and quota risks. Before widespread usage, add rate limiting, abuse controls, and optionally authentication. Never paste credentials, SSH keys, tokens, private personal details, or sensitive machine logs.

## Running the scripts

Windows PowerShell (run as Administrator):

```powershell
powershell -ExecutionPolicy Bypass -File .\Leads.ps1 -ReportOnly
```

Debian Linux (run with sudo):

```bash
sudo bash leads.sh --report-only
```

The report-only variants collect findings without applying the scripts' supported repairs. See scripts for scenario-specific authorized-user lists and required services. Review scripts before executing on any noncompetition machine.
