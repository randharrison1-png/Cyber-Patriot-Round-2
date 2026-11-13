# LeadHub — GitHub Pages website

This is the complete static website for the CyberPatriot script library and shared report workspace.

## What's ready

- **Library:** Search and filter five real scripts, inspect source, and download the originals from this repository.
- **Pastes:** Two-panel searchable local report history and editor, import/export text, share URL UI, revision conflicts, 8-second refresh.
- **Design:** Responsive left sidebar and top tabs; flat neutral surfaces, forest green `#247A58`, Inter typography.
- **Local fallback:** When Supabase is not connected, saved drafts stay in **this browser only**. They are not accessible to other people or devices.

## Publish on GitHub Pages

The workflow `.github/workflows/leadhub-pages.yml` deploys the contents of `site/` when files change on `main`. You must enable Pages once from the repository's **Settings → Pages → Build and deployment → Source → GitHub Actions**.

After deployment, the site is normally available at:

`https://randharrison1-png.github.io/Cyber-Patriot-Round-2/`

The app uses relative CSS/JS paths and works under a GitHub Pages repository subpath.

## Activate cross-device editable paste storage with Supabase

1. Create a Supabase project at [supabase.com](https://supabase.com).
2. Open **SQL Editor** in that project and run the full `site/sql/supabase.sql` script.
3. In your Supabase project settings, copy the **Project URL** and **publishable key** (or the older public `anon` key).
4. Edit `site/config.js` and put those two **public** values in `url` and `publishableKey`. Commit the change to `main`. GitHub Pages will redeploy automatically.
5. Test: create a paste, copy its URL, open it in another browser/device, make an edit, save, and reload the first browser. Newer revisions are checked every 8 seconds.

**Never put a service_role key, secret key, JWT signing key, database password, or private credential in `site/config.js` or any public repository file.** Supabase's public key is meant to be used in browsers; authorization depends on restrictive database access.

### How paste privacy works

Saved report slugs are cryptographically random. Paste reading and updating happen only through narrowly defined database RPC functions. The underlying table has row-level security enabled and direct anonymous access revoked. No global public paste listing is offered; **recent reports are a list of links kept locally in each browser**. Someone who obtains a shared report URL can read and edit the report. Do not upload sensitive audit output, tokens, passwords, personal data, SSH keys or private infrastructure details.

**Limitations:** An anonymous write service can be abused. The SQL limits content size and checks revisions, but does not provide CAPTCHA, account-based moderation, or per-IP rate limits. For widespread public use, introduce anti-spam and abuse protection before advertising the service.

## Script inventory

| File | Platform | Role |
|---|---|---|
| `portal/scripts/Leads.ps1` | Windows 11 and Server 2022 | Lead finder |
| `portal/scripts/leads.sh` | Debian 12 | Lead finder |
| `Harden-Win11.ps1` | Windows 11 | Hardening |
| `Harden-Server2022.ps1` | Windows Server 2022 | Hardening |
| `harden-debian12.sh` | Debian 12 | Hardening |

Do not run any script without reviewing its operations, scenario-specific user lists, critical services, and your competition rules. The lead-finder scripts include report-only options.
