<img width="607" height="346" alt="Untitled(1)" src="https://github.com/user-attachments/assets/a0299bd1-3b78-49a3-bad8-733c54db50e2" />

## Legal Disclaimer

**FOR AUTHORIZED TESTING ONLY**

This tool is intended for security researchers, penetration testers, and authorized security assessments. Only use on accounts you own or have explicit written permission to test. Unauthorized access is illegal. The authors assume no liability for misuse.

---

## Overview

GRaid demonstrates post-compromise data exfiltration capabilities available to attackers who have obtained valid session tokens through AiTM phishing, token theft, or credential compromise. The tool uses legitimate Google APIs to extract data.

**Supported Services:**
- Gmail
- Google Drive
- Google Calendar
- Google Contacts
- Google Tasks
- Google Keep (Workspace)
- YouTube (subscriptions, playlists, likes)
- Google Password Manager (direct link access)

**Workspace Features:**
- Google Groups enumeration
- Shared Drives discovery
- Admin directory access (complete user directory, org structure)

---

## Installation

**Requirements:**
- Python 3.7+
- Google Cloud Project with OAuth 2.0 credentials

**Setup:**

```bash
# Clone repository
git clone https://github.com/WalkerSchaar/graid.git
cd graid

# Install dependencies
pip install google-auth-oauthlib google-auth-httplib2 google-api-python-client requests
```

**Google Cloud Configuration:**

1. Create a project at https://console.cloud.google.com/
2. Enable required APIs: Gmail, Drive, Calendar, People, Photos Library, Tasks, YouTube Data, Admin SDK, Cloud Identity
3. Create OAuth 2.0 credentials (Desktop app)
4. Download credentials as `credentials.json`

---

## Usage

**Interactive Mode (Recommended):**
```bash
python GRaid.py --interactive
```

**Common Commands:**
```bash
# Reconnaissance only
python GRaid.py --probe

# Auto-exfiltrate active services that contain data
python GRaid.py --active-only

# Target specific services
python GRaid.py --gmail --drive --contacts

# Workspace enumeration
python GRaid.py --workspace

# Admin features (requires admin account)
python GRaid.py --workspace-admin

# Full exfiltration with no limits
python GRaid.py --all --no-limits
```

**Limit Controls:**
```bash
# Adjust download limits
python GRaid.py --gmail --limit-emails 500

# Custom output directory
python GRaid.py --active-only --output /path/to/output
```

---

## Output Structure

Data is saved locally to `exfiltrated_data/` (configurable) with organized subdirectories:

```
exfiltrated_data/
├── gmail/
├── drive/
├── calendar/
├── contacts/
├── photos/
├── tasks/
├── youtube/
├── workspace_groups/
├── workspace_shared_drives/
└── workspace_admin/
```


---

## License

MIT License - See LICENSE file for details

---
