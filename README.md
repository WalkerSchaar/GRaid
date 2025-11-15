**A Google Account Data Exfiltration Tool**
<img width="1215" height="692" alt="Untitled(1)" src="https://github.com/user-attachments/assets/a0299bd1-3b78-49a3-bad8-733c54db50e2" />
## Legal Disclaimer

**FOR AUTHORIZED TESTING ONLY**

This tool is intended for security researchers, penetration testers, and authorized security assessments. Only use on accounts you own or have explicit written permission to test. Unauthorized access is illegal. The authors assume no liability for misuse.

---

## Overview

GRaid demonstrates post-compromise data exfiltration capabilities available to attackers who have obtained valid session tokens through AiTM phishing, token theft, or credential compromise. The tool uses legitimate Google APIs to extract data, showing that 2FA alone does not prevent data exfiltration when session tokens are compromised.

**Supported Services:**
- Gmail (emails, attachments, labels)<img width="1800" height="1200" alt="Untitled" src="https://github.com/user-attachments/assets/608c21c5-1f72-4d8c-bfd9-00e54fa2acbc" />

- Google Drive (files, folders, documents)
- Google Calendar (events, calendars)
- Google Contacts (contact directory)
- Google Photos (media items, albums)
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
git clone https://github.com/yourusername/graid.git
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


## Contributing

Contributions are welcome. Please ensure all contributions maintain the tool's focus on authorized security testing.

---

## License

MIT License - See LICENSE file for details

---

## Author

Created for security research and authorized testing purposes.
