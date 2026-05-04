import { useState, useMemo } from 'react'
import { CheckCircle2, XCircle, Circle, Clock, ChevronDown, ChevronRight, RotateCcw, Smartphone, Globe } from 'lucide-react'
import { clsx } from 'clsx'

// ────────────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────────────

type Status = 'not_started' | 'in_progress' | 'pass' | 'fail'
type MobileOs = 'ios' | 'android'

interface TestCase {
  id: string
  mavsId: string
  title: string
  defaultStatus: Status
}

interface Category {
  category: string
  tests: TestCase[]
}

// ────────────────────────────────────────────────────────────────────────────
// iOS MASVS checklist
// ────────────────────────────────────────────────────────────────────────────

const IOS_CHECKLIST: Category[] = [
  {
    category: 'MASVS-STORAGE',
    tests: [
      { id: 'IOS-S1-01', mavsId: 'MASVS-STORAGE-1', title: 'Testing Local Data Storage', defaultStatus: 'not_started' },
      { id: 'IOS-S2-01', mavsId: 'MASVS-STORAGE-2', title: 'Checking Logs for Sensitive Data', defaultStatus: 'not_started' },
      { id: 'IOS-S2-02', mavsId: 'MASVS-STORAGE-2', title: 'Testing Memory for Sensitive Data', defaultStatus: 'not_started' },
      { id: 'IOS-S2-03', mavsId: 'MASVS-STORAGE-2', title: 'Testing Backups for Sensitive Data', defaultStatus: 'not_started' },
      { id: 'IOS-S2-04', mavsId: 'MASVS-STORAGE-2', title: 'Finding Sensitive Data in the Keyboard Cache', defaultStatus: 'not_started' },
      { id: 'IOS-S2-05', mavsId: 'MASVS-STORAGE-2', title: 'Determining Whether Sensitive Data Is Shared with Third Parties', defaultStatus: 'not_started' },
    ],
  },
  {
    category: 'MASVS-CRYPTO',
    tests: [
      { id: 'IOS-C1-01', mavsId: 'MASVS-CRYPTO-1', title: 'Verifying the Configuration of Cryptographic Standard Algorithms', defaultStatus: 'not_started' },
      { id: 'IOS-C1-02', mavsId: 'MASVS-CRYPTO-1', title: 'Testing Random Number Generation', defaultStatus: 'not_started' },
      { id: 'IOS-C2-01', mavsId: 'MASVS-CRYPTO-2', title: 'Testing Key Management', defaultStatus: 'not_started' },
    ],
  },
  {
    category: 'MASVS-AUTH',
    tests: [
      { id: 'IOS-A2-01', mavsId: 'MASVS-AUTH-2', title: 'Testing Local Authentication', defaultStatus: 'not_started' },
    ],
  },
  {
    category: 'MASVS-NETWORK',
    tests: [
      { id: 'IOS-N1-01', mavsId: 'MASVS-NETWORK-1', title: 'Testing the TLS Settings', defaultStatus: 'not_started' },
      { id: 'IOS-N1-02', mavsId: 'MASVS-NETWORK-1', title: 'Testing Endpoint Identity Verification', defaultStatus: 'not_started' },
      { id: 'IOS-N1-03', mavsId: 'MASVS-NETWORK-1', title: 'Testing Data Encryption on the Network', defaultStatus: 'not_started' },
      { id: 'IOS-N2-01', mavsId: 'MASVS-NETWORK-2', title: 'Testing Custom Certificate Stores and Certificate Pinning', defaultStatus: 'not_started' },
    ],
  },
  {
    category: 'MASVS-PLATFORM',
    tests: [
      { id: 'IOS-P1-01', mavsId: 'MASVS-PLATFORM-1', title: 'Testing App Extensions', defaultStatus: 'not_started' },
      { id: 'IOS-P1-02', mavsId: 'MASVS-PLATFORM-1', title: 'Testing Custom URL Schemes', defaultStatus: 'not_started' },
      { id: 'IOS-P1-03', mavsId: 'MASVS-PLATFORM-1', title: 'Testing App Permissions', defaultStatus: 'not_started' },
      { id: 'IOS-P1-04', mavsId: 'MASVS-PLATFORM-1', title: 'Determining Whether Sensitive Data Is Exposed via IPC Mechanisms', defaultStatus: 'not_started' },
      { id: 'IOS-P1-05', mavsId: 'MASVS-PLATFORM-1', title: 'Testing UIPasteboard', defaultStatus: 'not_started' },
      { id: 'IOS-P1-06', mavsId: 'MASVS-PLATFORM-1', title: 'Testing for Sensitive Functionality Exposure Through IPC', defaultStatus: 'not_started' },
      { id: 'IOS-P1-07', mavsId: 'MASVS-PLATFORM-1', title: 'Testing UIActivity Sharing', defaultStatus: 'not_started' },
      { id: 'IOS-P1-08', mavsId: 'MASVS-PLATFORM-1', title: 'Testing Universal Links', defaultStatus: 'not_started' },
      { id: 'IOS-P2-01', mavsId: 'MASVS-PLATFORM-2', title: 'Testing WebView Protocol Handlers', defaultStatus: 'not_started' },
      { id: 'IOS-P2-02', mavsId: 'MASVS-PLATFORM-2', title: 'Testing iOS WebViews', defaultStatus: 'not_started' },
      { id: 'IOS-P2-03', mavsId: 'MASVS-PLATFORM-2', title: 'Determining Whether Native Methods Are Exposed Through WebViews', defaultStatus: 'not_started' },
      { id: 'IOS-P3-01', mavsId: 'MASVS-PLATFORM-3', title: 'Checking for Sensitive Data Disclosed Through the User Interface', defaultStatus: 'not_started' },
      { id: 'IOS-P3-02', mavsId: 'MASVS-PLATFORM-3', title: 'Testing Auto-Generated Screenshots for Sensitive Information', defaultStatus: 'not_started' },
    ],
  },
  {
    category: 'MASVS-CODE',
    tests: [
      { id: 'IOS-CO2-01', mavsId: 'MASVS-CODE-2', title: 'Testing Enforced Updating', defaultStatus: 'not_started' },
      { id: 'IOS-CO3-01', mavsId: 'MASVS-CODE-3', title: 'Checking for Weaknesses in Third Party Libraries', defaultStatus: 'not_started' },
      { id: 'IOS-CO4-01', mavsId: 'MASVS-CODE-4', title: 'Testing Object Persistence', defaultStatus: 'not_started' },
      { id: 'IOS-CO4-02', mavsId: 'MASVS-CODE-4', title: 'Memory Corruption Bugs', defaultStatus: 'not_started' },
      { id: 'IOS-CO4-03', mavsId: 'MASVS-CODE-4', title: 'Make Sure That Free Security Features Are Activated', defaultStatus: 'not_started' },
    ],
  },
  {
    category: 'MASVS-RESILIENCE',
    tests: [
      { id: 'IOS-R1-01', mavsId: 'MASVS-RESILIENCE-1', title: 'Testing Jailbreak Detection', defaultStatus: 'not_started' },
      { id: 'IOS-R1-02', mavsId: 'MASVS-RESILIENCE-1', title: 'Testing Emulator Detection', defaultStatus: 'not_started' },
      { id: 'IOS-R2-01', mavsId: 'MASVS-RESILIENCE-2', title: 'Testing File Integrity Checks', defaultStatus: 'not_started' },
      { id: 'IOS-R2-02', mavsId: 'MASVS-RESILIENCE-2', title: 'Making Sure that the App Is Properly Signed', defaultStatus: 'not_started' },
      { id: 'IOS-R3-01', mavsId: 'MASVS-RESILIENCE-3', title: 'Testing for Debugging Code and Verbose Error Logging', defaultStatus: 'not_started' },
      { id: 'IOS-R3-02', mavsId: 'MASVS-RESILIENCE-3', title: 'Testing Obfuscation', defaultStatus: 'not_started' },
      { id: 'IOS-R3-03', mavsId: 'MASVS-RESILIENCE-3', title: 'Testing for Debugging Symbols', defaultStatus: 'not_started' },
      { id: 'IOS-R4-01', mavsId: 'MASVS-RESILIENCE-4', title: 'Testing Anti-Debugging Detection', defaultStatus: 'not_started' },
      { id: 'IOS-R4-02', mavsId: 'MASVS-RESILIENCE-4', title: 'Testing whether the App is Debuggable', defaultStatus: 'not_started' },
      { id: 'IOS-R4-03', mavsId: 'MASVS-RESILIENCE-4', title: 'Testing Reverse Engineering Tools Detection', defaultStatus: 'not_started' },
    ],
  },
]

// ────────────────────────────────────────────────────────────────────────────
// Android MASVS checklist
// ────────────────────────────────────────────────────────────────────────────

const ANDROID_CHECKLIST: Category[] = [
  {
    category: 'MASVS-STORAGE',
    tests: [
      { id: 'AND-S1-01', mavsId: 'MASVS-STORAGE-1', title: 'Testing Local Storage for Sensitive Data', defaultStatus: 'not_started' },
      { id: 'AND-S1-02', mavsId: 'MASVS-STORAGE-1', title: 'Testing the Device-Access-Security Policy', defaultStatus: 'not_started' },
      { id: 'AND-S2-01', mavsId: 'MASVS-STORAGE-2', title: 'Determining Whether Sensitive Data Is Shared with Third Parties via Embedded Services', defaultStatus: 'not_started' },
      { id: 'AND-S2-02', mavsId: 'MASVS-STORAGE-2', title: 'Determining Whether Sensitive Data Is Shared with Third Parties via Notifications', defaultStatus: 'not_started' },
      { id: 'AND-S2-03', mavsId: 'MASVS-STORAGE-2', title: 'Testing Backups for Sensitive Data', defaultStatus: 'not_started' },
      { id: 'AND-S2-04', mavsId: 'MASVS-STORAGE-2', title: 'Testing Memory for Sensitive Data', defaultStatus: 'not_started' },
      { id: 'AND-S2-05', mavsId: 'MASVS-STORAGE-2', title: 'Determining Whether the Keyboard Cache Is Disabled for Text Input Fields', defaultStatus: 'not_started' },
      { id: 'AND-S2-06', mavsId: 'MASVS-STORAGE-2', title: 'Testing Logs for Sensitive Data', defaultStatus: 'not_started' },
    ],
  },
  {
    category: 'MASVS-CRYPTO',
    tests: [
      { id: 'AND-C1-01', mavsId: 'MASVS-CRYPTO-1', title: 'Testing Symmetric Cryptography', defaultStatus: 'not_started' },
      { id: 'AND-C1-02', mavsId: 'MASVS-CRYPTO-1', title: 'Testing the Configuration of Cryptographic Standard Algorithms', defaultStatus: 'not_started' },
      { id: 'AND-C1-03', mavsId: 'MASVS-CRYPTO-1', title: 'Testing Random Number Generation', defaultStatus: 'not_started' },
      { id: 'AND-C2-01', mavsId: 'MASVS-CRYPTO-2', title: 'Testing the Purposes of Keys', defaultStatus: 'not_started' },
    ],
  },
  {
    category: 'MASVS-AUTH',
    tests: [
      { id: 'AND-A2-01', mavsId: 'MASVS-AUTH-2', title: 'Testing Biometric Authentication', defaultStatus: 'not_started' },
      { id: 'AND-A2-02', mavsId: 'MASVS-AUTH-2', title: 'Testing Confirm Credentials', defaultStatus: 'not_started' },
    ],
  },
  {
    category: 'MASVS-NETWORK',
    tests: [
      { id: 'AND-N1-01', mavsId: 'MASVS-NETWORK-1', title: 'Testing Endpoint Identity Verification', defaultStatus: 'not_started' },
      { id: 'AND-N1-02', mavsId: 'MASVS-NETWORK-1', title: 'Testing the Security Provider', defaultStatus: 'not_started' },
      { id: 'AND-N1-03', mavsId: 'MASVS-NETWORK-1', title: 'Testing Data Encryption on the Network', defaultStatus: 'not_started' },
      { id: 'AND-N1-04', mavsId: 'MASVS-NETWORK-1', title: 'Testing the TLS Settings', defaultStatus: 'not_started' },
      { id: 'AND-N2-01', mavsId: 'MASVS-NETWORK-2', title: 'Testing Custom Certificate Stores and Certificate Pinning', defaultStatus: 'not_started' },
    ],
  },
  {
    category: 'MASVS-PLATFORM',
    tests: [
      { id: 'AND-P1-01', mavsId: 'MASVS-PLATFORM-1', title: 'Testing for App Permissions', defaultStatus: 'not_started' },
      { id: 'AND-P1-02', mavsId: 'MASVS-PLATFORM-1', title: 'Testing for Vulnerable Implementation of PendingIntent', defaultStatus: 'not_started' },
      { id: 'AND-P1-03', mavsId: 'MASVS-PLATFORM-1', title: 'Testing for Sensitive Functionality Exposure Through IPC', defaultStatus: 'not_started' },
      { id: 'AND-P1-04', mavsId: 'MASVS-PLATFORM-1', title: 'Determining Whether Sensitive Stored Data Has Been Exposed via IPC Mechanisms', defaultStatus: 'not_started' },
      { id: 'AND-P1-05', mavsId: 'MASVS-PLATFORM-1', title: 'Testing Deep Links', defaultStatus: 'not_started' },
      { id: 'AND-P2-01', mavsId: 'MASVS-PLATFORM-2', title: 'Testing WebView Protocol Handlers', defaultStatus: 'not_started' },
      { id: 'AND-P2-02', mavsId: 'MASVS-PLATFORM-2', title: 'Testing WebViews Cleanup', defaultStatus: 'not_started' },
      { id: 'AND-P2-03', mavsId: 'MASVS-PLATFORM-2', title: 'Testing JavaScript Execution in WebViews', defaultStatus: 'not_started' },
      { id: 'AND-P2-04', mavsId: 'MASVS-PLATFORM-2', title: 'Testing for Java Objects Exposed Through WebViews', defaultStatus: 'not_started' },
      { id: 'AND-P3-01', mavsId: 'MASVS-PLATFORM-3', title: 'Testing for Overlay Attacks', defaultStatus: 'not_started' },
      { id: 'AND-P3-02', mavsId: 'MASVS-PLATFORM-3', title: 'Checking for Sensitive Data Disclosure Through the User Interface', defaultStatus: 'not_started' },
      { id: 'AND-P3-03', mavsId: 'MASVS-PLATFORM-3', title: 'Finding Sensitive Information in Auto-Generated Screenshots', defaultStatus: 'not_started' },
    ],
  },
  {
    category: 'MASVS-CODE',
    tests: [
      { id: 'AND-CO2-01', mavsId: 'MASVS-CODE-2', title: 'Testing Enforced Updating', defaultStatus: 'not_started' },
      { id: 'AND-CO3-01', mavsId: 'MASVS-CODE-3', title: 'Checking for Weaknesses in Third Party Libraries', defaultStatus: 'not_started' },
      { id: 'AND-CO4-01', mavsId: 'MASVS-CODE-4', title: 'Make Sure That Free Security Features Are Activated', defaultStatus: 'not_started' },
      { id: 'AND-CO4-02', mavsId: 'MASVS-CODE-4', title: 'Testing for Injection Flaws', defaultStatus: 'not_started' },
      { id: 'AND-CO4-03', mavsId: 'MASVS-CODE-4', title: 'Testing Local Storage for Input Validation', defaultStatus: 'not_started' },
      { id: 'AND-CO4-04', mavsId: 'MASVS-CODE-4', title: 'Memory Corruption Bugs', defaultStatus: 'not_started' },
      { id: 'AND-CO4-05', mavsId: 'MASVS-CODE-4', title: 'Testing Object Persistence', defaultStatus: 'not_started' },
      { id: 'AND-CO4-06', mavsId: 'MASVS-CODE-4', title: 'Testing Implicit Intents', defaultStatus: 'not_started' },
      { id: 'AND-CO4-07', mavsId: 'MASVS-CODE-4', title: 'Testing for URL Loading in WebViews', defaultStatus: 'not_started' },
    ],
  },
  {
    category: 'MASVS-RESILIENCE',
    tests: [
      { id: 'AND-R1-01', mavsId: 'MASVS-RESILIENCE-1', title: 'Testing Root Detection', defaultStatus: 'not_started' },
      { id: 'AND-R1-02', mavsId: 'MASVS-RESILIENCE-1', title: 'Testing Emulator Detection', defaultStatus: 'not_started' },
      { id: 'AND-R2-01', mavsId: 'MASVS-RESILIENCE-2', title: 'Testing File Integrity Checks', defaultStatus: 'not_started' },
      { id: 'AND-R2-02', mavsId: 'MASVS-RESILIENCE-2', title: 'Testing Runtime Integrity Checks', defaultStatus: 'not_started' },
      { id: 'AND-R2-03', mavsId: 'MASVS-RESILIENCE-2', title: 'Making Sure that the App is Properly Signed', defaultStatus: 'not_started' },
      { id: 'AND-R3-01', mavsId: 'MASVS-RESILIENCE-3', title: 'Testing for Debugging Symbols', defaultStatus: 'not_started' },
      { id: 'AND-R3-02', mavsId: 'MASVS-RESILIENCE-3', title: 'Testing for Debugging Code and Verbose Error Logging', defaultStatus: 'not_started' },
      { id: 'AND-R3-03', mavsId: 'MASVS-RESILIENCE-3', title: 'Testing Obfuscation', defaultStatus: 'not_started' },
      { id: 'AND-R4-01', mavsId: 'MASVS-RESILIENCE-4', title: 'Testing whether the App is Debuggable', defaultStatus: 'not_started' },
      { id: 'AND-R4-02', mavsId: 'MASVS-RESILIENCE-4', title: 'Testing Reverse Engineering Tools Detection', defaultStatus: 'not_started' },
      { id: 'AND-R4-03', mavsId: 'MASVS-RESILIENCE-4', title: 'Testing Anti-Debugging Detection', defaultStatus: 'not_started' },
    ],
  },
]

// ────────────────────────────────────────────────────────────────────────────
// Web OWASP WSTG checklist
// ────────────────────────────────────────────────────────────────────────────

const WEB_CHECKLIST: Category[] = [
  {
    category: '4.1 Information Gathering',
    tests: [
      { id: 'WSTG-INFO-01', mavsId: '', title: 'Conduct Search Engine Discovery Reconnaissance for Information Leakage', defaultStatus: 'not_started' },
      { id: 'WSTG-INFO-02', mavsId: '', title: 'Fingerprint Web Server', defaultStatus: 'not_started' },
      { id: 'WSTG-INFO-03', mavsId: '', title: 'Review Webserver Metafiles for Information Leakage', defaultStatus: 'not_started' },
      { id: 'WSTG-INFO-04', mavsId: '', title: 'Enumerate Applications on Webserver', defaultStatus: 'not_started' },
      { id: 'WSTG-INFO-05', mavsId: '', title: 'Review Webpage Content for Information Leakage', defaultStatus: 'not_started' },
      { id: 'WSTG-INFO-06', mavsId: '', title: 'Identify Application Entry Points', defaultStatus: 'not_started' },
      { id: 'WSTG-INFO-07', mavsId: '', title: 'Map Execution Paths Through Application', defaultStatus: 'not_started' },
      { id: 'WSTG-INFO-08', mavsId: '', title: 'Fingerprint Web Application Framework', defaultStatus: 'not_started' },
      { id: 'WSTG-INFO-09', mavsId: '', title: 'Fingerprint Web Application', defaultStatus: 'not_started' },
      { id: 'WSTG-INFO-10', mavsId: '', title: 'Map Application Architecture', defaultStatus: 'not_started' },
    ],
  },
  {
    category: '4.2 Configuration and Deployment Management',
    tests: [
      { id: 'WSTG-CONF-01', mavsId: '', title: 'Test Network Infrastructure Configuration', defaultStatus: 'not_started' },
      { id: 'WSTG-CONF-02', mavsId: '', title: 'Test Application Platform Configuration', defaultStatus: 'not_started' },
      { id: 'WSTG-CONF-03', mavsId: '', title: 'Test File Extensions Handling for Sensitive Information', defaultStatus: 'not_started' },
      { id: 'WSTG-CONF-04', mavsId: '', title: 'Review Old Backup and Unreferenced Files for Sensitive Information', defaultStatus: 'not_started' },
      { id: 'WSTG-CONF-05', mavsId: '', title: 'Enumerate Infrastructure and Application Admin Interfaces', defaultStatus: 'not_started' },
      { id: 'WSTG-CONF-06', mavsId: '', title: 'Test HTTP Methods', defaultStatus: 'not_started' },
      { id: 'WSTG-CONF-07', mavsId: '', title: 'Test HTTP Strict Transport Security', defaultStatus: 'not_started' },
      { id: 'WSTG-CONF-08', mavsId: '', title: 'Test RIA Cross Domain Policy', defaultStatus: 'not_started' },
      { id: 'WSTG-CONF-09', mavsId: '', title: 'Test File Permission', defaultStatus: 'not_started' },
      { id: 'WSTG-CONF-10', mavsId: '', title: 'Test for Subdomain Takeover', defaultStatus: 'not_started' },
      { id: 'WSTG-CONF-11', mavsId: '', title: 'Test Cloud Storage', defaultStatus: 'not_started' },
    ],
  },
  {
    category: '4.3 Identity Management',
    tests: [
      { id: 'WSTG-IDNT-01', mavsId: '', title: 'Test Role Definitions', defaultStatus: 'not_started' },
      { id: 'WSTG-IDNT-02', mavsId: '', title: 'Test User Registration Process', defaultStatus: 'not_started' },
      { id: 'WSTG-IDNT-03', mavsId: '', title: 'Test Account Provisioning Process', defaultStatus: 'not_started' },
      { id: 'WSTG-IDNT-04', mavsId: '', title: 'Testing for Account Enumeration and Guessable User Account', defaultStatus: 'not_started' },
      { id: 'WSTG-IDNT-05', mavsId: '', title: 'Testing for Weak or Unenforced Username Policy', defaultStatus: 'not_started' },
    ],
  },
  {
    category: '4.4 Authentication Testing',
    tests: [
      { id: 'WSTG-ATHN-01', mavsId: '', title: 'Testing for Credentials Transported over an Encrypted Channel', defaultStatus: 'not_started' },
      { id: 'WSTG-ATHN-02', mavsId: '', title: 'Testing for Default Credentials', defaultStatus: 'not_started' },
      { id: 'WSTG-ATHN-03', mavsId: '', title: 'Testing for Weak Lock Out Mechanism', defaultStatus: 'not_started' },
      { id: 'WSTG-ATHN-04', mavsId: '', title: 'Testing for Bypassing Authentication Schema', defaultStatus: 'not_started' },
      { id: 'WSTG-ATHN-05', mavsId: '', title: 'Testing for Vulnerable Remember Password', defaultStatus: 'not_started' },
      { id: 'WSTG-ATHN-06', mavsId: '', title: 'Testing for Browser Cache Weaknesses', defaultStatus: 'not_started' },
      { id: 'WSTG-ATHN-07', mavsId: '', title: 'Testing for Weak Password Policy', defaultStatus: 'not_started' },
      { id: 'WSTG-ATHN-08', mavsId: '', title: 'Testing for Weak Security Question Answer', defaultStatus: 'not_started' },
      { id: 'WSTG-ATHN-09', mavsId: '', title: 'Testing for Weak Password Change or Reset Functionalities', defaultStatus: 'not_started' },
      { id: 'WSTG-ATHN-10', mavsId: '', title: 'Testing for Weaker Authentication in Alternative Channel', defaultStatus: 'not_started' },
    ],
  },
  {
    category: '4.5 Authorization Testing',
    tests: [
      { id: 'WSTG-ATHZ-01', mavsId: '', title: 'Testing Directory Traversal File Include', defaultStatus: 'not_started' },
      { id: 'WSTG-ATHZ-02', mavsId: '', title: 'Testing for Bypassing Authorization Schema', defaultStatus: 'not_started' },
      { id: 'WSTG-ATHZ-03', mavsId: '', title: 'Testing for Privilege Escalation', defaultStatus: 'not_started' },
      { id: 'WSTG-ATHZ-04', mavsId: '', title: 'Testing for Insecure Direct Object References', defaultStatus: 'not_started' },
    ],
  },
  {
    category: '4.6 Session Management',
    tests: [
      { id: 'WSTG-SESS-01', mavsId: '', title: 'Testing for Session Management Schema', defaultStatus: 'not_started' },
      { id: 'WSTG-SESS-02', mavsId: '', title: 'Testing for Cookies Attributes', defaultStatus: 'not_started' },
      { id: 'WSTG-SESS-03', mavsId: '', title: 'Testing for Session Fixation', defaultStatus: 'not_started' },
      { id: 'WSTG-SESS-04', mavsId: '', title: 'Testing for Exposed Session Variables', defaultStatus: 'not_started' },
      { id: 'WSTG-SESS-05', mavsId: '', title: 'Testing for Cross Site Request Forgery', defaultStatus: 'not_started' },
      { id: 'WSTG-SESS-06', mavsId: '', title: 'Testing for Logout Functionality', defaultStatus: 'not_started' },
      { id: 'WSTG-SESS-07', mavsId: '', title: 'Testing Session Timeout', defaultStatus: 'not_started' },
      { id: 'WSTG-SESS-08', mavsId: '', title: 'Testing for Session Puzzling', defaultStatus: 'not_started' },
      { id: 'WSTG-SESS-09', mavsId: '', title: 'Testing for Session Hijacking', defaultStatus: 'not_started' },
    ],
  },
  {
    category: '4.7 Input Validation',
    tests: [
      { id: 'WSTG-INPV-01', mavsId: '', title: 'Testing for Reflected Cross Site Scripting', defaultStatus: 'not_started' },
      { id: 'WSTG-INPV-02', mavsId: '', title: 'Testing for Stored Cross Site Scripting', defaultStatus: 'not_started' },
      { id: 'WSTG-INPV-03', mavsId: '', title: 'Testing for HTTP Verb Tampering', defaultStatus: 'not_started' },
      { id: 'WSTG-INPV-04', mavsId: '', title: 'Testing for HTTP Parameter Pollution', defaultStatus: 'not_started' },
      { id: 'WSTG-INPV-05', mavsId: '', title: 'Testing for SQL Injection', defaultStatus: 'not_started' },
      { id: 'WSTG-INPV-06', mavsId: '', title: 'Testing for LDAP Injection', defaultStatus: 'not_started' },
      { id: 'WSTG-INPV-07', mavsId: '', title: 'Testing for XML Injection', defaultStatus: 'not_started' },
      { id: 'WSTG-INPV-08', mavsId: '', title: 'Testing for SSI Injection', defaultStatus: 'not_started' },
      { id: 'WSTG-INPV-09', mavsId: '', title: 'Testing for XPath Injection', defaultStatus: 'not_started' },
      { id: 'WSTG-INPV-10', mavsId: '', title: 'Testing for IMAP SMTP Injection', defaultStatus: 'not_started' },
      { id: 'WSTG-INPV-11', mavsId: '', title: 'Testing for Code Injection', defaultStatus: 'not_started' },
      { id: 'WSTG-INPV-12', mavsId: '', title: 'Testing for Command Injection', defaultStatus: 'not_started' },
      { id: 'WSTG-INPV-13', mavsId: '', title: 'Testing for Format String Injection', defaultStatus: 'not_started' },
      { id: 'WSTG-INPV-14', mavsId: '', title: 'Testing for Incubated Vulnerability', defaultStatus: 'not_started' },
      { id: 'WSTG-INPV-15', mavsId: '', title: 'Testing for HTTP Splitting Smuggling', defaultStatus: 'not_started' },
      { id: 'WSTG-INPV-16', mavsId: '', title: 'Testing for HTTP Incoming Requests', defaultStatus: 'not_started' },
      { id: 'WSTG-INPV-17', mavsId: '', title: 'Testing for Host Header Injection', defaultStatus: 'not_started' },
      { id: 'WSTG-INPV-18', mavsId: '', title: 'Testing for Server-side Template Injection', defaultStatus: 'not_started' },
      { id: 'WSTG-INPV-19', mavsId: '', title: 'Testing for Server-Side Request Forgery', defaultStatus: 'not_started' },
    ],
  },
  {
    category: '4.8 Error Handling',
    tests: [
      { id: 'WSTG-ERRH-01', mavsId: '', title: 'Testing for Improper Error Handling', defaultStatus: 'not_started' },
      { id: 'WSTG-ERRH-02', mavsId: '', title: 'Testing for Stack Traces', defaultStatus: 'not_started' },
    ],
  },
  {
    category: '4.9 Weak Cryptography',
    tests: [
      { id: 'WSTG-CRYP-01', mavsId: '', title: 'Testing for Weak Transport Layer Security', defaultStatus: 'not_started' },
      { id: 'WSTG-CRYP-02', mavsId: '', title: 'Testing for Padding Oracle', defaultStatus: 'not_started' },
      { id: 'WSTG-CRYP-03', mavsId: '', title: 'Testing for Sensitive Information Sent via Unencrypted Channels', defaultStatus: 'not_started' },
      { id: 'WSTG-CRYP-04', mavsId: '', title: 'Testing for Weak Encryption', defaultStatus: 'not_started' },
    ],
  },
  {
    category: '4.10 Business Logic',
    tests: [
      { id: 'WSTG-BUSL-01', mavsId: '', title: 'Test Business Logic Data Validation', defaultStatus: 'not_started' },
      { id: 'WSTG-BUSL-02', mavsId: '', title: 'Test Ability to Forge Requests', defaultStatus: 'not_started' },
      { id: 'WSTG-BUSL-03', mavsId: '', title: 'Test Integrity Checks', defaultStatus: 'not_started' },
      { id: 'WSTG-BUSL-04', mavsId: '', title: 'Test for Process Timing', defaultStatus: 'not_started' },
      { id: 'WSTG-BUSL-05', mavsId: '', title: 'Test Number of Times a Function Can Be Used Limits', defaultStatus: 'not_started' },
      { id: 'WSTG-BUSL-06', mavsId: '', title: 'Testing for the Circumvention of Work Flows', defaultStatus: 'not_started' },
      { id: 'WSTG-BUSL-07', mavsId: '', title: 'Test Defenses Against Application Misuse', defaultStatus: 'not_started' },
      { id: 'WSTG-BUSL-08', mavsId: '', title: 'Test Upload of Unexpected File Types', defaultStatus: 'not_started' },
      { id: 'WSTG-BUSL-09', mavsId: '', title: 'Test Upload of Malicious Files', defaultStatus: 'not_started' },
    ],
  },
  {
    category: '4.11 Client-Side Testing',
    tests: [
      { id: 'WSTG-CLNT-01', mavsId: '', title: 'Testing for DOM-Based Cross Site Scripting', defaultStatus: 'not_started' },
      { id: 'WSTG-CLNT-02', mavsId: '', title: 'Testing for JavaScript Execution', defaultStatus: 'not_started' },
      { id: 'WSTG-CLNT-03', mavsId: '', title: 'Testing for HTML Injection', defaultStatus: 'not_started' },
      { id: 'WSTG-CLNT-04', mavsId: '', title: 'Testing for Client-side URL Redirect', defaultStatus: 'not_started' },
      { id: 'WSTG-CLNT-05', mavsId: '', title: 'Testing for CSS Injection', defaultStatus: 'not_started' },
      { id: 'WSTG-CLNT-06', mavsId: '', title: 'Testing for Client-side Resource Manipulation', defaultStatus: 'not_started' },
      { id: 'WSTG-CLNT-07', mavsId: '', title: 'Testing Cross Origin Resource Sharing', defaultStatus: 'not_started' },
      { id: 'WSTG-CLNT-08', mavsId: '', title: 'Testing for Cross Site Flashing', defaultStatus: 'not_started' },
      { id: 'WSTG-CLNT-09', mavsId: '', title: 'Testing for Clickjacking', defaultStatus: 'not_started' },
      { id: 'WSTG-CLNT-10', mavsId: '', title: 'Testing WebSockets', defaultStatus: 'not_started' },
      { id: 'WSTG-CLNT-11', mavsId: '', title: 'Testing Web Messaging', defaultStatus: 'not_started' },
      { id: 'WSTG-CLNT-12', mavsId: '', title: 'Testing Browser Storage', defaultStatus: 'not_started' },
      { id: 'WSTG-CLNT-13', mavsId: '', title: 'Testing for Cross Site Script Inclusion', defaultStatus: 'not_started' },
    ],
  },
  {
    category: '4.12 API Testing',
    tests: [
      { id: 'WSTG-APIT-01', mavsId: '', title: 'Testing GraphQL', defaultStatus: 'not_started' },
    ],
  },
]

// ────────────────────────────────────────────────────────────────────────────
// localStorage persistence — separate keys per context
// ────────────────────────────────────────────────────────────────────────────

function lsKey(tab: 'mobile' | 'web', os?: MobileOs) {
  return `blujay_checklist_v1_${tab}${os ? `_${os}` : ''}`
}

function loadState(tab: 'mobile' | 'web', os?: MobileOs): Record<string, Status> {
  try {
    const raw = localStorage.getItem(lsKey(tab, os))
    return raw ? JSON.parse(raw) : {}
  } catch {
    return {}
  }
}

function saveState(state: Record<string, Status>, tab: 'mobile' | 'web', os?: MobileOs) {
  try {
    localStorage.setItem(lsKey(tab, os), JSON.stringify(state))
  } catch { /* quota exceeded */ }
}

// ────────────────────────────────────────────────────────────────────────────
// Status helpers
// ────────────────────────────────────────────────────────────────────────────

const STATUS_CYCLE: Status[] = ['not_started', 'in_progress', 'pass', 'fail']

function nextStatus(s: Status): Status {
  return STATUS_CYCLE[(STATUS_CYCLE.indexOf(s) + 1) % STATUS_CYCLE.length]
}

function statusLabel(s: Status) {
  if (s === 'pass')        return 'Pass'
  if (s === 'fail')        return 'Fail'
  if (s === 'in_progress') return 'In Progress'
  return 'Not Started'
}

function StatusIcon({ status, size = 15 }: { status: Status; size?: number }) {
  if (status === 'pass')        return <CheckCircle2 size={size} className="text-green-400 shrink-0" />
  if (status === 'fail')        return <XCircle      size={size} className="text-red-400 shrink-0" />
  if (status === 'in_progress') return <Clock        size={size} className="text-yellow-400 shrink-0" />
  return <Circle size={size} className="text-zinc-600 shrink-0" />
}

// ────────────────────────────────────────────────────────────────────────────
// Progress bar
// ────────────────────────────────────────────────────────────────────────────

function ProgressBar({ pass, fail, inProgress, total }: { pass: number; fail: number; inProgress: number; total: number }) {
  const pPct = total ? (pass / total) * 100 : 0
  const fPct = total ? (fail / total) * 100 : 0
  const iPct = total ? (inProgress / total) * 100 : 0
  return (
    <div className="w-full h-2 rounded-full bg-zinc-800 overflow-hidden flex">
      <div className="h-full bg-green-500 transition-all duration-300" style={{ width: `${pPct}%` }} />
      <div className="h-full bg-yellow-500 transition-all duration-300" style={{ width: `${iPct}%` }} />
      <div className="h-full bg-red-500 transition-all duration-300"   style={{ width: `${fPct}%` }} />
    </div>
  )
}

// ────────────────────────────────────────────────────────────────────────────
// Category accordion
// ────────────────────────────────────────────────────────────────────────────

function CategorySection({
  category,
  statuses,
  onToggle,
}: {
  category: Category
  statuses: Record<string, Status>
  onToggle: (id: string) => void
}) {
  const [open, setOpen] = useState(true)

  const pass       = category.tests.filter(t => (statuses[t.id] ?? t.defaultStatus) === 'pass').length
  const fail       = category.tests.filter(t => (statuses[t.id] ?? t.defaultStatus) === 'fail').length
  const inProgress = category.tests.filter(t => (statuses[t.id] ?? t.defaultStatus) === 'in_progress').length
  const total      = category.tests.length

  return (
    <div className="border border-bg-border rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-4 py-3 bg-bg-surface hover:bg-bg-elevated transition-colors text-left"
      >
        {open
          ? <ChevronDown  size={14} className="text-zinc-500 shrink-0" />
          : <ChevronRight size={14} className="text-zinc-500 shrink-0" />}
        <span className="font-mono text-sm font-medium text-zinc-200 flex-1">{category.category}</span>
        <span className="text-xs text-zinc-500 shrink-0">{pass + fail}/{total}</span>
        {fail > 0 && <span className="text-xs text-red-400 shrink-0">{fail} fail</span>}
        {pass > 0 && <span className="text-xs text-green-400 shrink-0">{pass} pass</span>}
        <div className="w-24 shrink-0">
          <ProgressBar pass={pass} fail={fail} inProgress={inProgress} total={total} />
        </div>
      </button>

      {open && (
        <div className="divide-y divide-bg-border">
          {category.tests.map(test => {
            const status = statuses[test.id] ?? test.defaultStatus
            return (
              <div
                key={test.id}
                onClick={() => onToggle(test.id)}
                className="flex items-start gap-3 px-4 py-2.5 hover:bg-bg-elevated cursor-pointer transition-colors group"
                title={`Click to cycle: ${statusLabel(status)} → ${statusLabel(nextStatus(status))}`}
              >
                <StatusIcon status={status} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-zinc-200 leading-snug">{test.title}</p>
                  {test.mavsId && (
                    <p className="text-xs text-zinc-600 font-mono mt-0.5">{test.mavsId}</p>
                  )}
                </div>
                <span className="text-xs text-zinc-600 font-mono shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                  {test.id}
                </span>
                <span
                  className={clsx('text-xs shrink-0 w-20 text-right', {
                    'text-green-400':  status === 'pass',
                    'text-red-400':    status === 'fail',
                    'text-yellow-400': status === 'in_progress',
                    'text-zinc-600':   status === 'not_started',
                  })}
                >
                  {statusLabel(status)}
                </span>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ────────────────────────────────────────────────────────────────────────────
// Main page
// ────────────────────────────────────────────────────────────────────────────

export default function ChecklistPage() {
  const [tab, setTab]       = useState<'mobile' | 'web'>('mobile')
  const [mobileOs, setMobileOs] = useState<MobileOs>('ios')

  const [iosStatuses,     setIosStatuses]     = useState<Record<string, Status>>(() => loadState('mobile', 'ios'))
  const [androidStatuses, setAndroidStatuses] = useState<Record<string, Status>>(() => loadState('mobile', 'android'))
  const [webStatuses,     setWebStatuses]     = useState<Record<string, Status>>(() => loadState('web'))

  const checklist = tab === 'web'
    ? WEB_CHECKLIST
    : mobileOs === 'ios' ? IOS_CHECKLIST : ANDROID_CHECKLIST

  const statuses = tab === 'web' ? webStatuses : mobileOs === 'ios' ? iosStatuses : androidStatuses

  const allTests   = useMemo(() => checklist.flatMap(c => c.tests), [checklist])
  const pass       = allTests.filter(t => (statuses[t.id] ?? t.defaultStatus) === 'pass').length
  const fail       = allTests.filter(t => (statuses[t.id] ?? t.defaultStatus) === 'fail').length
  const inProgress = allTests.filter(t => (statuses[t.id] ?? t.defaultStatus) === 'in_progress').length
  const total      = allTests.length
  const pct        = total ? Math.round(((pass + fail) / total) * 100) : 0

  function toggle(id: string) {
    const updater = (prev: Record<string, Status>) => {
      const test = allTests.find(t => t.id === id)
      const cur  = prev[id] ?? (test?.defaultStatus ?? 'not_started')
      return { ...prev, [id]: nextStatus(cur) }
    }

    if (tab === 'web') {
      setWebStatuses(prev => { const n = updater(prev); saveState(n, 'web'); return n })
    } else if (mobileOs === 'ios') {
      setIosStatuses(prev => { const n = updater(prev); saveState(n, 'mobile', 'ios'); return n })
    } else {
      setAndroidStatuses(prev => { const n = updater(prev); saveState(n, 'mobile', 'android'); return n })
    }
  }

  function resetCurrent() {
    const empty: Record<string, Status> = {}
    if (tab === 'web') {
      setWebStatuses(empty); saveState(empty, 'web')
    } else if (mobileOs === 'ios') {
      setIosStatuses(empty); saveState(empty, 'mobile', 'ios')
    } else {
      setAndroidStatuses(empty); saveState(empty, 'mobile', 'android')
    }
  }

  const subtitle =
    tab === 'web'
      ? 'OWASP WSTG v4.2 — Web Security Testing Guide'
      : mobileOs === 'ios'
        ? 'OWASP MASVS v2.0 — iOS Mobile Security'
        : 'OWASP MASVS v2.0 — Android Mobile Security'

  return (
    <div className="flex flex-col h-full p-4 gap-4 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between shrink-0">
        <div>
          <h1 className="text-lg font-semibold text-zinc-100">Testing Checklist</h1>
          <p className="text-xs text-zinc-500">{subtitle}</p>
        </div>
        <button
          onClick={resetCurrent}
          className="flex items-center gap-1.5 text-xs text-zinc-500 hover:text-zinc-300 border border-bg-border rounded px-2 py-1 transition-colors"
        >
          <RotateCcw size={12} />
          Reset
        </button>
      </div>

      {/* Top-level tabs: Mobile / Web */}
      <div className="flex items-center gap-2 shrink-0">
        <div className="flex gap-1">
          <button
            onClick={() => setTab('mobile')}
            className={clsx(
              'flex items-center gap-1.5 px-4 py-1.5 rounded text-sm font-medium transition-colors',
              tab === 'mobile' ? 'bg-accent text-white' : 'text-zinc-400 hover:text-zinc-200 hover:bg-bg-elevated'
            )}
          >
            <Smartphone size={14} />
            Mobile
          </button>
          <button
            onClick={() => setTab('web')}
            className={clsx(
              'flex items-center gap-1.5 px-4 py-1.5 rounded text-sm font-medium transition-colors',
              tab === 'web' ? 'bg-accent text-white' : 'text-zinc-400 hover:text-zinc-200 hover:bg-bg-elevated'
            )}
          >
            <Globe size={14} />
            Web
          </button>
        </div>

        {/* iOS / Android switch — only visible on Mobile tab */}
        {tab === 'mobile' && (
          <div className="flex items-center ml-4 rounded-lg border border-bg-border overflow-hidden shrink-0">
            <button
              onClick={() => setMobileOs('ios')}
              className={clsx(
                'px-3 py-1 text-xs font-medium transition-colors',
                mobileOs === 'ios'
                  ? 'bg-zinc-700 text-zinc-100'
                  : 'text-zinc-500 hover:text-zinc-300 hover:bg-bg-elevated'
              )}
            >
              iOS
            </button>
            <button
              onClick={() => setMobileOs('android')}
              className={clsx(
                'px-3 py-1 text-xs font-medium transition-colors',
                mobileOs === 'android'
                  ? 'bg-zinc-700 text-zinc-100'
                  : 'text-zinc-500 hover:text-zinc-300 hover:bg-bg-elevated'
              )}
            >
              Android
            </button>
          </div>
        )}
      </div>

      {/* Overall progress bar */}
      <div className="shrink-0 bg-bg-surface border border-bg-border rounded-lg p-4">
        <div className="flex justify-between text-xs text-zinc-400 mb-1.5">
          <span>{pass + fail} of {total} complete ({pct}%)</span>
          <div className="flex gap-3">
            <span className="text-green-400">{pass} pass</span>
            <span className="text-red-400">{fail} fail</span>
            <span className="text-yellow-400">{inProgress} in progress</span>
            <span className="text-zinc-600">{total - pass - fail - inProgress} not started</span>
          </div>
        </div>
        <ProgressBar pass={pass} fail={fail} inProgress={inProgress} total={total} />
      </div>

      {/* Checklist */}
      <div className="flex-1 overflow-y-auto space-y-2 pr-1">
        {checklist.map(cat => (
          <CategorySection
            key={cat.category}
            category={cat}
            statuses={statuses}
            onToggle={toggle}
          />
        ))}
      </div>
    </div>
  )
}
