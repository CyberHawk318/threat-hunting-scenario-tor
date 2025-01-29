<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/CyberHawk318/threat-hunting-scenario-event-creation-tor/blob/main/README.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Seearched DeviceFile table for any file that had the string “tor” in it. It was discovered that the user “labvm” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a text file named “TOR SHOPPING LIST.txt”. These events began at: `2025-01-28T22:43:39.6647966Z`

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName startswith "tor"
| where DeviceName == "labvm-hawk"
| order by Timestamp desc 
| project Timestamp, ActionType, FileName, SHA256, account = InitiatingProcessAccountName

```
![Screenshot 2025-01-29 at 9 34 39 AM](https://github.com/user-attachments/assets/19ae3a2a-4a71-4120-985b-9689d4adbe19)

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the ProcessEvent table for any process that contained the string “tor-browser-windows-x86_64-portable-14.0.4.exe”. Based on the logs returned, on January 29, 2025, at 5:45 AM, a process was initiated on the account "labvm" to execute the file “tor-browser-windows-x86_64-portable-14.0.4.exe”. The file, identified by its unique SHA-256 hash (095da0bb0c9db5cc23513a511e6f617fc5e278fe31bf48c164c31796f8c3890c), was launched with the /S command-line parameter, likely indicating a silent or automated installation or execution.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "labvm-hawk"
|where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.4.exe"
| project Timestamp, ActionType, FileName, SHA256, account = InitiatingProcessAccountName, ProcessCommandLine

```
![Screenshot 2025-01-29 at 9 37 12 AM](https://github.com/user-attachments/assets/9e5cfda0-5a92-4789-8ae1-3de8d0a81288)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvent table for any indication that user “labvm” actually opened the tor browser. There was evidence that they did open it at `2025-01-28T22:46:31.5494809Z`. There were several other instances of firefox.exe (Tor) and tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "labvm-hawk"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc 
| project Timestamp, ActionType, FileName, SHA256, account = InitiatingProcessAccountName, ProcessCommandLine

```
![Screenshot 2025-01-29 at 9 38 41 AM](https://github.com/user-attachments/assets/19b0a48a-81e8-4597-ab4d-e19b062182c6)

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication that the tor browser was used to establish a connection using any of he known tor ports.At 5:46 AM, On January 29, 2025, a computer named “labvm-hawk” successfully established an outbound network connection. The connection originated from the “labvm” user account and was initiated by tor.exe, located in the Tor Browser directory on the desktop. This process connected to the remote IP address 91.56.3.85 over port 9001, which is commonly associated with Tor network traffic. The connection also involved the URL https://www.irfegjnj5ihl.com, suggesting potential communication with an external server.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "labvm-hawk"
| order by Timestamp desc 
| where InitiatingProcessAccountName != "system" 
| where RemotePort in ("9001", "9030", "9040", "9050","9051")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFolderPath

```
![Screenshot 2025-01-29 at 9 39 49 AM](https://github.com/user-attachments/assets/701250a7-5daf-463f-b265-3a2a6f4d8e84)

---

## Chronological Event Timeline  

## 🛠 Tor Installation and Execution  
- **5:43:39 AM** – A file named `tor-browser-windows-x86_64-portable-14.0.4.exe` was renamed.  
- **5:45:54 AM** – The renamed Tor Browser installer was executed with the `/S` switch, indicating a **silent installation**.  
- **5:46:16 AM - 5:46:27 AM** – Several Tor-related files were created, confirming installation:  
  - `Tor.txt`  
  - `Tor-Launcher.txt`  
  - `Torbutton.txt`  
  - `tor.exe`  
  - `Tor Browser.lnk`  
- **5:46:35 AM** – `tor.exe` was executed, establishing a connection to the **Tor network**.  

## 🌐 Firefox Execution (Tor Browser Usage)  
- **5:46:36 AM - 5:53:59 AM** – Multiple instances of `firefox.exe` were executed with parameters indicating that they were running within the **Tor Browser environment**.  
- The sequential launches suggest **web activity through the Tor network**.  

## ⚠️ Suspicious File Activity  
- **5:56:19 AM** – A file named `TOR SHOPPING LIST.txt` was created.  
- **5:56:19 AM** – Two **shortcut (.lnk) files** pointing to the `TOR SHOPPING LIST.txt` file were created, potentially for easier access.  
- **5:56:19 AM** – `TOR SHOPPING LIST.txt` was renamed.  
- **5:56:39 AM** – `TOR SHOPPING LIST.txt` was **modified**.  

---

## Summary

On January 29, 2025, at approximately 5:43 AM, the Tor browser installation process began on the system named "labvm." The installation was followed by the execution of the browser and multiple instances of Firefox.exe, indicating active use of the Tor network. Shortly thereafter, a text file named "TOR SHOPPING LIST.txt" was created, modified, and linked multiple times.

---

## Response Taken

TOR usage was confirmed on the endpoint labvm-hawk by the user labvm. The device was isolated and the user's direct manager was notified.

---
