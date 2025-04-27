
<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/SPANKYWOWWOW/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched the DeviceFileEvents table for ANY file that had the string `tor` in it and discovered what looks like the user `labuser007` downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-04-08T22:11:33.4378077Z`. These events began at: `2025-04-08T21:56:01.3513123Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "davarthreathunt"
| where InitiatingProcessAccountName == "labuser007"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-04-08T21:56:01.3513123Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName


```
![image](https://github.com/user-attachments/assets/66eea5c3-20bb-46c8-bb8e-9d984f07c89b)


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string `tor-browser-windows`. Based on the logs returned, at `2025-04-08T21:59:21.0020949Z`, an employee on the `davarthreathunt` device ran the file `tor-browser-windows-x86_64-portable-14.0.9.exe` from their Downloads folder, using a command that triggered to locate event:

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "davarthreathunt"
| where ProcessCommandLine contains "tor-browser-windows"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,ProcessCommandLine

```
![image](https://github.com/user-attachments/assets/08cfd74f-bc77-405e-a8ed-72239c3be6b2)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user `labuser007` actually opened the tor browser. There was evidence that they did open it at `2025-04-08T21:59:49.1605732Z`. There were several other instances of `firefox.exe(Tor)` as well as `tor.exe` spawned afterwards


**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "davarthreathunt"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256,ProcessCommandLine
| order by Timestamp desc

```
![image](https://github.com/user-attachments/assets/c998d413-4d83-4d40-8a9b-14b96dd6d935)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Search the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports.

At `2025-04-08T21:59:59.0683546Z`, an employee on the `davarthreathunt` device successfully established a connection to the remote IP address `157.90.112.145` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\labuser007\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "davarthreathunt"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc

```
![image](https://github.com/user-attachments/assets/e7737288-cb00-4446-bafd-f6959ea4adc1)


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `April 8, 2025 – 21:56:01 UTC`
🔹 User `labuser007` downloads the file:
 `tor-browser-windows-x86_64-portable-14.0.9.exe`
 📂 Location: `C:\Users\labuser007\Downloads\tor-browser-windows-x86_64-portable-14.0.9.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `April 8, 2025 – 21:59:21 UTC`
🔹 User executes the Tor Browser installer.
 🛠️ Process Created: `tor-browser-windows-x86_64-portable-14.0.9.exe`
 🗂️ From: Downloads folder
 🔍 Command Line: `tor-browser-windows-x86_64-portable-14.0.9.exe /S`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `April 8, 2025 – 21:59:35 - 21:59:36 UTC`
🔹 Multiple Tor-related files are created on the desktop, including:
`Tor.txt`
`Tor-Launcher.txt`
`tor.exe`
 📂 Path: `C:\Users\labuser007\Desktop\Tor Browser\Browser\TorBrowser\Tor\`

### 4. Network Connection - TOR Network

- **Timestamp:** `April 8, 2025 – 21:59:49 UTC`
🔹 Tor Browser is launched.
 Process: `tor.exe` and `firefox.exe` both start executing.
 This confirms that the browser was successfully opened.

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:** `April 8, 2025 – 21:59:59 UTC`
  🔹 Outbound network connection is established via Tor.
🌐 Remote IP: `157.90.112.145`

🔌 Port: `9001` (a known Tor relay port)

🔄 Initiating Process: `tor.exe`
 📂 Path: `C:\Users\labuser007\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

Additional connections were also observed on port `443`, indicating encrypted web traffic via the Tor network.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `April 8, 2025 – 22:11:33 UTC`
🔹 A file named `tor-shopping-list.txt` is created on the desktop.
 This may suggest potential use of Tor for planning or communication.

---

## Summary

- User `labuser007` downloaded and executed the Tor browser.
- Successful installation and execution occurred, confirmed by file activity and process creation logs.
- Network logs confirm actual Tor network usage with outbound connections.
- The presence of `tor-shopping-list.txt` suggests user intent to document or plan activity.

---

## Response Taken

TOR usage was confirmed on the endpoint `DavarThreatHunt` by the user `labuser007`. The device was isolated and the user's direct manager was notified.

---
