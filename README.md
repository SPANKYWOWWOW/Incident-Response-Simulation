# Incident Response Simulation (T1059 - Command and Scripting Interpreter & T1086 - PowerShell)
- [Scenario Creation](https://github.com/SPANKYWOWWOW/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Tools and Frameworks used in this lab
- Azure Virtual Machines
- Microsoft Defender for Endpoint
- Microsoft Sentinel
- Wireshark (For network packet collection)
- Powershell
- Atomic Red Scripts
- Optional: DeepBlueCLI
- NIST 800-61 Incident Response

- NOTE: It is recommended to go through the entire ([Threat Hunting, SecOps, and Incident Response](https://www.skool.com/cyber-range/about?ref=165f4ace0ddb4555bca0303c82a78c4a)) Skool course first before attempting this lab.


##  Scenario

In this lab project, you will simulate a basic script execution attack by running an Atomic Red script called AutoIt Script Execution in your Azure Windows VM. 

`“Script execution attacks”` are when a bad actor infects your endpoint with malware that uses a “script interpreter” (in this case, AutoIt.exe) to automatically launch malicious programs within the target machine, silently. This typically happens when you download this malware from a website or click a malicious link.

In this lab, the “malicious program” that will be remotely launched by this attack will be Windows Calculator. Once the attack runs successfully, you will then conduct a complete incident response investigation based on NIST 800-61 guidelines.

##  Important Links

([Link to Atomic Red Script](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059/T1059.yaml#L4))

([Link to Atomic Red attack description (MITRE)](https://www.atomicredteam.io/atomic-red-team/atomics/T1059#atomic-test-1---autoit-script-execution))

([Wireshark Tool Download](https://www.wireshark.org/download.html))

([DeepBlueCLI (optional)](https://www.sans.org/tools/deepbluecli/))

([Git for Windows (Needed to run Atomic Red Script into VM)](https://git-scm.com/download/win))


---

## Steps Taken

### 1. Prepare Your Virtual Machine for Attack Simulation

- Create your Azure Windows virtual machine (VM) by following the instructions laid out in the Cyber Range Skool Course ([click here](https://www.skool.com/cyber-range/classroom/1e12b5ac?md=023a17a3c87b4598926163c8188642fd)) - `Make sure you create a VM with a public IP address!`

- Disable your VM’s firewall and configure your VM Network Security Group (NSG) to allow all inbound traffic. See instructions on how to do this by ([clicking here](https://www.skool.com/cyber-range/classroom/1e12b5ac?md=c32ee90cd87a4cbc9075a16613491ce6)).

- Onboard your VM to Microsoft Defender for Endpoint (EDR). See instructions on how by ([clicking here](https://www.skool.com/cyber-range/classroom/7ffd6346?md=8f3753c7a6244a6d891688706d46fab9)).

- Once you created your VM, `log into it`. Then download and install the following tools into the VM (`Get links from Intro Page`):

- Wireshark - Install with default settings
  ![image](https://github.com/user-attachments/assets/32242e7e-9d09-4de8-851d-f28186fab86a)

- DeepBlueCLI (optional, but not necessary for the lab. Make sure you create a Unzipped folder on Desktop.)
  ![image](https://github.com/user-attachments/assets/7a440ebd-f7c6-4c07-b28c-eb9eebe734da)

- Git for Windows (Choose “Git from Command Line and 3rd Party Software”. Everything else, choose the default install settings.)
  ![image](https://github.com/user-attachments/assets/64c41eb6-d0dd-4bdd-8afd-3b13f1facaa8)
  ![image](https://github.com/user-attachments/assets/cdf7d4e5-5e62-4eb3-a57e-ddd71f805eb8)

---

### 2. Setup MDE To Detect Attack

- Next, we need to make sure that our `Microsoft Defender for Enpoint (MDE)` is setup to detect the attack we are about to simulate with the Atomic Red Team Script.

- Based on the behavior of the [(AutoIt Script Execution script](https://www.atomicredteam.io/atomic-red-team/atomics/T1059#atomic-test-1---autoit-script-execution)), we know that this script is designed to do the following actions in our VM:
1. Check to see if `AutoIt3.exe` is installed on the machine.
2. If AutoIt3.exe is `NOT` present, then it will silently download the program from this website via Powershell and install it into the machine: (https://www.autoitscript.com/cgi-bin/getfile.pl?autoit3/autoit-v3-setup.exe)
3. Once Autolt3.exe is installed, it will then run this program in combination with the malicious `calc.au3` script found in the following directory: `PathToAtomicsFolder\T1059\src\calc.au3`
4. This will result in Windows `Calculator being launched`.

Tip: You can also upload the raw attack script into ChatGpt and ask it what it is trying to do in simple terms.

Therefore, `we will create the following MDE detection rules` using KQL query language to alert us when any of these steps are executed on our VM:

Creating The MDE KQL Detection Rules:

Note: To Review how to created MDE detection rules click here

- For each rule you create, do the following in the setup process:
1. General: Add the correct MITRE category and technique + High Severity
2. Impacted Entities: DeviceName
3. Automated Actions: None

Rule 1: Alert when AutoIt.exe is launched from a User, Temp or Downloads folder AND the command line runs the malicious calc.au3 script file:

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "your-device-name"
| where FileName =~ "AutoIt3.exe"
| where ProcessCommandLine has_any (".au3", "calc.au3")
| where FolderPath has_any ("Users", "Temp", "Downloads")
```

Rule 2: Alert when Autolt.exe launches calc.exe (this is an abnormal parent-child process relationship):

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "your-device-name"
| where InitiatingProcessFileName =~ "AutoIt3.exe"
| where FileName =~ "calc.exe"
```

Rule 3: Alert when PowerShell is used to download something from the internet via the “Invoke-WebRequest” command:

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "your-device-name"
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("Invoke-WebRequest", "wget", "curl")
| where ProcessCommandLine has "autoit" "getfile.pl"
```

Rule 4: Alert when Powershell is being used to install Autolt.exe (Powershell is not typically used to install programs like these in a normal enterprise environment).

**Query used to locate event:**

```kql
DeviceFileEvents
| where DeviceName == "your-device-name"
| where FileName has "autoit" and FileName endswith ".exe"
| where InitiatingProcessFileName =~ "powershell.exe"
```

Optional Rule 5: Alert when non-standard scripting engines are found in the VM (like Autolt.exe, add others to the query, etc.). The “standard” scripting engines for Windows 10 are JScript and VBScript:

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "your-device-name"
| where FileName has_any ("AutoIt3.exe", "cscript.exe", "wscript.exe", "mshta.exe")
| summarize count() by DeviceName, FileName, bin(Timestamp, 1d)
| order by count_ desc

```
Note: If you do not know how to add detection rules to MDE ([click here](https://www.skool.com/cyber-range/classroom/7ffd6346?md=b4521d0acbb44a95b671992852ab548e)) for instructions


Here is a screenshot of the rules setup in MDE:
![image](https://github.com/user-attachments/assets/b40029e3-ee39-425b-95e9-5c4dccbe7e83)

---

### 3. Run the Atomic Script Attack

Now that our VM and MDE are setup, the next step is to run and detonate the Atomic Red malicious script into our VM and see if we can detect it. Here are the instructions to execute FROM WITHIN YOUR VM:

- Open and Run Wireshark in your VM to start collecting traffic packets. To do so, **open Wireshark** > Choose “**Ethernet**” > Click “**Start Capturing Packets**” (blue shark fin button)
![image](https://github.com/user-attachments/assets/ea3dfc35-3b42-4742-978d-15c174746c53)

Once Wireshark is running, open up Powershell as an Admnistrator and run the following powershell commands in the following order:

1. `git clone https://github.com/redcanaryco/atomic-red-team.git`
- This downloads the full library of Atomic Red simulated attacks into your VM, including the script we are using. 

2. `cd C:\Users\ceh2025\atomic-red-team`
- This moves you to the folder where the scripts are loaded

3. `$env:PathToAtomicsFolder = "C:\Users\YourUser\atomic-red-team\atomics\"`

- This makes sure that you are pulling the atomic script from the correct folder (Atomics) that was created when you cloned the Atomic Red database of attacks.
- Manually check to see if this filepath is actually true by manually looking up the folders, just in case.

4. `Install-Module -Name Invoke-AtomicRedTeam -Force -AllowClobber`
- This preps your VM for running the attacks by downloading the right module to do so. “-AllowClobber” also allows you to override any existing modules that could get in the way.

5. `Import-Module Invoke-AtomicRedTeam`
- This pullsup the needed module to run the script for your current Powershell session. You will see it install in powershell.

6. `Set-ExecutionPolicy Bypass -Scope Process -Force`
- This preps your VM for running the attacks by creating the right permissions so that no security controls get in the way.

7. `Invoke-AtomicTest T1059 -GetPrereqs -PathToAtomicsFolder "C:\Users\YourUser\atomic-red-team\atomics\"`
- Downloads and installs the pre-reqs needed to run the script (tools, programs, etc.)

8. `Invoke-AtomicTest T1059 -PathToAtomicsFolder "C:\Users\YourUser\atomic-red-team\atomics\"`
- Runs and detonates our malicious script in the VM. You should see calculator launched after running this.


Once you have run the script successfully, stop the Wireshark packet capture and save the recorded network activity into a PCAP file on your VM desktop (we will analyze this later).

Restore your firewall and NSG settings so that your VM does not get further compromised!


That’s it! You have successfully detonate this malicious script. Now let’s check if MDE has detected this attack in the next section so we can begin our Incident Response investigation!

---

### 4. Review MDE Alerts Post-Attack

Now that we have detonated the attack script, let’s check if the attack has triggered any of the detection rules we setup in MDE!

To do this, log into your MDE and click on **Assets** > **Devices** > **Click on Your VM** > **Incidents and Alerts** 

You should see a list of any `alerts that were triggered` by MDE, like this:

![image](https://github.com/user-attachments/assets/b58ab53a-14fe-47f8-a0b9-3f9941b1cd79)

As you can see,`one of our detection rules were triggered!` Ideally, the others should have also been triggered, but it seems like we have to refine the KQL queries a little more to improve their detection within MDE. We also seem to have a ransomware attack, probably due to disabling our firewall and NSG. For the sake of this lab, we will ignore the ransomware alert.

`So now that we officially have a security “Incident”`, lets begin our Incident Response invstigation according to NIST 800-61.

---
### 5. Conduct Incident Response Investigation 
We will be conducting our incident response investigation in accordance with NIST 800-61 guidelines, which puts us in the Detection and Analysis Phase (([Click Here](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)) for NIST 800-61 Guidelines PDF):
![image](https://github.com/user-attachments/assets/37b76289-d354-4732-830e-6a444534c52a)

Per NIST 800-61 guidelines, we need to perform the following tasks during our investigation in order to successfully determine if the alert is a “false” or “true” positive:
1. Find the attack vector used to initiate the attack.
2. Finding precursors or indicators of a security incident.
3. Analyze the potential security Incident and determine if it is a true or false positive.
4. Document all findings and activities of investigation if it is a true positive.
5. Report the confirmed security incident to management team.



a. **What Was the Attack Vector that Was Used?**
   
Under typical circumstance, our investigation would involve identifying the Attack Vector used to initiate the attack. Attack vectors could be things like clicking a link from a phishing email or a successful brute force attack, etc.

However, since we have simulated the attack from within our VM, there won’t be an “attack vector” to identify per se. 

b. **What are the Precursors and/or Indicators of the Attack?**
   
Since this was a simulated attack, there won’t be any real precursors since we intentionally disabled our VM’s firewall and allowed all inbound traffic to occur without restriction (NSG).

However, we have generated many indicators of our security incident via MDE and Sentinel logs and alerts. So we are now going to search through these logs to see if we can find any strong **indicators of compromise (IOCs)** from our simulated attack!

As a reminder, our simulated attack generated one MDE alert that indicated a potential attack. And so, we will begin our investigation here:
![image](https://github.com/user-attachments/assets/4c75e318-16c5-4e27-aa12-5d0cbc687877)

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
