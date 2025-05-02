# Incident Response Simulation (T1059 - Command and Scripting Interpreter & T1086 - PowerShell)

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
### 5.  Detection and Analysis Phase
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
### 5.1. Indicators of Compromise 
**Microsoft Defender for Endpoint Logs (MDE)**
To evaluate the logs recorded from MDE we will do the following:
- Look at the logs generated for the alert in MDE
- Analyze the PCAP file we created in our VM with Wireshark to identify suspicious network traffic from our VM.
- Create and Download an investigation package from MDE for our VM (Click here if you don’t know how)
- (Optional) use DeepBlueCLI to analyze windows event security logs from our VM.

Let’s Start with looking at the timeline of logs generated in MDE for that specific alert by going into the “Alerts” tab and clicking on the alert itself: 

![image](https://github.com/user-attachments/assets/c20ea9ed-0e83-45de-8e75-07ca61eedbfa)

Then we are going to down into the “Timeline” section and expand all of the process logs:

![image](https://github.com/user-attachments/assets/238c0b16-b679-407b-96d1-46633cbbc411)

Once we do this, `we can see the entire timeline of events` that were recorded by MDE when this alert was triggered! 

As you go through the expanded logs, you will see some familiar commands that we initiated when setting up our attack. You will also see `all the malware scripts` that were run as a result!:

![image](https://github.com/user-attachments/assets/0d87e601-28ac-4e88-b0f2-a337fc8fa442)

Clearly there is alot indicators of compromise here! At this point, we would have enough evidence to contain and `isolate this endpoint`. Lets dig deeper and see if we can detect the steps involved in our AutoIt Script Execution attack.


---
### 5.2. MDE Logs
Upon analyzing the MDE timeline of events, a few things stand out that tells us more about what this attack is trying to accomplish:

If we scroll down to event ID 11848, we can see a Powershell command that is initiating a `“Invoke-WebRequest”` command and downloaded `AutoIt-v3-setup.exe` from the following URI: 

`https[:]//www.autoitscript.com/cgi-bin/getfile.pl?autoit3/autoit-v3-setup.exe`

This is clearly the script downloading and installing the required AutoIt.exe program it needs to run the malicious script! (Remember our -GetPrereqs command?)
![image](https://github.com/user-attachments/assets/d9ef83a9-8fc9-4a10-adb2-cad637af2e4a)

And as a result we see that `AutoIt.exe was ran and installed`, which eventually lead to the execution of the `calc.au3` malicious script (resulting in calculator being launched in our VM)

![image](https://github.com/user-attachments/assets/a19ba3e3-82ab-4e42-b21c-c031403b4974)

But lets verify that this `“Invoke-WebRequest”`, which resulted in the download of AutoIt.exe, actually took place by analyzing the captured network traffic in our Wireshark PCAP file.

To do this, log back into your VM and open the PCAP file that was saved onto our Desktop with Wireshark:

![image](https://github.com/user-attachments/assets/918db320-2820-4b05-94c4-071cac1d2337)

---
### 5.3. Wireshark and Sentinal 
Once you open the PCAP file, you should see `all of the network traffic packets` that were captured during our attack simulation (there will be a TON):

![image](https://github.com/user-attachments/assets/8284acfa-b499-4dc6-b208-2313fde7d30e)

In order to verify that the `“Invoke-WebRequest”` we are going to filter down these results to the most relevant for our investigation. `Based on the MDE logs`, we know that the URI request occurred via `HTTPS` protocol at `3:51:08 PM` (`20:51:08 PM UTC`) to actually download the AutoIt-v3-setup.exe file. We also know that our VMs private IP (`10.0.0.189`) would be used as a “source IP” in the exchange…. 

Based on these facts,  we will construct the following display filter to see if we can find this malicious download request:

`tls && ip.src == 10.0.0.189 && frame contains "autoitscript.com"`

When we run this Display Filter, we get back one packet that shows an initial connection request to the likely website at the destination IP of `212.227.91.231`:

![image](https://github.com/user-attachments/assets/ae808155-9ce8-43fd-9b9b-1c0691fcdd9f)

Now that we have the destination IP, lets run this additional display filter to see the full exchange between our VM IP and the autoitscript.com website:

`ip.addr == 10.0.0.189 && ip.addr == 212.227.91.231 && tls`

The result yields evidence that the there was indeed an exchange of an encrypted payload (“application data”) between our VM’s IP and the suspected website’s IP at `20:51 PM UTC` (`15:51 in the EST`):

![image](https://github.com/user-attachments/assets/7dc408c0-7611-487f-8152-c04b854439c7)

We can also lookup this networking log in Sentinel by using the following KQL Query. 

**Query used to locate event:**

```kql

DeviceNetworkEvents
| where Timestamp > ago(24h)
| where DeviceName == "atomic-red-007"
| project Timestamp, DeviceName, RemoteIP, RemotePort, Protocol, ActionType, InitiatingProcessFileName, ReportId
| order by Timestamp desc
```
In this screenshot you will see that we can find a successful connection to the `same suspected IP address` at 20:51 PM UTC, further supporting that this security incident is indeed a true positive:

![image](https://github.com/user-attachments/assets/e3f5a676-e4d9-4e65-abfc-35ad2de293c9)

So at this point, we should have enough evidence to escalate this incident and move into the `Containment, Eradication, and Recovery` phase of NIST 800-6.

BUT I am going to go a step further and review the VM’s event security logs with DeepBlueCLI to see if I missed anything else…

You can also review these logs via Sentinel with KQL queries, whatever is easier for you! This is just another way to do it.

---
### 5.4. DeepBlueCLI 

**What is DeepBlueCLI?**
DeepBlueCLI is a program that was developed by the SANS institute to help conduct threat hunting activities. 

In simple terms, this Powershell script allows you to pull up any security event logs that have been triggered by your Windows VM. It is a super convenient way to get a quick snapshot of any malicious activity that has slipped through the cracks

In order to run this in our VM, follow these steps:
Log into your VM and open the DeepBlueCLI-master folder that we downloaded and unzipped earlier in Step 1.
Hold Shift + Right click inside the folder and select “Open PowerShell window here” (Make sure it is with Administrator priveledge)

![image](https://github.com/user-attachments/assets/5daff4ca-a36e-4c62-a877-5bb72dbdaec2)

In Powershell run this command to bypass any permission that might get in the way:

`Set-ExecutionPolicy Bypass -Scope CurrentUser`

Then execute this command (click “R” to run it when prompted):

`./DeepBlue.ps1 -log security`

Once you complete the above step, the DeepBlueCLI script will run and any security event logs that have been triggered will populate on the screen (might take a few minutes). 

In our case, here are some of the logs that have been generated:

![image](https://github.com/user-attachments/assets/176169ac-a73b-4ff5-b1a5-39ccbf71e4a6)

Because I disabled the VM firewall and NSG setting, we actually are seeing a TON of brute force attempts to log into our VM. Other than that, there aren’t any other security events present from this avenue.

Alright, lets move to the  Containment, Eradication, and Recovery phase of NIST 800-6!

---
### 6. Containment, Eradication, and Recovery 
At this point we have conducted our investigation in accordance with the Detection and Analysis phase of NIST 800-61. In a real work environment, this would be the time to collect your evidence, write a report of your findings and inform the appropriate stake holders of the confirmed security incident.

Once we have taken the above steps, we can now enter the Containment, Eradication and Recovery phase of NIST 800-61 (([Click Here](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)) for more info):

![image](https://github.com/user-attachments/assets/8579a189-c89c-4efb-9de1-163a3d6c5c16)

According to NIST, this phase involves completing the following tasks in order to remediate this security breach:
1. Choose a containment strategy
2. Gather any evidence, artifacts, IOCs for potential legal proceedings.
3. Identify the attacking host(s)
4. Eradicate the components of the breach and Recover the impacted assets.

`Choosing a containment strategy`: In our scenarios the most appropriate containment strategy is to `“isolate”` our VM from within Micrsoft Defender for Enpoint to prevent any further communication with external malicious servers.

`Gather evidence`: Here, we would gather all IP addresses, PCAP files, logs, hash values of suspected files (calc.au3.exe, etc.) and any indicators of compromise that will help build a legal case if needed.

`Identify the attacking host(s)`: Since this was a simulated attack, this won’t apply.

`Eradicate the components of the breach and Recover the impacted assets`: In our case, this would involve running an antivirus scan, reinstating our firewall and NSG settings, and deleting any malicious files from the VM. Since our VM instance was freshly created for this exercise, there will not be a “backup” to recover.


At this point, we have concluded the Containment, Eradication and Recovery phase and we are now in the final Post-Incident Activity phase. In this phase we `review all of the lessons learned` from our lab and use that to build better detection rules in future Atomic Red Attack simulations:

![image](https://github.com/user-attachments/assets/acea6b7e-5fa5-4dff-9261-eae11eccd844)


---

