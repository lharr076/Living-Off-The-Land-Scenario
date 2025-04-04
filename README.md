<img width="400" src="https://github.com/lharr076/Living-Off-The-Land-Scenario/blob/main/assests/sys-hacked-img.jpg" alt="Living Off The Land image"/>

# Threat Hunt Report: Living Off The Land(LOTL)
- [Scenario Creation](https://github.com/lharr076/Living-Off-The-Land-Scenario/blob/main/living_off_the_land_template.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- PowerShell
- Command Line Interface (CLI)
- Github

---

##  Scenario

An employee arrives to work after the weekend and starts their PC. After logging on and stepping away from the computer, the employee notice notepad is open and has a message quoting a song from Pink Floyd that says, "`Hello my son Welcome to the machine`". Thinking it was a joke from one of the other staff members, the employee closes out the notepad message and proceeds with their day. The following day the employee did not step away from the computer after logon and after a few minutes of being logged on, the message pops up again. The employee contacts their first line supervisor of the incident and with the supervisor performing a restart of the machine, the supervisor also witnessed this message come across the employees screen. The goal is to detect any files or folders that have been created and/or moved and analyze related security incidents to mitigate potential risks. If any data is found, notify management.

### High-Level Insider Threat IoC Discovery Plan

- **Check `DeviceFileEvents`** for any files downloaded, created, or moved.
- **Check `DeviceProcessEvents`** for any signs of the command line interface (CLI) or PowerShell usage.

---

## Steps Taken

### 1. Searched the `DeviceProcessEvents` and `DeviceFileEvents` Tables For Relevant Events to Command Line Interface (CLI) and Files Downloaded

Searched for any processes utilizing the command line interface (CLI) and at `2025-04-03T12:07:18` a command was ran to download a file from a remote location using `PowerShell`. The command uses `-ExecutionPolicy Bypass` to override the machine current execution policy. The command also performs the download silently using `WindowsStyle Hidden`. The file in question is `https://raw.githubusercontent.com/lharr076/Living-Off-The-Land-Scenario/refs/heads/main/assests/themachine.html.ps1` and the location of the download is `C:\Users\Training-vm-1186\Downloads\themachine.html.ps1` at `2025-04-03T12:07:23`. The file is a `PowerShell` script dressed as a `HTML` file. These events began at `2025-04-03T12:07:18`.

**Querys used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == target_machine
| where AccountName == "training-vm-1186"
| where Timestamp >=  datetime(2025-04-03)
| where InitiatingProcessFileName in ("cmd.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

DeviceFileEvents
| where DeviceName StartsWith target_machine
| where ActionType in ("FileCreated", "FileRenamed")
| where Timestamp >=  datetime(2025-04-03)
| where FolderPath contains "Downloads"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
| order by Timestamp desc
```
<img width="1212" alt="LOTL DeviceProcessEvents1" src="https://github.com/lharr076/Living-Off-The-Land-Scenario/blob/main/assests/DeviceProcessEvents1.jpg">

<img width="1212" alt="LOTL DeviceFileEvents1" src="https://github.com/lharr076/Living-Off-The-Land-Scenario/blob/main/assests/DeviceFileEvents1.jpg">

---

### 2. Searched the `DeviceFileEvents` Table For Relevant Events to System32

Searched in the `FolderPath` that contained the string "System32". Based on the logs returned, at `2025-04-03T12:07:24`, a task is created within the `System32\Tasks` folder called `StartNotepadWithDelay` signaling an event involving `notepad` will happen after some time passes.

**Query used to locate event:**

```kql
DeviceFileEvents
| where DeviceName StartsWith target_machine
| where ActionType in ("FileCreated", "FileRenamed")
| where Timestamp >=  datetime(2025-04-03)
| where FolderPath contains "System32"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
| order by Timestamp desc


```

<img width="1212" alt="DeviceFileEvents2" src="https://github.com/lharr076/Living-Off-The-Land-Scenario/blob/main/assests/DeviceFileEvents2.jpg">

---

### 3. Searched the `DeviceProcessEvents` Table For Relevant Events to PowerShell 

Searched for an `InitiatingProcessFileName` that contained in `PowerShell`. Based on the logs returned, at `2025-04-04T09:34:07`, `notepad.exe` is executed by `powershell.exe` with the command (-Command `"Start-Process notepad.exe; Start-Sleep -Seconds 2; Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait('Hello my son{ENTER}Welcome to the machine{ENTER}')`).

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == target_machine
| where AccountName == "training-vm-1186"
| where Timestamp >=  datetime(2025-04-03)
| where InitiatingProcessFileName in ("powershell.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc


```
<img width="1212" alt="DeviceProcessEvents2" src="https://github.com/lharr076/Living-Off-The-Land-Scenario/blob/main/assests/DeviceProcessEvents2.jpg">

---

## Chronological Event Timeline 

### 1. File Downloaded - Malicious File downloaded from remote location

- **Timestamp:** `2025-04-03T12:07:18`
- **Event:** The PC user "Training-vm-1186" executed a command to download a file named `themachine.html.ps1` from a remote location.
- **Action:** File download detected.


### 2. File Created - File Created in Downloads Folder

- **Timestamp:** `2025-04-03T12:07:23`
- **Event:** The file `themachine.html.ps1` was created in the Downloads folder.
- **Action:** File creation detected.
- **File Path:** `C:\Users\Training-vm-1186\Downloads\themachine.html.ps1`t`

### 3. Scheduled Task Creation - StartNotepadWithDelay Task Created

- **Timestamp:** `2025-04-03T12:07:24`
- **Event:** A task named `StartNotepadWithDelay` was created in the `System32\Tasks` folder.
- **Action:** Task creation detected. 
- **File Path:** `C:\Windows\System32\Tasks\StartNotepadWithDelay`

### 4. Task Execution - Task Executed via PowerShell

- **Timestamp:** `2025-04-04T09:34:07`
- **Event:** Two minutes after logon, a task named `StartNotepadWithDelay` was executed via PowerShell.
- **Action:** Execution success.
- **Process:** `powershell.exe`, `notepad.exe`

---

## Summary

The employee utilizing the machine "training-vm-118" experienced `Remote Code Execution exploiting` `Living Off The Land` utilizing tools that are default to Windows. The attacker utilized the command line (CLI) to silently download a malicious file called `themachine.html.ps1` from a remote location. The file is a `PowerShell` script dressed as a `HTML` file. Within the same command, the attacker was also able to  run the `PowerShell` script to create a task in the `System32\Tasks` folder called `StartNotepadWithDelay`. Two minutes after logon, the task `StartNotepadWithDelay` executes the script, `"Start-Process notepad.exe; Start-Sleep -Seconds 2; Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait('Hello my son{ENTER}Welcome to the machine{ENTER}')` every time the employee logs on.

---

## Response Taken

The device was isolated and the persistent task was removed along with the malicious file. The device was swept for any other attack vectors that can be exploited and a friendly reminder was sent to the employee about security best practices to ensure the employee is following them. The employee's direct manager was notified about the incident.

---
