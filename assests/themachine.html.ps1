# Create a scheduled task that runs 2 minutes after login
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command `"Start-Process notepad.exe; Start-Sleep -Seconds 2; Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait('Hello my son{ENTER}Welcome to the machine{ENTER}')`""
$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$Principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
# Create a task with a delay of 2 minutes (120 seconds)
$Trigger.Delay = 'PT120S'
# Register the task
Register-ScheduledTask -TaskName "StartNotepadWithDelay" -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal