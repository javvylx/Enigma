
#Get the drive letter
$bashbunny = (gwmi win32_volume -f 'label=''BASHBUNNY''').Name
$external = (gwmi win32_volume -f 'label=''ExtDrive''').Name
#Create directory in loot folder to store file
mkdir $bashbunny\loot\triage\$env:computername

$exfil_dir="C:\Windows\System32\winevt\Logs"
$exfil_ext="Security.evtx"
$loot_dir= "$bashbunny\loot\triage\$env:computername"

"Basic Computer Info:" >> "$loot_dir\computer_info.txt"
Get-WmiObject -Class Win32_ComputerSystem >> "$loot_dir\computer_info.txt"

"Disk Space Info:" >> "$LootDir\computer_info.txt"
Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" -ComputerName . >> "$loot_dir\computer_info.txt"

#run robocopy to copy Security.evtx out
robocopy $exfil_dir $loot_dir $exfil_ext /S /MT /Z /tee /log:$loot_dir\robocopy.log

