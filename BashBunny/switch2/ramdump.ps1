$bashbunny = (gwmi win32_volume -f 'label=''BASHBUNNY''').Name
$external = (gwmi win32_volume -f 'label=''ExtDrive''').Name
#Create directory in loot folder to store file
mkdir $external\TriageData-RAM\$env:computername

$date = Get-Date -Format "dddd MM/dd/yyyy HH:mm K"
$src_dir = "$external\TriageData-RAM\$env:computername"
set-location $src_dir
$ram = "$bashbunny\tools\DumpIt.exe"
#$args = "/a /f $src_dir\$env:computername.raw" 
& $ram | Out-File -FilePath "$src_dir\log.txt"
"Acquisition Date:" >> "$src_dir\log.txt"
 "$date" >> "$src_dir\log.txt"