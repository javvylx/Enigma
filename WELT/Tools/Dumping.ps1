<#

    JEROME TAN GO ADD THE SYNOPSIS IN BECAUSE I FUCKING LAZE
    n = case name
    cd to e.g. F:/asdasd/WELT
    run script
    logs will dump to F/asdasd/WELT/logs or wherever you want
    analysis also ^
#>


param(
	[Parameter(Mandatory=$true)][string]$n
)

$casefile = "$n-$(get-date -f ddMMyyyy-HHmm)"
if (!(test-path ".\$casefile")){
		new-item -type directory -Path ".\$casefile"
        "Logs" | % {New-Item -Name ".\$casefile\$_" -type directory}

		write-host "Case File is created successfully!" -foregroundcolor "green"
		write-host "-------------------------------------------------------------------------"
}

$arg1 = "C:\Windows\sysnative\winevt\Logs\Security.evtx" 
$arg2 = "C:\Windows\sysnative\winevt\Logs\Windows Powershell.evtx"

python .\python-evtx-master\scripts\evtx_dump.py $arg1 > .\$casefile\Logs\Security.xml #python script
write-host "Dumping of Security Logs successful!" -foregroundcolor "green"
write-host "-------------------------------------------------------------------------"
python .\python-evtx-master\scripts\evtx_dump.py $arg2 > .\$casefile\Logs\Powershell.xml #python script
write-host "Dumping of Powershell Logs successful!" -foregroundcolor "green"
write-host "-------------------------------------------------------------------------"

$windd = ".\$casefile\Logs"


# Whole WinD log
$defender = get-winevent "microsoft-windows-windows defender/operational" | format-table -wrap -auto
$defender | out-file "$windd\WinDefender_Dump.txt"
write-host "Dumping Windows Defender Logs"
write-host "-------------------------------------------------------------------------"


# warning/error items from WinD logs
$warning = get-winevent -LogName "microsoft-windows-windows defender/operational" | Where-object {$_.LevelDisplayName -eq "warning" -or $_.LevelDisplayName -eq "error"} | format-table -wrap -auto
$warning | out-file "$windd\WinDefender(WE).txt"
write-host "Dumping Windows Defenders Logs"
write-host "-------------------------------------------------------------------------"
write-host "Dumping of Windows Defender Logs completed!" -foregroundcolor "green"
write-host "-------------------------------------------------------------------------"


# MPThreatDetection detects for possible malware
$threats = get-MPThreatDetection | Select-Object -ExpandProperty resources
$threats | out-file "$windd\WinDefender_Threats.txt"
write-host "Extraction of threats detected by Windows Defender successful!" -foregroundcolor "green"
write-host "------------------------------RESULTS-------------------------------------" 
#get-content ".\Analysis\WinDefender Threats.txt"
write-host "--------------------------------END---------------------------------------" 