 <#
	.SYNOPSIS
	This is a CLI-based event-logs correlator.

	.DESCRIPTION
	
	
	Parameters/Switches: 
	p - Specify a path to work in and save output to. If it did not exist previously, it will be created.
	l - The events log which is to be dumped.	
	d - Name the event log that is dumped out (file extension not required - .xml by default.)
	o - Name the output (results) file. (File extension not required - .txt by default.)
	V - Extract VSS Events. Script will not be run if switch is not called as parameter.
	wD - Extract Windows Defenders operational log. Script will not be run if switch is not called as parameter.
	wDt - Invokes "get-MpThreatsDetection" cmdlet. Extracts threats scanned by Windows Defender. *only applicable for powershell 3.0 onwards*
	b - Extract Logs before a certain date (dd/mm/yyyy).
	a - Extract Logs after a certain date (dd/mm/yyyy).
	nA - Analysis on $dump will not be run when this switch is called.
	oA - Analyse an event dump pre-defined by user

	.EXAMPLE
	powershell.exe -f "E:\Forensics\Windows Events\WELT.ps1" -p "C:\dump" -l "Security" -d "evdump" -b "11/5/2016" -a "2/12/2015" -o "Analysis Results"
	The output will be:
		-Tool will be run from E:\Forensics\Windows Events\
		-"dump" folder will be created in C:\
		-Eventlogs from Security will be dumped into the C:\dump
		-Dump will be named "evdump.xml"
		-Dump will consist of events extracted between 2/12/2015 and 11/5/2016.
		-Results after analysis will be named "Analysis Results.txt" and can be found in C:\dump
#>

param(
	[Parameter(Mandatory=$true)][string]$p,
	[Parameter(Mandatory=$true)][string]$d,
	[Parameter(Mandatory=$false)][string]$l,
	[Parameter(Mandatory=$false)][string]$o,
	[Parameter(Mandatory=$false)][switch]$V,
    [Parameter(Mandatory=$false)][switch]$wD,
	[Parameter(Mandatory=$false)][switch]$wDt,
    [Parameter(Mandatory=$false)][switch]$b,
    [Parameter(Mandatory=$false)][switch]$a,
    [Parameter(Mandatory=$false)][switch]$nA,
	[Parameter(Mandatory=$false)][switch]$oA
)

if (!$oA){

	$arg1 = "C:\Windows\sysnative\winevt\logs\" + $l + ".evtx"


    if (!(test-path "$p")){
		new-item $p -type directory
		write-host "New path $p is created successfully!" -foregroundcolor "green"
		write-host "-------------------------------------------------------------------------"
	}
    
	python .\python-evtx-master\scripts\evtx_dump.py $arg1 > $p\$d.xml #python script

    
    write-host "Dumping of $l Logs successful!" -foregroundcolor "green"
    write-host "-------------------------------------------------------------------------"
}


if($wD){
	$defender = get-winevent "microsoft-windows-windows defender/operational" | format-table -wrap -auto
	new-item "$p\Windows Defender Analysis" -type directory
	$defender | out-file "$p\Windows Defender Analysis\WinDefender Dump.txt"
	write-host "Dumping Windows Defender Logs into $p\Windows Defender Analysis\WinDefender Dump.txt ........."
	write-host "-------------------------------------------------------------------------"
	write-host "Dumping of Windows Defender Logs successful!" -foregroundcolor "green"
	write-host "-------------------------------------------------------------------------"
	$windanalysis = select-object "$p\Windows Defender Analysis\WinDefender Dump.txt" | where {$_ -match "1116"}
	$windanalysis | out-file "$p\Windows Defender Analysis\WinDefender results.txt"
	$windanalysis = select-object "$p\Windows Defender Analysis\WinDefender Dump.txt" | where {$_ -match "1006"}
	$windanalysis | out-file "$p\Windows Defender Analysis\WinDefender results.txt"
	$windanalysis = select-object "$p\Windows Defender Analysis\WinDefender Dump.txt" | where {$_ -match "1008"}
	$windanalysis | out-file "$p\Windows Defender Analysis\WinDefender results.txt"
	$windanalysis = select-object "$p\Windows Defender Analysis\WinDefender Dump.txt" | where {$_ -match "1015"}
	$windanalysis | out-file "$p\Windows Defender Analysis\WinDefender results.txt"
	$windanalysis = select-object "$p\Windows Defender Analysis\WinDefender Dump.txt" | where {$_ -match "1118"}
	$windanalysis | out-file "$p\Windows Defender Analysis\WinDefender results.txt"
	$windanalysis = select-object "$p\Windows Defender Analysis\WinDefender Dump.txt" | where {$_ -match "1119"}
	$windanalysis | out-file "$p\Windows Defender Analysis\WinDefender results.txt"
	$windanalysis = select-object "$p\Windows Defender Analysis\WinDefender Dump.txt" | where {$_ -match "5001"}
	$windanalysis | out-file "$p\Windows Defender Analysis\WinDefender results.txt"
	write-host "Analysis of Windows Defender Logs Completed!" -foregroundcolor "green"
	write-host "------------------------------RESULTS-------------------------------------" 
	$windresult = get-content "$p\Windows Defender Analysis\WinDefender results.txt"
	write-host $windresult
	write-host "--------------------------------END---------------------------------------" 
}

if ($wDt){
	$threats = get-MPThreatDetection | format-table -wrap -auto
	$threats | out-file "$p\WinDefender Threats.txt"
	write-host "Dumping Windows Defender Threats Results into $p\WinDefender Threats.txt ........."
	write-host "-------------------------------------------------------------------------"
	write-host "Extraction of threats detected by Windows Defender successful!" -foregroundcolor "green"
	write-host "------------------------------RESULTS-------------------------------------" 
	get-content "$p\WinDefender Threats.txt"
	write-host "--------------------------------END---------------------------------------" 
}

if ($nA){break}
else{
	.\parseRuleset.ps1
}