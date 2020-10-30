<#
    This is for analysis, to be done on workstation to preserve
    integrity of the compromised machine.
    
    working directory: cd to inside welt

    Analysis include:
        - Security 

#>

<#

param(
	[Parameter(Mandatory=$true)][string]$n     # case name/number
    [Parameter(Mandatory=$true)][string]$f     # path of dumped logs
)
#>

# for testing, remove from final. $n = folder to store results in, $evtxdump = .evtx dump absolute path (aft bashbunny dump)

$evtxdump = $args[0] # full path of the evtx file


$casefile = "output"
# if not created, create
if (!(test-path ".\$casefile")){
		new-item -type directory -Path ".\$casefile"
        "Logs", "Analysis" | % {New-Item -Name ".\$casefile\$_" -type directory}

		write-host "Logs folder is created successfully!" -foregroundcolor "green"
		write-host "Analysis folder is created successfully!" -foregroundcolor "green"
		write-host "-------------------------------------------------------------------------"
}

python .\python-evtx-master\scripts\evtx_dump.py $evtxdump > .\$casefile\Logs\Security.xml
write-host "Convertion of Security logs into .xml format for analaysis has completed!" -foregroundcolor "green"

[xml]$rules = get-content "WELTrules.xml"
$ruleNodes = $rules.SelectNodes("/xml/ruleset/rules/rule")

[xml]$evdump = get-content .\$casefile\Logs\Security.xml | % { $_.replace('version="1.1"','version="1.0"') }
$nodes = $evdump.Events.Event


foreach ($ruleNode in $ruleNodes){ # for each rule

    $rulename = $ruleNode.rulename
    $ruledesc = $ruleNode.ruledesc

    $triggerRID = $ruleNode.trigger.getAttribute("rid")
    $triggerEVs = $ruleNode.trigger.triggerEv
    
    $EventANDArray = New-Object System.Collections.ArrayList
    $TriggerANDArray = New-Object System.Collections.ArrayList

    $EventSEQArray = New-Object System.Collections.ArrayList
    $TriggerSEQArray = New-Object System.Collections.ArrayList

    write-host "Analysing Logs for: $rulename...."

    # making Array to hold all "AND" triggers
    foreach($triggerEV in $triggerEVs){
        $triggerEvEventID = $triggerEV.EventID
        $triggerEvOperator = $triggerEv.getAttribute("operator")
        if($triggerEvOperator -eq "AND") {
            $TriggerANDArray.Add($triggerEvEventID) > $null
        }
        if($TriggerEvOperator -eq "SEQ") {
            $TriggerSEQArray.Add($triggerEvEventID) > $null
        }
    }


    foreach($triggerEV in $triggerEVs){ # for each trigger
        
        $triggerEvEventID = $triggerEV.EventID
        $triggerEvOperator = $triggerEv.getAttribute("operator")
        $triggerEvID = $triggerEv.getAttribute("id") #?
        $triggerEvSource = $triggerEv.source
               

        if($triggerEvOperator -eq "EQ"){ Invoke-Expression .\operators\EQ.ps1 }
        if($triggerEvOperator -eq "RP"){ Invoke-Expression .\operators\RP.ps1 }
        if($triggerEvOperator -eq "OR"){ Invoke-Expression .\operators\OR.ps1 }
        if($triggerEvOperator -eq "AND"){ Invoke-Expression .\operators\AND.ps1 }
        if($triggerEvOperator -eq "SEQ"){ Invoke-Expression .\operators\SEQ.ps1 }
    
    }
    
    write-host "Completed." -ForegroundColor Green
}
