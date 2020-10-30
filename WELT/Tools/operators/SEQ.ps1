<#
    For rules with SEQ operator
#>
[bool]$verifySEQ = $false


foreach($node in $nodes)
{
	$evid = $node.System.EventID.get_InnerXml()
    $time = $node.System.TimeCreated.SystemTime
    $evrid = $node.System.EventRecordID

	if($triggerEvOperator -eq "SEQ" -and $triggerEvEventID -eq $evid -and $EventSEQArray -notcontains $evid) {
    	$EventSEQArray.Add("$evid") > $null
	}

    if ($TriggerSEQArray.count -eq $EventSEQArray.count){
        
        for($i=0; $i -lt $TriggerSEQArray.count; $i++) {
	        if($EventSEQArray[$i] -eq $TriggerSEQArray[$i]) {
		        $verifySEQ = $true
	        }
	        else {
		        $verifySEQ = $false
		        break
	        }
        }
        if($verifySEQ -eq $true) {
			$output = '{
	"RuleTriggered: "'+$triggerRID+'",
	"RuleName: "'+$rulename+'",
	"EventIDs: "'+$EventSEQArray+'",
	"LastTimestamp: "'+$time+'",
	"LastEventRecordID: "'+$evrid+'",
	"Description: "'+$ruledesc+'",
	}'
		Add-content ".\WELT\Tools\$casefile\Analysis\Security_Analysis.json" $output
            $EventSEQArray.clear()
        }
    }
} 