<#
    For rules with AND operator
#>


foreach($node in $nodes)
{
	$evid = $node.System.EventID.get_InnerXml()
	$evrid = $node.System.EventRecordID
    $time = $node.System.TimeCreated.SystemTime
    if($triggerEvOperator -eq "AND" -and $triggerEvEventID -eq $evid -and $EventANDArray -notcontains $evid){
        $EventANDArray.Add($evid) > $null
    }
    
    if ((compare-object $EventANDArray $TriggerANDArray -SyncWindow 0).Length -eq 0){
		$output = '{
	"RuleTriggered" : "'+$triggerRID+'",
	"RuleName" : "'+$rulename+'",
	"EventIDs" : "'+$EventANDArray+'",
	"LastTimestamp" : "'+$time+'",
	"LastEventRecordID" : "'+$evrid+'",
	"Description" : "'+$ruledesc+'"
	}'
		Add-content ".\WELT\Tools\$casefile\Analysis\Security_Analysis.json" $output
        $EventANDArray.clear()
    }
}


