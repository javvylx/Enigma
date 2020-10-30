<#
    REPEATED FAILED LOG IN EVENTS BRUTE FORCE
#>


$count = 0
foreach($node in $nodes)
{
	$evid = $node.System.EventID.get_InnerXml()
    $time = $node.System.TimeCreated.SystemTime
    $evrid = $node.System.EventRecordID

	if($evid -eq $triggerEvEventID -and $triggerEvOperator -eq "RP")
		{
			$count++
			if($count -ge 3 -and $triggerEvEventID -eq $evid)
				{
					write-host "Multiple occurences of $evid found!" -foregroundcolor "darkyellow"
		            $output = '{
	"RuleTriggered: "'+$triggerRID+'",
	"RuleName: "'+$rulename+'",
	"EventID: "'+$evid+'",
	"Timestamp: "'+$time+'",
	"EventRecordID: "'+$evrid+'",
	"Description: "'+$ruledesc+'",
	}'
		Add-content ".\WELT\Tools\$casefile\Analysis\Security_Analysis.json" $output
				}
		}

}
