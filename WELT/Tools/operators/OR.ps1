<#
    evid XXX or evid YYY in dump.
#>


foreach($node in $nodes)
{
    $evid = $node.System.EventID.get_InnerXml()
    $time = $node.System.TimeCreated.SystemTime
    $evrid = $node.System.EventRecordID

    if($triggerEvOperator -eq "OR" -and $triggerEvEventID -eq $evid){
	    write-host "$triggerEvEventID found in eventdump!" -foregroundcolor "darkyellow"
	    $output = '{
	"RuleTriggered" : "'+$triggerRID+'",
	"RuleName" : "'+$rulename+'",
	"EventID" : "'+$evid+'",
	"Timestamp" : "'+$time+'",
	"EventRecordID" : "'+$evrid+'",
	"Description" : "'+$ruledesc+'"
	"IPAddress" : "NIL"
	},'
		Add-content ".\WELT\Tools\$casefile\Analysis\Security_Analysis.json" $output
	}

}
