<#

    EQ OPERATOR: evid XXX == rule evid XXX
	-ne 22 cos of RDP.

#>
foreach($node in $nodes){
    $evid = $node.System.EventID.get_innerxml()
    $evrid = $node.System.EventRecordID
    if ($triggerRID -ne 22){
        
        if ($evid -eq $triggerEvEventID){
            $time = $node.System.TimeCreated.SystemTime
            write-host "$triggerEvEventID matched!" -foregroundcolor "red"
		    $output = '{
	"RuleTriggered: "'+$triggerRID+'",
	"RuleName: "'+$rulename+'",
	"EventID: "'+$evid+'",
	"Timestamp: "'+$time+'",
	"EventRecordID: "'+$evrid+'",
	"Description: "'+$ruledesc+'",
	}'
		Add-content "$casefile\Analysis\Security_Analysis.json" $output
        }
    }

    else{
        if ($evid -eq $triggerEvEventID){
            $evid = $node.System.EventID.get_innerxml()
            $evrid = $node.System.EventRecordID
            $time = $node.System.TimeCreated.SystemTime
			$Ltype = $node.EventData.Data | Where-Object {$_.Name -eq "LogonType"}
			$Ltype = $Ltype.get_innerxml()
			if ($Ltype -eq 10){
				$Ip = $node.EventData.Data | Where-Object {$_.Name -eq "IpAddress"}
				$Ip = $Ip.get_innerxml()
				
				write-host "$triggerEvEventID matched!" -foregroundcolor "red"
				$output = '{
	"RuleTriggered: "'+$triggerRID+'",
	"RuleName: "'+$rulename+'",
	"EventID: "'+$evid+'",
	"Timestamp: "'+$time+'",
	"EventRecordID: "'+$evrid+'",
	"Description: "'+$ruledesc+'",
	"IPAddress: "'+$Ip+'",
	}'
			Add-content "$casefile\Analysis\Security_Analysis.json" $output
        }
    }
}
}