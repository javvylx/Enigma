# script.ps1
write-host "----------------------------------------------------------------------------------------"
[xml]$test = get-content "WELTrules.xml"
$nodelist = $test.SelectNodes("/xml/ruleset/rules/rule")
foreach($ruleNode in $nodelist){
    $EventANDArrayList = New-Object System.Collections.ArrayList
    $EventSEQArrayList = New-Object System.Collections.ArrayList
    $RuleSEQArrayList = New-Object System.Collections.ArrayList
    $rulename = $ruleNode.selectSingleNode("rulename").get_InnerXml()
    $ruledesc = $ruleNode.selectSingleNode("ruledesc").get_InnerXml()
    $triggerNode = $ruleNode.selectSingleNode("trigger")
    $triggerRID = $triggerNode.getAttribute("rid")
    $triggerEvNodelist = $triggerNode.selectNodes("triggerEv")
    write-host "Rule Number: $triggerRID"
    write-host "Potential Compromise: $rulename"
    write-host "Desc: $ruledesc"
    write-host "More details on events that trigger this rule is shown below:"
    foreach($triggerEvNodeNode in $triggerEvNodelist){
        $triggerEvOperator = $triggerEvNodeNode.getAttribute("operator")
        $triggerEvID = $triggerEvNodeNode.getAttribute("id")
        $triggerEvEventID = $triggerEvNodeNode.selectSingleNode("EventID").get_InnerXml()
        $triggerEvSource = $triggerEvNodeNode.selectSingleNode("Source").get_InnerXml()
        write-host "Trigger Event number is $triggerEvID"
        write-host "Trigger Event Operator is $triggerEvOperator"
        write-host "ID of the Event that triggers alert is $triggerEvEventID"
        write-host "Source of the triggerEv is $triggerEvSource"
        if($triggerEvOperator -eq "EQ"){
            Invoke-Expression operators\EQ.ps1
        }
        if($triggerEvOperator -eq "AND"){
            Invoke-Expression operators\AND.ps1
        }
        if($triggerEvOperator -eq "SEQ"){
            Invoke-Expression operators\SEQ.ps1
        }
        if($triggerEvOperator -eq "RP"){
            Invoke-Expression operators\RP.ps1
        }
        if($triggerEvOperator -eq "OR"){
            Invoke-Expression operators\OR.ps1
        }
    }
write-host "End of rule $triggerRID"
write-host "----------------------------------------------------------------------------------------"
}