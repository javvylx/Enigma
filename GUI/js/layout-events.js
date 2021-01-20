$('#row-home').html(HTML(dashboardCtxs));
$(HTML(sideMenuCtx)).insertAfter('#first-boarder');

// 1
$('#row-volatility').html(HTML([volatiltiyInstructionsCtx, volatilityRequiredCaseNameCtx, volatilityRequiredRamDumpCtx]));

// 2
$('#row-triage').html(HTML([triageInstructionsCtx, triageFunctionsDescCtx, triageRequiredInputCtx, triageResultsPanelCtx]));

// 3
$('#row-malware').html(HTML([malwareFunctionsCtx, malwareRequiredInputCtx, malwareResultsPanelCtx]));

$('#row-event').html(HTML([evtInstructionsCtx, evtRequiredInputCtx, evtResultsPanelCtx]));

$('#row-review').html(HTML([reviewInstructionsCtx, reviewRequiredCaseFolderCtx, reviewResultsPanelCtx]));

$("#row-technologies").html(HTML([techInfoBashBunnyCtx, techInfoPythonCtx, techInfoTensorFlowCtx, techInfoVolatilityCtx, techInfoSeleniumCtx, techInfoJqueryCtx, techInfoBootstrapCtx, techInfoPowershellCtx]));

$("#row-about").html(HTML([aboutIntroCtx, aboutPeopleCtx]));
