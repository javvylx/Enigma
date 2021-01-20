



var triageInstructionsCtx = ctxHelper.genPageIntroCardCtx("Instructions", "fas fa-info-circle", [
	ctxHelper.genParaCtx("Fill in case name & choose folder location to dump analysis output", "", "")
]);



var triageFunctionsDescCtx = ctxHelper.genPageIntroCardCtx("Functionalities", "fas fa-atom", [
	ctxHelper.genParaCtx("The whole triage process covers the following ", "h4 col-12 mb-5" ),
	ctxHelper.genTriageCardCtx("triage-func-process", "col-xl-4 col-lg-6 col-md-6 triage-desc-card", "border-bottom-success", "", "Processes", "triage-func-process-label", "", "fa-2x fas fa-microchip"),
	ctxHelper.genTriageCardCtx("triage-func-files", "col-xl-4 col-lg-6 col-md-6 triage-desc-card", "border-bottom-success", "", "Files", "triage-func-files-label", "", "fa-2x fas fa-file-alt"),

	ctxHelper.genTriageCardCtx("triage-func-domains", "col-xl-4 col-lg-6 col-md-6 triage-desc-card", "border-bottom-success", "", "Domains", "triage-func-domains-label", "", "fa-2x fas fa-server"),
	ctxHelper.genTriageCardCtx("triage-func-malware", "col-xl-4 col-lg-6 col-md-6 triage-desc-card", "border-bottom-success", "", "Malware", "triage-func-malware-label", "", "fa-2x fas fa-biohazard icon-cog"),
	ctxHelper.genTriageCardCtx("triage-func-logs-analysis", "col-xl-4 col-lg-6 col-md-6 triage-desc-card", "border-bottom-success", "", "Logs-Analysis", "triage-func-logs-analysis-label", "", "fa-2x fas fa-chart-area"),
	
	
	ctxHelper.genTriageCardCtx("triage-func-virustotal", "col-xl-4 col-lg-6 col-md-6 triage-desc-card", "border-bottom-success", "", "Virustotal", "triage-func-virustotal-label", "", "fa-2x fas fa-viruses")],
	"row"
);


var triageRequiredFieldsCtx = ctxHelper.genRequiredTextCtx('trigage-card-input-fields',
	'Please fill in the required fields',
	'triage-card-input-case-name', //Try impv to put list and handle it
	'Case name', 
	'info');

var triageRequiredInputCtx = ctxHelper.genFileSelectCtx("triage-card-select_dump_folder",
	"Choose your case folder",
	"triage-dump-folder",
	"Choose folder...",
	"FILE",
	"triage-dump-run",
	"Execute analysis",
	"fas fa-play",
	"info"
);


var triageResultsSaveButtonCtx = []

var triageResultsMetaNameCtx = 
	ctxHelper.genNoImageCardCtx("triage-result-meta-name", // card ID
			"col-xl-6 col-lg-6 col-md-6 triage-results-card mt-3", //gridClass
			"py-0", //colorStyle
			"border-bottom-info", //hoverStyle
			"Name", //title
			"triage-result-meta-name-label", //descId
			"ICTNYP-NB17");

// genNoImageCardCtx(cardId, gridClass, colorStyle, hoverStyle, title, descId, desc) {
var triageResultsMetaImageDateCtx = 
	ctxHelper.genNoImageCardCtx("triage-result-meta-datetime", // card ID
		"col-xl-6 col-lg-6 col-md-6 triage-results-card mt-3", //gridClass
		"py-0", //colorStyle
		"border-bottom-info", //hoverStyle
		"Image DateTime", //title
		"triage-result-meta-datetime-label", //descId
		"2020-10-27 12:49:25 UTC+0000");

var triageResultsMetaModelCtx = 
	ctxHelper.genNoImageCardCtx("triage-result-meta-model", // card ID
			"col-xl-6 col-lg-6 col-md-6 triage-results-card mt-3", //gridClass
			"py-0", //colorStyle
			"border-bottom-info", //hoverStyle
			"Model", //title
			"triage-result-meta-model-label", //descId
			"Latitude 5590");

var triageResultsMetaManufacturerCtx = 
	ctxHelper.genNoImageCardCtx("triage-result-meta-manufacturer", // card ID
			"col-xl-6 col-lg-6 col-md-6 triage-results-card mt-3", //gridClass
			"py-0", //colorStyle
			"border-bottom-info", //hoverStyle
			"Manufacturer", //title
			"triage-result-meta-manufacturer-label", //descId
			"Dell Inc.");



// Name ImgDateTime Model Manufacturer 
var triageResultProcessCountCtx = 
	ctxHelper.genTriageCardCtx("triage-result-process-info", // card ID
		"col-xl-6 col-lg-6 col-md-6 triage-results-card mt-3", 
		"border-bottom-primary", 
		"", 
		"Number of Processes", 
		"triage-process-info-label", 
		"101 "+ "Processes running", 
		"fa-3x fas fa-microchip");

var triageResultDomainResultsCtx = 
	ctxHelper.genTriageCardCtx("triage-result-domain-info", // card ID
		"col-xl-6 col-lg-6 col-md-6 triage-results-card mt-3", 
		"border-bottom-primary", 
		"", 
		"Domains/IPS Found", 
		"triage-domain-info-label", 
		"3 "+ "IP Addresses Found", 
		"fa-3x fas fa-server");

var triageResultMalignFilesCtx = 
	ctxHelper.genTriageCardCtx("triage-result-malign-files-info", // card ID
		"col-xl-6 col-lg-6 col-md-6 triage-results-card mt-3", 
		"border-bottom-danger", 
		"", 
		"Number of Malign/suspicious Files", 
		"triage-malign-files-info-label", 
		"3 out of 200 are flagged", 
		"fa-3x fas fa-viruses");

var triageResultMalignEventsCtx = 
	ctxHelper.genTriageCardCtx("triage-result-malign-events-info", // card ID
		"col-xl-6 col-lg-6 col-md-6 triage-results-card mt-3", 
		"border-bottom-danger", 
		"", 
		"Flagged Events", 
		"triage-malign-events-info-label", 
		"2 suspicious events found", 
		"fa-3x fas fa-viruses");


var triageResultPstreeResultsCtx = ctxHelper.genTableWithDivCtx("triage-pstree-table-div", 
	"triage-pstree-inner-div", 
	"triage-pstree-table",
	'Process Tree results',
	["Name", "PID", "PPID", "Threads", "Handles", "Time"],
	[
		["Name", "PID", "PPID", "Threads", "Handles", "Time"]
	]);

console.log(HTML(triageResultPstreeResultsCtx));

var triageResultWhoIsResultsCtx = ctxHelper.genTableWithDivCtx("triage-whois-table-div", 
	"triage-whois-inner-div", 
	"triage-whois-table", 
	'WhoIsDomain Lookup for IP Addresses', 
	["IP", "Organisation", "HostName", "ISP", "Continent", "Country", "State/Region", "City"],
	[
		["IP", "Organisation", "HostName", "ISP", "Continent", "Country", "State/Region", "City"]
		// ["IP Address", "Org" "Security.evtx", "15", "Your mother v cute"],
		// ["Sunday 2359", "Security.evtx", "15", "Jerome so cute wow hehe"],
	]);



var triageResultEvtTableCtx = ctxHelper.genTableWithDivCtx("triage-evt-table-div", 
	"triage-evt-inner-div", 
	"triage-evt-table", 
	'Event Logs Analysis', 
	['RuleTriggered', 'RuleName', 'EventID', 'Timestamp', 'EventRecordID', 'Description', 'IPAddress'],
	[
		['RuleTriggered', 'RuleName', 'EventID', 'Timestamp', 'EventRecordID', 'Description', 'IPAddress']
	]);

var triageResultsExesTableCtx = ctxHelper.genTableWithDivCtx("triage-exes-table-div", 
	"triage-exes-inner-div", 
	"triage-exes-table", 
	'Executables', 
	["File Name", "MD5", "SHA1", "VirusTotal", "Heuristics Indicators", "Tensorflow Model"],
	[
		["JeromeNoodes", "SHA1", "HashYourDaddy", "30/60", "1/20", "73.5%"],
		["JeromeNoodes1", "SHA1", "HashYourDaddy2", "30/60", "1/20", "73.5%"]
	]);

var triageResultsDllTableCtx = ctxHelper.genTableWithDivCtx("triage-dlls-table-div", 
	"triage-dlls-inner-div", 
	"triage-dlls-table", 
	'Dynamic Linking Libraries (DLLs)', 
	["File Name", "MD5", "SHA1", "VirusTotal", "Heuristics Indicators", "Tensorflow Model"],
	[
		["JeromeNoodes", "SHA1", "HashYourDaddy", "30/60", "1/20", "73.5%"],
		["JeromeNoodes1","SHA1", "hashYourDaddy2", "30/60", "1/20", "73.5%"]
	]);



var triageResultsPanelCtx = ['div', {id:'res-triage-panel', class: 'col-xl-12 col-md-12 mb-4 results-container'} ,
	['div', {class: 'card'},
		ctxHelper.genCardHeaderWithEleCtx("Results",
			"m-0 font-weight-bold text-secondary", 
			"ml-2 fa-1x fas fas fa-chart-bar",
			['a', {id: 'res-triage-save-btn', class: 'float-right btn-sm btn-success btn-icon-split'},
				['span', {class: 'icon text-white-50'},
					['i', {class: 'fas fa-save'}]
				],
				['span', {class: 'text btn-white'}, 'Save triage results']
			]),
			['div', {class: 'card-body row'},
				triageResultsMetaNameCtx,
				triageResultsMetaImageDateCtx,
				triageResultsMetaModelCtx,
				triageResultsMetaManufacturerCtx,

				triageResultProcessCountCtx,
				triageResultDomainResultsCtx,
				
				triageResultMalignFilesCtx,
				triageResultMalignEventsCtx,

				//Tables
				triageResultPstreeResultsCtx,			
				triageResultWhoIsResultsCtx,					
				triageResultsExesTableCtx,
				triageResultsDllTableCtx,
				triageResultEvtTableCtx
			]	

	]

];

