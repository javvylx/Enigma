var reviewInstructionsCtx = ctxHelper.genPageIntroCardCtx("Instructions", "fas fa-info-circle", [
	ctxHelper.genParaCtx("Browse to the case folder and click execute", "", "")
]);


var reviewRequiredCaseFolderCtx = ctxHelper.genFileSelectCtx("review-card-select-file",
	"Choose your case file",
	"review-input-file",
	"Choose file...",
	"FOLDER",
	"review-btn-dump",
	"Review case",
	"fas fa-play", //Icon Picture
	"info" //Style
);



var reviewResultsMetaNameCtx = 
	ctxHelper.genNoImageCardCtx("review-result-meta-name", // card ID
			"col-xl-6 col-lg-6 col-md-6 review-results-card mt-3", //gridClass
			"py-0", //colorStyle
			"border-bottom-info", //hoverStyle
			"Name", //title
			"review-result-meta-name-label", //descId
			"ICTNYP-NB17");

// genNoImageCardCtx(cardId, gridClass, colorStyle, hoverStyle, title, descId, desc) {
var reviewResultsMetaImageDateCtx = 
	ctxHelper.genNoImageCardCtx("review-result-meta-datetime", // card ID
		"col-xl-6 col-lg-6 col-md-6 review-results-card mt-3", //gridClass
		"py-0", //colorStyle
		"border-bottom-info", //hoverStyle
		"Image DateTime", //title
		"review-result-meta-datetime-label", //descId
		"2020-10-27 12:49:25 UTC+0000");

var reviewResultsMetaModelCtx = 
	ctxHelper.genNoImageCardCtx("review-result-meta-model", // card ID
			"col-xl-6 col-lg-6 col-md-6 review-results-card mt-3", //gridClass
			"py-0", //colorStyle
			"border-bottom-info", //hoverStyle
			"Model", //title
			"review-result-meta-model-label", //descId
			"Latitude 5590");

var reviewResultsMetaManufacturerCtx = 
		ctxHelper.genNoImageCardCtx("review-result-meta-manufacturer", // card ID
				"col-xl-6 col-lg-6 col-md-6 review-results-card mt-3", //gridClass
				"py-0", //colorStyle
				"border-bottom-info", //hoverStyle
				"Manufacturer", //title
				"review-result-meta-manufacturer-label", //descId
				"Dell Inc.");



// Name ImgDateTime Model Manufacturer 
// Rewview onwards from here
// 
// 
// 

var reviewResultProcessCountCtx = 
	ctxHelper.genReviewCardCtx("review-result-process-info", // card ID
		"col-xl-6 col-lg-6 col-md-6 review-results-card mt-3", 
		"border-bottom-primary", 
		"", 
		"Number of Processes", 
		"review-process-info-label", 
		"101 "+ "Processes running", 
		"fa-3x fas fa-microchip");

var reviewResultDomainResultsCtx = 
	ctxHelper.genReviewCardCtx("review-result-domain-info", // card ID
		"col-xl-6 col-lg-6 col-md-6 review-results-card mt-3", 
		"border-bottom-primary", 
		"", 
		"Domains/IPS Found", 
		"review-domain-info-label", 
		"3 "+ "IP Addresses Found", 
		"fa-3x fas fa-server");

var reviewResultMalignFilesCtx = 
	ctxHelper.genReviewCardCtx("review-result-malign-files-info", // card ID
		"col-xl-6 col-lg-6 col-md-6 review-results-card mt-3", 
		"border-bottom-danger", 
		"", 
		"Number of Malign Files", 
		"review-malign-files-info-label", 
		"3 out of 200 are flagged", 
		"fa-3x fas fa-viruses");

var reviewResultMalignEventsCtx = 
	ctxHelper.genReviewCardCtx("review-result-malign-events-info", // card ID
		"col-xl-6 col-lg-6 col-md-6 review-results-card mt-3", 
		"border-bottom-danger", 
		"", 
		"Flagged Events", 
		"review-malign-events-info-label", 
		"2 suspicious events found", 
		"fa-3x fas fa-viruses");


var reviewResultPstreeResultsCtx = ctxHelper.genTableWithDivCtx("review-pstree-table-div", 
	"review-pstree-inner-div", 
	"review-pstree-table",
	'Process Tree results',
	["Name", "PID", "PPID", "Threads", "Handles", "Time"],
	[
		["Name", "PID", "PPID", "Threads", "Handles", "Time"]
	]);

// console.log(HTML(reviewResultPstreeResultsCtx));


var reviewResultWhoIsResultsCtx = ctxHelper.genTableWithDivCtx("review-whois-table-div", 
	"review-whois-inner-div", 
	"review-whois-table", 
	'WhoIsDomain Lookup for IP Addresses', 
	["IP", "Organisation", "HostName", "ISP", "Continent", "Country", "State/Region", "City"],
	[
		["IP", "Organisation", "HostName", "ISP", "Continent", "Country", "State/Region", "City"]
		// ["IP Address", "Org" "Security.evtx", "15", "Your mother v cute"],
		// ["Sunday 2359", "Security.evtx", "15", "Jerome so cute wow hehe"],
	]);


var reviewResultEvtTableCtx = ctxHelper.genTableWithDivCtx("review-evt-table-div", 
	"review-evt-inner-div", 
	"review-evt-table", 
	'Event Logs Analysis', 
	['RuleTriggered', 'RuleName', 'EventID', 'Timestamp', 'EventRecordID', 'Description', 'IPAddress'],
	[
		['RuleTriggered', 'RuleName', 'EventID', 'Timestamp', 'EventRecordID', 'Description', 'IPAddress']
	]);

var reviewResultsExesTableCtx = ctxHelper.genTableWithDivCtx("review-exes-table-div", 
	"review-exes-inner-div", 
	"review-exes-table", 
	'Executables', 
	["File Name", "MD5", "SHA1", "VirusTotal", "Heuristics Indicators", "Tensorflow Model"],
	[
		["JeromeNoodes", "SHA1", "HashYourDaddy", "30/60", "1/20", "73.5%"],
		["JeromeNoodes1", "SHA1", "HashYourDaddy2", "30/60", "1/20", "73.5%"]
	]);

var reviewResultsDllTableCtx = ctxHelper.genTableWithDivCtx("review-dlls-table-div", 
	"review-dlls-inner-div", 
	"review-dlls-table", 
	'Dynamic Linking Libraries (DLLs)', 
	["File Name", "MD5", "SHA1", "VirusTotal", "Heuristics Indicators", "Tensorflow Model"],
	[
		["JeromeNoodes", "SHA1", "HashYourDaddy", "30/60", "1/20", "73.5%"],
		["JeromeNoodes1","SHA1", "hashYourDaddy2", "30/60", "1/20", "73.5%"]
	]);

var reviewResultsPanelCtx = ['div', {id:'res-review-panel', class: 'col-xl-12 col-md-12 mb-4 results-container'} ,
	['div', {class: 'card'},
		ctxHelper.genCardHeaderCtx("Results",
			"m-0 font-weight-bold text-secondary", 
			"ml-2 fa-1x fas fas fa-chart-bar"),
		['div', {class: 'card-body row'},
			reviewResultsMetaNameCtx,
			reviewResultsMetaImageDateCtx,
			reviewResultsMetaModelCtx,
			reviewResultsMetaManufacturerCtx,

			reviewResultProcessCountCtx,
			reviewResultDomainResultsCtx,
			
			reviewResultMalignFilesCtx,
			reviewResultMalignEventsCtx,

			//Tables
			reviewResultPstreeResultsCtx,
			reviewResultWhoIsResultsCtx,
			reviewResultsExesTableCtx,
			reviewResultsDllTableCtx,
			reviewResultEvtTableCtx
		]	
	]

];
