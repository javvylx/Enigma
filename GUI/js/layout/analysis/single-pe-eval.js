var malwareFunctionsCtx = ctxHelper.genPageIntroCardCtx("Functions", "fas fa-atom", [
	ctxHelper.genParaCtx("This module analyses Portable Executables (PE) files in several aspect", "fa-2x h4 col-12 mb-5" ),
	ctxHelper.genMalwareCardCtx("malware-func-heuristics", "col-xl-3 col-lg-6 col-md-6 triage-desc-card", "border-bottom-primary", "", "Heuristics", "malware-func-heuristics-label", "", "fa-2x fas fa-viruses"),
	ctxHelper.genMalwareCardCtx("malware-func-entropy", "col-xl-3 col-lg-6 col-md-6 triage-desc-card", "border-bottom-primary", "", "Entropy", "malware-func-entropy-label", "", "fa-2x fas fa-sort-numeric-up-alt"),
	ctxHelper.genMalwareCardCtx("malware-func-imports", "col-xl-3 col-lg-6 col-md-6 triage-desc-card", "border-bottom-primary", "", "Functions", "malware-func-imports-label", "", "fa-2x fas fa-file-import"),
	ctxHelper.genMalwareCardCtx("malware-func-ml", "col-xl-3 col-lg-6 col-md-6 triage-desc-card", "border-bottom-primary", "", "ML", "malware-func-ml-label", "", "fa-2x fas fa-robot")],
	"row"
);

var malwareRequiredInputCtx = ctxHelper.genFileSelectCtx("malware-card-select-file",
	"Choose your PE file to analyse",
	"malware-input-file",
	"Choose file...",
	"FILE",
	"malware-btn-run",
	"Execute analysis",
	"fas fa-play",
	"info"
);


var malwareResultsHeuristicsCardCtx = ctxHelper.genMalwareDescCardCtx('malware-single-heuristics-info', 
	"col-xl-6 col-md-6 col-sm-12 col-12 justify-content-center",
	"col-xl-6 col-md-6 col-sm-12 col-12 justify-content-center",

	"primary",
	"",
	['div', {class: 'row no-gutters align-items-center'},
		['div', {class: 'col mr-2'},
			['div',{class: 'text-xl font-weight-bold text-primary text-uppercase mb-1'}, "Heuristics"],
			['div', {id:'res-malware-single-heuristics-score', class: 'h5 mb-0 font-weight-bold text-gray-800'}, "2 / 31 "]
		],
		['div', {class: 'col-auto'}, 
			['i' , {class: 'fas fa-viruses fa-6x text-gray-300'}]
		]
		
	]);


var malwareResultHeuristicsScoreCtx = 
	ctxHelper.genMalwareCardCtx("malware-single-heuristics-info", // card ID
		"col-xl-6 col-lg-6 col-md-6 malware-results-card mt-3", 
		"border-left-primary", 
		"", 
		"Heuristics Score", 
		"malware-single-heuristics-info-label", 
		"2 / 23", 
		"fa-3x fas fa-viruses");

var malwareResultMLPredictionScoreCtx =
	ctxHelper.genMalwareCardCtx("malware-single-ml-score", 
		"col-xl-6 col-lg-6 col-md-6 malware-results-card mt-3", 
		"border-left-primary", 
		"", 
		"ML Prediction", 
		"malware-single-ml-score-label", 
		"60 %", 
		"fa-3x fas fa-robot"); 

var malwareResultImportsTableCtx = ctxHelper.genTableWithDivCtx("malware-single-Imports-table-div", 
	"malware-single-Imports-inner-div", 
	"malware-single-Imports-table", 
	'Imports Analysis', 
	["API", "Functions"],
	[
		["API", "Functions"]
	]);

var malwareResultEntropyTableCtx = ctxHelper.genTableWithDivCtx("malware-single-sections-table-div", 
	"malware-single-entropy-inner-div", 
	"malware-single-sections-table", 
	'PE Section Details', 
	["Name", "Entropy", "VirtualAddress", "Misc_VirtualSize", "SizeOfRawData", "Characteristics"],
	[
		["Name", "Entropy", "VirtualAddress", "Misc_VirtualSize", "SizeOfRawData", "Characteristics"]
	]);

var malwareResultEntropyDetailsCtx = ctxHelper.genMalwareDescCardCtx('malware-single-section-details', 
	'col-xl-12 col-lg-12 col-md-6 malware-results-card', 
	'border-bottom-primary', 
	"", //hoverStyle
	''); //Put table here


// Put into results panel
var malwareResultsPanelCtx = ['div', {id:'res-malware-single-panel', class: 'col-xl-12 col-md-12 mb-4 results-container'} ,
	['div', {class: 'card '},
		ctxHelper.genCardHeaderCtx("Results",
		"m-0 font-weight-bold text-secondary", 
		"ml-2 fa-1x fas fas fa-chart-bar"),
		['div', {class: 'card-body row'},
		// ['div', {class: 'card-header py-3'}]
			malwareResultHeuristicsScoreCtx,
			
			malwareResultMLPredictionScoreCtx,
			malwareResultImportsTableCtx,
			malwareResultEntropyTableCtx
		]

	]

];

