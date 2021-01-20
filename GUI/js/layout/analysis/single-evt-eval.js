var evtInstructionsCtx = ctxHelper.genPageIntroCardCtx("Information", "fas fa-info-circle", [
	ctxHelper.genParaCtx("Browse to where your security.evtx file is and click execute.", "", "")
]);

var evtRequiredInputCtx = ctxHelper.genFileSelectCtx("evt-card-select-file",
	"Choose your Windows Log to analyse",
	"evt-input-file",
	"Choose file...",
	"FILE",
	"evt-btn-run",
	"Execute correlation",
	"fas fa-play",
	"info"
);

var evtResultEvtTableCtx = ctxHelper.genTableWithDivCtx("evt-evt-table-div", 
	"evt-evt-inner-div", 
	"evt-evt-table", 
	'Event Logs Analysis', 
	['RuleTriggered', 'RuleName', 'EventID', 'Timestamp', 'EventRecordID', 'Description', 'IPAddress'],
	[
		['RuleTriggered', 'RuleName', 'EventID', 'Timestamp', 'EventRecordID', 'Description', 'IPAddress']
	]);

var evtResultsPanelCtx = ['div', {id:'res-evt-panel', class: 'col-xl-12 col-md-12 mb-4 results-container'} ,
	['div', {class: 'card'},
		ctxHelper.genCardHeaderCtx("Results",
			"m-0 font-weight-bold text-secondary", 
			"ml-2 fa-1x fas fas fa-chart-bar"),
			['div', {class: 'card-body row'},
				evtResultEvtTableCtx
			]	

	]
];