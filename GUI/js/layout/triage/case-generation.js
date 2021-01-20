

var caseInstructionsCtx = ctxHelper.genPageIntroCardCtx("Instructions", "fas fa-info-circle", [
	ctxHelper.genParaCtx("Fill in case name & choose folder location to dump analysis output", "", "")
]);


var caseRequiredCaseNameCtx = ctxHelper.genRequiredTextCtx('volatility-card-input-fields',
	'Please fill in the required fields',
	'volatility-card-input-case-name', //Try impv to put list and handle it
	'Case name',
	'info');


var caseRequiredInputCtx = ctxHelper.genFileSelectCtx("volatility-card-select-file",
	"Choose your dump RAM file",
	"volatility-input-file",
	"Choose file...",
	"FILE",
	"volatility-btn-dump",
	"Execute Dump",
	"fas fa-play",
	"info"
);

var caseRequiredRamDumpCtx = ['div', {class: 'col-xl-12 col-md-12 mb-4'},
	['div', {class: 'card border-left-success shadow h-100 py-3'},
		['div', {class: 'card-body'},
			['div', {class: 'row no-gutters align-items-center'},
				['div', {class: 'col mr-2'},
					['div',{class: 'text-xs font-weight-bold text-info text-uppercase mb-1'}, "Choose your RAM dump file"],
					ctxHelper.genInputSelectorCtx("volatility-ram-dump-input", "Choose file...", "FILE"), 
					ctxHelper.genButtonCtx("volatility-btn-dump", "Execute dump", "fas fa-play", "info")
					// ['div',{class: 'text-xl font-weight-bold text-success text-uppercase mb-1'}, "Available RAM Size"],
					// ['div', {class: 'h2 mb-0 font-weight-bold text-gray-800'}, "32 GB"]
				]
				// ['div', {class: 'col-auto'}, 
				// 	['i' , {class: 'fas fa-memory fa-6x text-gray-300'}]
				// ]
				
			]
		]        
	]
];