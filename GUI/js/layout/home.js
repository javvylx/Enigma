var arrTitles = {
	"home": "What do you want to do",
	"case": "Case generation",
	"triage": "Automated RAM Analysis",
	"malware": "Malware Heuristics",
	"event": "Windows Logs Correlator",
	"about": "About Us",
	"technologies": "Technologies Used",
	"review": "Review Triage Results"
};

var homevolatilityDumpCtx = ctxHelper.genHomeCardCtx("home-case-card", "col-xl-6 col-md-6 col-sm-12 col-12", "border-bottom-primary", "home-card", "Case Generation", "Parse all case artifacts for triage analysis", "fa-6x fas fa-memory");

var homeTriageCtx = ctxHelper.genHomeCardCtx("home-triage-card", "col-xl-6 col-md-6 col-sm-12 col-12", "border-bottom-success", "home-card", "Triage Analyis", "Conducts full analysis of Volatility with analysis modules", "fa-6x fab fa-searchengin");

var homeMalwareCtx = ctxHelper.genHomeCardCtx("home-malware-card", "col-xl-6 col-md-6 col-sm-12 col-12", "border-bottom-danger", "home-card", "Malware Heuristics", "Classify & identify IOCs of PE file using heuristics", "fa-6x fas fa-biohazard");

var homeEventLogCtx = ctxHelper.genHomeCardCtx("home-event-card", "col-xl-6 col-md-6 col-sm-12 col-12", "border-bottom-danger", "home-card", "Event Logs Correlator", "Identify potential footprints of malwares with event logs", "fa-6x fas fa-chart-area");

var homeReview = ctxHelper.genHomeCardCtx("home-review-card", "col-xl-12 col-md-12 col-sm-12 col-12 pb-3", "border-bottom-info", "home-card", "Triage Review", "Review past Triage analysis results", "fa-6x fas fa-scroll");

var dashboardCtxs = [homevolatilityDumpCtx,homeTriageCtx,homeMalwareCtx,homeEventLogCtx, homeReview];