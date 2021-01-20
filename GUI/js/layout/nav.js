
var ctxHelper = context.helper();

// Display Side Bar
var sideHomeCtx = ctxHelper.genSideItemCtx("side-home", "Home", "fas fa-tachometer-alt active");
var sideCaseCtx = ctxHelper.genSideItemCtx("side-case", "Case Generation", "fas fa-memory");
var sideTriageCtx = ctxHelper.genSideItemCtx("side-triage", "Triage Analysis", "fab fa-searchengin");
var sideMalwareCtx = ctxHelper.genSideItemCtx("side-malware", "Malware Heuristics", "fas fa-biohazard");
var sideEventCtx = ctxHelper.genSideItemCtx("side-event", "Event Logs Correlator", "fas fa-chart-area");
var sideTechnologiesCtx = ctxHelper.genSideItemCtx("side-technologies", "Technologies Used", "fas fa-question-circle");
var sideAboutCtx = ctxHelper.genSideItemCtx("side-about", "About Us", "fas fa-user-secret");
var sideReviewCtx = ctxHelper.genSideItemCtx("side-review", "Review Triage", "fas fa-scroll");

var sideMenuCtx = [
	sideHomeCtx,
	ctxHelper.genSideDividerCtx(),
	ctxHelper.genSideSubHeaderCtx("Triage"),
	sideCaseCtx,
	sideTriageCtx,
	ctxHelper.genSideDividerCtx(),
	ctxHelper.genSideSubHeaderCtx("Analysis"),
	sideMalwareCtx,
	sideEventCtx,
	ctxHelper.genSideDividerCtx(),
	ctxHelper.genSideSubHeaderCtx("Review"),
	sideReviewCtx,
	ctxHelper.genSideDividerCtx(),
	ctxHelper.genSideSubHeaderCtx("Misc"),
	sideTechnologiesCtx,
	sideAboutCtx
];