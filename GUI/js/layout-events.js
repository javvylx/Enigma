
$(function () {
	$('#row-home').html(HTML(dashboardCtxs));
	$(HTML(sideMenuCtx)).insertAfter('#first-boarder');

	// 1
	$('#row-case').html(HTML([caseInstructionsCtx, caseRequiredCaseNameCtx, caseRequiredRamDumpCtx]));

	// 2
	$('#row-triage').html(HTML([triageInstructionsCtx, triageFunctionsDescCtx, triageRequiredInputCtx, triageResultsPanelCtx]));

	// 3
	$('#row-malware').html(HTML([malwareFunctionsCtx, malwareRequiredInputCtx, malwareResultsPanelCtx]));

	$('#row-event').html(HTML([evtInstructionsCtx, evtRequiredInputCtx, evtResultsPanelCtx]));

	$('#row-review').html(HTML([reviewInstructionsCtx, reviewRequiredCaseFolderCtx, reviewResultsPanelCtx]));

	$("#row-technologies").html(HTML([techInfoBashBunnyCtx, techInfoPythonCtx, techInfoTensorFlowCtx, techInfoVolatilityCtx, techInfoSeleniumCtx, techInfoJqueryCtx, techInfoBootstrapCtx, techInfoPowershellCtx]));

	$("#row-about").html(HTML([aboutIntroCtx, aboutPeopleCtx]));


	$("#triage-pstree-table").DataTable({
		'pageLength': 5,
		'lengthMenu': [5,-1],
		'columns' : [
			{"data" : "Name"},
			{"data" : "PID"},
			{"data" : "PPID"},
			{"data" : "Threads"},
			{"data" : "Handles"},
			{"data" : "Time"}
		]
	});

	$("#triage-whois-table").DataTable({
		'pageLength': 5,
		'lengthMenu': [5,10,15,20],
		'columns' : [
			{'data': 'IP'},
			{'data': 'Organisation'},
			{'data': 'HostName'},
			{'data': 'ISP'},
			{'data': 'Continent'},
			{'data': 'Country'},
			{'data': 'State/Region'},
			{'data': 'City'}
		]
	});

	$("#triage-exes-table").DataTable({
		'pageLength': 5,
		'lengthMenu': [5,10,15,20],
		'columns': [
			{'data':'File Name'},
			{'data':'MD5'},
			{'data':'SHA1'},
			{'data':"VirusTotal"},
			{'data':"Heuristics Indicators"},
			{'data':"Tensorflow Model"}
		]
	});

	$("#triage-dlls-table").DataTable({
		'pageLength': 5,
		'lengthMenu': [5,10,15,20],
		'columns': [
			{'data':'File Name'},
			{'data':'MD5'},
			{'data':'SHA1'},
			{'data':"VirusTotal"},
			{'data':"Heuristics Indicators"},
			{'data':"Tensorflow Model"}
		]
	});

	$('#triage-evt-table').DataTable({
		'pageLength':5,
		'columns': [
			{'data' : 'RuleTriggered'},
			{'data' : 'RuleName'},
			{'data' : 'EventID'},
			{'data' : 'Timestamp'},
			{'data' : 'EventRecordID'},
			{'data' : 'Description'},
			{'data' : 'IPAddress'}
		]
	});

	// Malware datatables
	// 
	// 
	// 

	$('#malware-single-Imports-table').DataTable({
		'pageLength':5,
		'columns': [
			{'data' : 'API'},
			{'data' : 'Functions'}
		]
	});

	$('#malware-single-sections-table').DataTable({
		'pageLength':5,
		'columns': [
			{'data': "Name"},
			{'data': "Entropy"},
			{'data': "VirtualAddress"},
			{'data': "Misc_VirtualSize"},
			{'data': "SizeOfRawData"},
			{'data': "Characteristics"}

		]
	});

	// WinEvt Tables
	// 
	// 
	// 
	// 
	$('#evt-evt-table').DataTable({
		'pageLength':5,
		'columns': [
			{'data' : 'RuleTriggered'},
			{'data' : 'RuleName'},
			{'data' : 'EventID'},
			{'data' : 'Timestamp'},
			{'data' : 'EventRecordID'},
			{'data' : 'Description'},
			{'data' : 'IPAddress'}
		]
	});

	// Review datatables
	// 
	// 
	// 
	$("#review-pstree-table").DataTable({
		'pageLength': 5,
		'lengthMenu': [5,-1],
		'columns' : [
			{"data" : "Name"},
			{"data" : "PID"},
			{"data" : "PPID"},
			{"data" : "Threads"},
			{"data" : "Handles"},
			{"data" : "Time"}
		]
	});

	$("#review-whois-table").DataTable({
		'pageLength': 5,
		'lengthMenu': [5,10,15,20],
		'columns' : [
			{'data': 'IP'},
			{'data': 'Organisation'},
			{'data': 'HostName'},
			{'data': 'ISP'},
			{'data': 'Continent'},
			{'data': 'Country'},
			{'data': 'State/Region'},
			{'data': 'City'}
		]
	});

	$("#review-exes-table").DataTable({
		'pageLength': 5,
		'lengthMenu': [5,10,15,20],
		'columns': [
			{'data':'File Name'},
			{'data':'MD5'},
			{'data':'SHA1'},
			{'data':"VirusTotal"},
			{'data':"Heuristics Indicators"},
			{'data':"Tensorflow Model"}
		]
	});

	$("#review-dlls-table").DataTable({
		'pageLength': 5,
		'lengthMenu': [5,10,15,20],
		'columns': [
			{'data':'File Name'},
			{'data':'MD5'},
			{'data':'SHA1'},
			{'data':"VirusTotal"},
			{'data':"Heuristics Indicators"},
			{'data':"Tensorflow Model"}
		]
	});

	$('#review-evt-table').DataTable({
		'pageLength':5,
		'columns': [
			{'data' : 'RuleTriggered'},
			{'data' : 'RuleName'},
			{'data' : 'EventID'},
			{'data' : 'Timestamp'},
			{'data' : 'EventRecordID'},
			{'data' : 'Description'},
			{'data' : 'IPAddress'}
		]
	});



	$('.nav-item').click(function() {

		// Set Sidebar to active then toggle page
		if (!$(this).hasClass('active')) {
			$('.nav-item').removeClass('active');
			$(this).addClass('active');
			
			// Hide all content row first       
			$("#content-header").text(arrTitles[$(this).attr('id').replace("side-", "")]);
			$(".content-row").hide();
			$("#"+$(this).attr('id').replace("side", "content-header")).show()
			$("#" + $(this).attr('id').replace("side", "row")).fadeIn(1000);
			// console.log($(this).attr('id'))
		}		
	});

	$('.home-card').click(function() {
		var cat = $(this).attr('id').split('-')[1];

		if (!$('side-' + cat).hasClass('active')) {
			$('.nav-item').removeClass('active');
			$('#side-' + cat).addClass('active');

			$("#content-header").text(arrTitles[cat]);
			$(".content-row").hide();
			$('#content-header-' + cat).show();
			$("#row-" + cat).fadeIn(1000);
		}
	});
	/* --- End of Toggle Pages --- */

	// --- 1 Volatility analysis events --- //
	$('#case-ram-dump-input').click(function() {
		needsUpdate.volRamDumpInput = true;
		// console.log(needsUpdate.volRamDumpInput);
	});


	window.volRamDumpInputed = function () {
		$('#case-ram-dump-input-label').html(inputFilePaths.ramImage);
		inputFilePaths.ramImage = "";
	};

	window.volFinishedDump = function() {
		volFields.caseName = "";
		volFields.ramFilePath = "";
	}

	$("#case-btn-dump").click(function() {
		volFields.caseName = $('#case-card-input-case-name').val();
		volFields.ramFilePath = $('#case-ram-dump-input-label').html();
		if (volFields.caseName != "") {
			needsUpdate.volExecuteDump = true;
		} else {
			toastr.error("Please input valid case name");
		}	
	})

	// --- End of Volatility analysis events --- //

	$('#triage-dump-folder').click(function(){
		needsUpdate.triageCaseFolderInput = true;
	});


	window.triageFolderInputed = function() {
		$('#triage-dump-folder-label').html(inputFilePaths.triageFolderPath);
		inputFilePaths.triageFolderPath = "";
	}

	window.triageFinishedAnalysis = function() {
		triageFields.caseFolderPath = ""; //Reset triageFields inputs
		console.log(modesResultsData.triage)
		// Update all tables using the modesResultsData['triage']
	}	

	updateTableData = function(tblId, tblHeaders, tblData) {
		console.log(tblData);
		if (tblData != "None" && tblData != "Error") {
			var tbl = $('#'+tblId).DataTable();
			tbl.clear();
			tbl.rows.add(tblData);
			tbl.draw();
		}
	}

	updateResultLabels = function(labelId, text) {
		$('#'+labelId).html(text);
	}

	retrieveTriageJsonResults = function() {
		if (modesResultsData.triage != '') {
			return JSON.stringify(modesResultsData.triage);
		} else {
			return '';
		}
	}

	$('#res-triage-save-btn').click(function() {
		needsUpdate.triageSaveResult = true;
	});

	$('#triage-dump-run').click(function() {
		triageFields.caseFolderPath = $('#triage-dump-folder-label').html();

		console.log(triageFields.caseFolderPath);
		needsUpdate.triageExecuteAnalysis = true;
		
	});

	
	window.exeResultsBatchUpdate = function (t) {

		updateResultLabels(t+"-result-meta-name-label", modesResultsData[t]["ImgName"]);
		updateResultLabels(t+"-result-meta-datetime-label", modesResultsData[t]["ImgDateTime"]);
		updateResultLabels(t+"-result-meta-model-label", modesResultsData[t]["ImgModel"]);
		updateResultLabels(t+"-result-meta-manufacturer-label", modesResultsData[t]["ImgManufacturer"]);
		updateResultLabels(t+"-process-info-label", modesResultsData[t]["ProcessesCount"]);
		updateResultLabels(t+"-domain-info-label", modesResultsData[t]["DomainsCount"]);
		updateResultLabels(t+"-malign-files-info-label", modesResultsData[t]["MalignFileCount"]);
		updateResultLabels(t+"-malign-events-info-label", modesResultsData[t]["FlaggedEvents"]);

		updateTableData(t+"-pstree-table", 
			["Name", "PID", "PPID", "Threads", "Handles", "Time"],
			modesResultsData[t]['PstreeResult']);

		updateTableData(t+"-whois-table", 
			["IP", "Organisation", "HostName", "ISP", "Continent", "Country", "State/Region", "City"],
			modesResultsData[t]['WhoIsDomainDetails']);

		updateTableData(t+"-exes-table", 
			['File Name', 'MD5', 'SHA1', "VirusTotal", "Heuristics Indicators", "Tensorflow Model"],
			modesResultsData[t]['FilesAnalysisDetails']);

		updateTableData(t+"-dlls-table", 
			['File Name', 'MD5', 'SHA1', "VirusTotal", "Heuristics Indicators", "Tensorflow Model"],
			modesResultsData[t]['DLLAnalysisDetails']);
		
		updateTableData(t+"-evt-table", 
			['RuleTriggered', 'RuleName', 'EventID', 'Timestamp', 'EventRecordID', 'Description', 'IPAddress'],
			modesResultsData[t]['EventLogAnalysisDetails']);

		$('#res-'+t+'-panel').show(100);
	};


	window.execTriageDumpRun = function() {
		window.exeResultsBatchUpdate('triage');
	}


	window.malwareFileInputed = function () {
		$('#malware-input-file-label').html(inputFilePaths.malwareFilePath);
		inputFilePaths.malwareFilePath = "";
	}

	$('#malware-input-file').click(function(){
		needsUpdate.malwareFileInput = true;
	});


	window.execMalwareResults = function() {
		updateResultLabels("malware-single-heuristics-info-label", modesResultsData['malware']['Heuristics']);
		updateResultLabels("malware-single-ml-score-label", modesResultsData['malware']['TensorModel']);

		updateTableData("malware-single-Imports-table", 
					['API', 'Functions'],
					modesResultsData['malware']['ImportsResult']);
		updateTableData("malware-single-sections-table", 
					["Name", "Entropy", "VirtualAddress", "Misc_VirtualSize", "SizeOfRawData", "Characteristic"],
					modesResultsData['malware']['SectionResults']['Rows']);

		$('#res-malware-single-panel').show(100);
	}


	window.malwareFinishedAnalysis = function() {
		malwareFields.pePath = '';
	}

	// window.function
	
	$('#malware-btn-run').click(function(){
		malwareFields.pePath = $('#malware-input-file-label').html();

		needsUpdate.malwareExecuteAnalysis = true;
	});


	window.evtLogInputted = function() {
		$('#evt-input-file-label').html(inputFilePaths.evtLogPath);		
		inputFilePaths.evtLogPath = '';
	}

	$('#evt-input-file').click(function(){
		needsUpdate.evtLogInput = true;
	});


	window.evtFinishedAnalysis = function () {
		evtFields.logPath = "";
	}

	window.execEvtAnalysisResults = function () {
		updateTableData("evt-evt-table", 
			['RuleTriggered', 'RuleName', 'EventID', 'Timestamp', 'EventRecordID', 'Description', 'IPAddress'],
			modesResultsData['evt']['EventLogAnalysisSolo']);

		$('#res-evt-panel').show(100);

	}


	$('#evt-btn-run').click(function(){
		evtFields.logPath = $('#evt-input-file-label').html();

		console.log(evtFields.logPath);
		// triageFields = imageFilePath: 'c:\\users\\user\\desktop\\test.txt'}
		needsUpdate.evtExecuteAnalysis = true;
	});


	window.reviewCaseInputted = function() {
		$('#review-input-file-label').html(inputFilePaths.reviewCasePath);		
		inputFilePaths.reviewCasePath = '';
	}

	$('#review-input-file').click(function() {
		needsUpdate.reviewResultInput = true;
	});


	window.execReviewDumpRun = function() {
		window.exeResultsBatchUpdate('review');
	}

	window.reviewFinishedAnalysis = function() {
		reviewFields.caseFilePath = ""; //Reset triageFields inputs
	}

	$('#review-btn-dump').click(function() {
		reviewFields.caseFilePath = $('#review-input-file-label').html();
		needsUpdate.reviewExecuteReview = true;
	});

	var startUp = function() {
		$('#side-home').addClass("active");
		$('.content-row').hide();
		$('#row-home').show();

		// $('.results-container').hide();
	};

	var sbAdminEvents = function () { 
		$("#sidebarToggle, #sidebarToggleTop").on('click', function(e) {
		  	$("body").toggleClass("sidebar-toggled");
		  	$(".sidebar").toggleClass("toggled");
		  	if ($(".sidebar").hasClass("toggled")) {
		  		$('.sidebar .collapse').collapse('hide');
		  	};
	  	});

		  // Close any open menu accordions when window is resized below 768px
		  $(window).resize(function() {
		  	if ($(window).width() < 768) {
		  		$('.sidebar .collapse').collapse('hide');
		  	};
		  	
			// Toggle the side navigation when window is resized below 480px
			if ($(window).width() < 480 && !$(".sidebar").hasClass("toggled")) {
				$("body").addClass("sidebar-toggled");
				$(".sidebar").addClass("toggled");
				$('.sidebar .collapse').collapse('hide');
			};
		});

		  // Prevent the content wrapper from scrolling when the fixed side navigation hovered over
	  	$('body.fixed-nav .sidebar').on('mousewheel DOMMouseScroll wheel', function(e) {
		  	if ($(window).width() > 768) {
		  		var e0 = e.originalEvent,
		  		delta = e0.wheelDelta || -e0.detail;
		  		this.scrollTop += (delta < 0 ? 1 : -1) * 30;
		  		e.preventDefault();
		  	}
	  	});

		  // Scroll to top button appear
	  	$(document).on('scroll', function() {
		  	var scrollDistance = $(this).scrollTop();
		  	if (scrollDistance > 100) {
		  		$('.scroll-to-top').fadeIn();
		  	} else {
		  		$('.scroll-to-top').fadeOut();
		  	}
  		});

		  // Smooth scrolling using jQuery easing
	  	$(document).on('click', 'a.scroll-to-top', function(e) {
		  	var $anchor = $(this);
		  	$('html, body').stop().animate({
		  		scrollTop: ($($anchor.attr('href')).offset().top)
		  	}, 1000, 'easeInOutExpo');
		  	e.preventDefault();
	  	});
	};

	startUp();
	sbAdminEvents();
});
