layout = {};
context = {};

var refreshB64 = 'data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+PHN2ZyB4bWxuczpkYz0iaHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iIHhtbG5zOmNjPSJodHRwOi8vY3JlYXRpdmVjb21tb25zLm9yZy9ucyMiIHhtbG5zOnJkZj0iaHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyIgeG1sbnM6c3ZnPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczpzb2RpcG9kaT0iaHR0cDovL3NvZGlwb2RpLnNvdXJjZWZvcmdlLm5ldC9EVEQvc29kaXBvZGktMC5kdGQiIHhtbG5zOmlua3NjYXBlPSJodHRwOi8vd3d3Lmlua3NjYXBlLm9yZy9uYW1lc3BhY2VzL2lua3NjYXBlIiB2aWV3Qm94PSIwIC0yNTYgMTc5MiAxNzkyIiBpZD0ic3ZnMiIgdmVyc2lvbj0iMS4xIiBpbmtzY2FwZTp2ZXJzaW9uPSIwLjQ4LjMuMSByOTg4NiIgd2lkdGg9IjEwMCUiIGhlaWdodD0iMTAwJSIgc29kaXBvZGk6ZG9jbmFtZT0icmVmcmVzaF9mb250X2F3ZXNvbWUuc3ZnIj4gIDxtZXRhZGF0YSBpZD0ibWV0YWRhdGExMiI+ICAgIDxyZGY6UkRGPiAgICAgIDxjYzpXb3JrIHJkZjphYm91dD0iIj4gICAgICAgIDxkYzpmb3JtYXQ+aW1hZ2Uvc3ZnK3htbDwvZGM6Zm9ybWF0PiAgICAgICAgPGRjOnR5cGUgcmRmOnJlc291cmNlPSJodHRwOi8vcHVybC5vcmcvZGMvZGNtaXR5cGUvU3RpbGxJbWFnZSIvPiAgICAgIDwvY2M6V29yaz4gICAgPC9yZGY6UkRGPiAgPC9tZXRhZGF0YT4gIDxkZWZzIGlkPSJkZWZzMTAiLz4gIDxzb2RpcG9kaTpuYW1lZHZpZXcgcGFnZWNvbG9yPSIjZmZmZmZmIiBib3JkZXJjb2xvcj0iIzY2NjY2NiIgYm9yZGVyb3BhY2l0eT0iMSIgb2JqZWN0dG9sZXJhbmNlPSIxMCIgZ3JpZHRvbGVyYW5jZT0iMTAiIGd1aWRldG9sZXJhbmNlPSIxMCIgaW5rc2NhcGU6cGFnZW9wYWNpdHk9IjAiIGlua3NjYXBlOnBhZ2VzaGFkb3c9IjIiIGlua3NjYXBlOndpbmRvdy13aWR0aD0iNjQwIiBpbmtzY2FwZTp3aW5kb3ctaGVpZ2h0PSI0ODAiIGlkPSJuYW1lZHZpZXc4IiBzaG93Z3JpZD0iZmFsc2UiIGlua3NjYXBlOnpvb209IjAuMTMxNjk2NDMiIGlua3NjYXBlOmN4PSI4OTYiIGlua3NjYXBlOmN5PSI4OTYiIGlua3NjYXBlOndpbmRvdy14PSIwIiBpbmtzY2FwZTp3aW5kb3cteT0iMjUiIGlua3NjYXBlOndpbmRvdy1tYXhpbWl6ZWQ9IjAiIGlua3NjYXBlOmN1cnJlbnQtbGF5ZXI9InN2ZzIiLz4gIDxnIHRyYW5zZm9ybT0ibWF0cml4KDEsMCwwLC0xLDEyMS40OTE1MywxMjcwLjIzNzMpIiBpZD0iZzQiPiAgICA8cGF0aCBkPSJtIDE1MTEsNDgwIHEgMCwtNSAtMSwtNyBRIDE0NDYsMjA1IDEyNDIsMzguNSAxMDM4LC0xMjggNzY0LC0xMjggNjE4LC0xMjggNDgxLjUsLTczIDM0NSwtMTggMjM4LDg0IEwgMTA5LC00NSBRIDkwLC02NCA2NCwtNjQgMzgsLTY0IDE5LC00NSAwLC0yNiAwLDAgdiA0NDggcSAwLDI2IDE5LDQ1IDE5LDE5IDQ1LDE5IGggNDQ4IHEgMjYsMCA0NSwtMTkgMTksLTE5IDE5LC00NSAwLC0yNiAtMTksLTQ1IEwgNDIwLDI2NiBxIDcxLC02NiAxNjEsLTEwMiA5MCwtMzYgMTg3LC0zNiAxMzQsMCAyNTAsNjUgMTE2LDY1IDE4NiwxNzkgMTEsMTcgNTMsMTE3IDgsMjMgMzAsMjMgaCAxOTIgcSAxMywwIDIyLjUsLTkuNSA5LjUsLTkuNSA5LjUsLTIyLjUgeiBtIDI1LDgwMCBWIDgzMiBxIDAsLTI2IC0xOSwtNDUgLTE5LC0xOSAtNDUsLTE5IGggLTQ0OCBxIC0yNiwwIC00NSwxOSAtMTksMTkgLTE5LDQ1IDAsMjYgMTksNDUgbCAxMzgsMTM4IFEgOTY5LDExNTIgNzY4LDExNTIgNjM0LDExNTIgNTE4LDEwODcgNDAyLDEwMjIgMzMyLDkwOCAzMjEsODkxIDI3OSw3OTEgMjcxLDc2OCAyNDksNzY4IEggNTAgUSAzNyw3NjggMjcuNSw3NzcuNSAxOCw3ODcgMTgsODAwIHYgNyBxIDY1LDI2OCAyNzAsNDM0LjUgMjA1LDE2Ni41IDQ4MCwxNjYuNSAxNDYsMCAyODQsLTU1LjUgMTM4LC01NS41IDI0NSwtMTU2LjUgbCAxMzAsMTI5IHEgMTksMTkgNDUsMTkgMjYsMCA0NSwtMTkgMTksLTE5IDE5LC00NSB6IiBpZD0icGF0aDYiIGlua3NjYXBlOmNvbm5lY3Rvci1jdXJ2YXR1cmU9IjAiIHN0eWxlPSJmaWxsOmN1cnJlbnRDb2xvciIvPiAgPC9nPjwvc3ZnPg==';

window.needsUpdate = {
	volRamDumpInput: false, volExecuteDump: false,
	triageCaseFolderInput: false, triageExecuteAnalysis: false, triageSaveResult: false,
	malwareFileInput: false, malwareExecuteAnalysis: false,
	evtLogInput: false, evtExecuteAnalysis: false,
	reviewResultInput: false, reviewExecuteReview: false};

window.inputFilePaths = {
	ramImage: '',
	triageFolderPath: '',
	malwareFilePath: '',
	evtLogPath:'',
	reviewCasePath: ''
};

// Fields for interacting with python
volFields = {caseName: '', ramFilePath:''}

triageFields = {caseFolderPath: ''};

malwareFields = {pePath: ''};

evtFields = {logPath: ''};

reviewFields = {caseFilePath: ''};

modesResultsData = {vol: '', triage: '' , malware: '', evt: '', review: ''};


// Notification options
toastr.options = {
	  "closeButton": true,
	  "debug": false,
	  "newestOnTop": false,
	  "progressBar": false,
	  "positionClass": "toast-top-right",
	  "preventDuplicates": false,
	  "onclick": null,
	  "showDuration": "200",
	  "hideDuration": "1000",
	  "timeOut": "3000",
	  "extendedTimeOut": "1000",
	  "showEasing": "swing",
	  "hideEasing": "linear",
	  "showMethod": "fadeIn",
	  "hideMethod": "fadeOut"
};


showSuccess = function(s) {
	toastr.success(s);
}


showLoader = function(t) {
  // $('#refresh').addClass('disabled');
  $.LoadingOverlay('show', {
    image: '',
    custom: $(HTML(['div', {id: 'download', class: 'row noselect'},
      ['img', {class: 'refresh'}, {src: refreshB64}], 
      ['span', {class: 'ml-2 text'}, t]
    ]))
  });
}

showError = function(e) {
	if (e != '') {
		toastr.error(e);
	}
}

hideLoader = function(error) {
  if (error) toastr.error(error);
  $('#refresh').removeClass('disabled');
  $.LoadingOverlay('hide');
}