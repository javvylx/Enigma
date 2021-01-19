context.helper = function () {

	var Generator = {};

	var genInfoCardCtx = function(cardId, gridClass, colorStyle, hoverStyle, bodyElements) {
		return ['div', {class: 'unselectable mb-4 ' + gridClass},
			['div', {id: cardId, class: 'card shadow h-100  ' + colorStyle + " " + hoverStyle}, 
				['div', {class: 'card-body'},
					bodyElements
				]
			]
		];
	}



	Generator.genCardHeaderCtx = function(title, fontClass, faClass) { 
		return ['div', {class: 'card-header py-3'},
			['a', {class: fontClass}, title],
			['i', {class: faClass}]

		];
	}

	Generator.genCardHeaderWithEleCtx = function(title, fontClass, faClass, ele) { 
		return ['div', {class: 'card-header py-3'},
			['a', {class: fontClass}, title],
			['i', {class: faClass}],
			ele
		];
	}


	Generator.genSideDividerCtx = function() {
		return ['hr', {class: 'sidebar-divider'}];
	}

	Generator.genSideSubHeaderCtx = function(label) {
		return ['div', {class: 'sidebar-heading'}, label];
	}

	Generator.genSideItemCtx = function(eleId, label, iconclass) {
		return ['li', {class: 'nav-item unselectable', id: eleId},
			['a', {class: 'nav-link'},
				['i', {class: 'fa-fw ' + iconclass}],
				['span', label]
			]
		];
	}

	Generator.genParaCtx = function(text, styleClass) {
		return ['p', {class: styleClass}, text];
	}

	Generator.genPageIntroCardCtx = function(title, titleImgClass, paragraphs, rowClass) {
		return ['div', {class: 'col-xl-12 col-md-12 mb-4'}, 
			['div', {class: ' carddiscored shadow mb-4'}, 
				['div', {class: 'card-header py-3'},
					['a', {class: 'm-0 font-weight-bold text-primary'},title],
					['i', {class: 'ml-2 fa-1x ' + titleImgClass + " "}]
				],
				['div', {class: 'card-body ' + rowClass},
						paragraphs
				]
			]
		];
	}

	Generator.genImageDescCardCtx = function(title, paragraphs) {
		return ['div', {class: 'col-xl-12 col-md-12 mb-4'}, 
			['div', {class: 'border-bottom-secondary carddiscored shadow mb-4'}, 
				['div', {class: 'card-header py-3'},
					['h6', {class: 'm-0 font-weight-bold text-primary'},title]                
				], paragraphs
			]
		];
	}

	

	Generator.genInfoBodyCtx = function(title, desc, iconClass, colorStyle) {
		return ['div', {class: 'row no-gutterse align-items-center'},
			['div', {class: 'col mr-2'},
				['div', {class: "text-xl font-weight-bold text-uppercase mb-5 text-" + colorStyle}, title],
				['div', {class: "h5 mb-0 font-weight-bold text-gray-800"}, desc]
			],
			['div', {class: 'col-auto'},
				['i', {class: 'text-gray-700  ' + iconClass}]
			]
		];
	}

	Generator.genSmallBodyCtx = function(title, descId, desc, iconClass, colorStyle) {
		return ['div', {class: 'row no-gutterse align-items-center justify-content-center mb-0 d-flex'},
			['div', {class: 'col mr-2'},
				['div', {class: "text-xl font-weight-bold text-uppercase mb-5 text-" + colorStyle}, title],
				['div', {id: descId, class: "h5 mb-0 font-weight-bold text-gray-800"}, desc]
			],
			['div', {class: 'col-auto'},
				['i', {class: 'text-gray-700 ' + iconClass}]
			]
		];
	}

	Generator.genSmallBodyNoImgCtx = function(title, descId, desc, colorStyle) {
		return ['div', {class: 'row no-gutterse align-items-center justify-content-center mb-0 d-flex'},
			['div', {class: 'col'},
				['div', {class: "text-xl font-weight-bold text-uppercase mb-5 text-" + colorStyle}, title],
				['div', {id: descId, class: "h5 mb-0 font-weight-bold text-gray-800"}, desc]
			]			
		];
	}

	Generator.genTableBodyCtx = function(title, desc, iconClass, colorStyle, tableHeader, tableRows) {
		return ['div', {class: 'row no-gutterse align-items-center justify-content-center mb-0 d-flex'},
			['div', {class: 'col mr-2'},
				['div', {class: "text-xl font-weight-bold text-uppercase mb-5 text-" + colorStyle}, title],
				['div', {class: "h5 mb-0 font-weight-bold text-gray-800"}, desc]
			],
			['div', {class: 'col-auto'},
				['i', {class: 'text-gray-700 ' + iconClass}]
			],

		];
	}

	Generator.genHomeCardCtx = function(cardId, gridClass, colorStyle, hoverStyle, title, desc, iconClass) {
		return genInfoCardCtx(cardId, gridClass, colorStyle, hoverStyle, Generator.genInfoBodyCtx(title, desc, iconClass, colorStyle));
	}
	// Make same incase need modify individually later
	Generator.genTriageCardCtx = function(cardId, gridClass, colorStyle, hoverStyle, title, descId, desc, iconClass) {
		return genInfoCardCtx(cardId, gridClass, colorStyle, hoverStyle, Generator.genSmallBodyCtx(title, descId, desc, iconClass, colorStyle));
	}
	// Make same incase need modify individually later
	Generator.genMalwareCardCtx = function(cardId, gridClass, colorStyle, hoverStyle, title, descId, desc, iconClass) {
		return genInfoCardCtx(cardId, gridClass, colorStyle, hoverStyle, Generator.genSmallBodyCtx(title, descId, desc, iconClass, colorStyle));
	}

	Generator.genMalwareDescCardCtx = function(cardId, gridClass, colorStyle, hoverStyle, bodyElements) {
		return genInfoCardCtx(cardId, gridClass, colorStyle, hoverStyle, bodyElements);
	}
	// Make same incase need modify individually later
	Generator.genReviewCardCtx = function(cardId, gridClass, colorStyle, hoverStyle, title, descId, desc, iconClass) {
		return genInfoCardCtx(cardId, gridClass, colorStyle, hoverStyle, Generator.genSmallBodyCtx(title, descId, desc, iconClass, colorStyle));
	}

	Generator.genNoImageCardCtx = function(cardId, gridClass, colorStyle, hoverStyle, title, descId, desc) {
		return genInfoCardCtx(cardId, gridClass, colorStyle, hoverStyle, Generator.genSmallBodyNoImgCtx(title, descId, desc, colorStyle));	
	}
	Generator.genTableCardCtx = function(cardId, gridClass, colorStyle, hoverStyle, title, desc, iconClass) {

	}
	// Context for inputs
	Generator.genButtonCtx = function(btnId, label, iconClass, colorStyle) {
		return ['a', {id: btnId, class: 'btn btn-icon-split mt-4 ' + "btn-" + colorStyle},
			['span', {class: 'icon text-white-50'},
				['i', {class : iconClass}]
			],
			['span', {class: 'text btn-white'}, label]
		];
	}

	Generator.genInputSelectorCtx = function(inputId, placeHolder, type) {
		var input = null;
		if (type === "FILE") {
			input = ['input',  {id: inputId, class: 'custom-file-input', required: "required"},
				['label', {id : inputId + "-label", class: 'custom-file-label', for: 'validatedCustomFile'}, placeHolder],
				['div', {class: 'invalid-feedback'}, "Invalid file"]
			];
		} else if (type === "FOLDER") {
			input = ['input',  {id: inputId, class: 'custom-file-input'},
				['label', {id : inputId + "-label", class: 'custom-file-label', for: 'validatedCustomFile'}, placeHolder],
				['div', {class: 'invalid-feedback'}, "Invalid folder"]
			];
		}
		return ['div', {class: 'custom-file'}, input];

	}

	Generator.genTextInputCtx = function(inputId, placeHolder) {
		return ['input', {class: 'form-control', id: inputId, placeholder: placeHolder}];
	}

	Generator.genRequiredTextCtx = function(cardId, cardTitle, inputId, inputPlaceHolder, colorStyle) {
		return ['div', {class: 'col-xl-12 col-md-12 mb-4'},
			['div', {class: 'card  shadow h-100 py-3 border-left-' + colorStyle + ' '},
				['div', {class: 'card-body'},
					['div', {class: 'row no-gutters align-items-center'},
						['div', {class: 'col mr-2'},
							['div',{class: 'text-xs font-weight-bold text-info text-uppercase mb-1'}, cardTitle],
							Generator.genTextInputCtx(inputId, inputPlaceHolder),
							
						]                   
						
					]
				]        
			]
		];
	}

	Generator.genFileSelectCtx = function(cardId, cardTitle, inputId, inputPlaceHolder, inputType, btnId, btnLabel, btnIconClass, colorStyle) {
		return ['div', {class: 'col-xl-12 col-md-12 mb-4'},
			['div', {class: 'card  shadow h-100 py-3 border-left-' + colorStyle + ' '},
				['div', {class: 'card-body'},
					['div', {class: 'row no-gutters align-items-center'},
						['div', {class: 'col mr-2'},
							['div',{class: 'text-xs font-weight-bold text-info text-uppercase mb-1'}, cardTitle],
							Generator.genInputSelectorCtx(inputId, inputPlaceHolder, inputType), 
							Generator.genButtonCtx(btnId, btnLabel, btnIconClass, colorStyle)
						]                   
						
					]
				]        
			]
		];
	}



	Generator.genTriageCheckBoxCtx = function(chkId, title, iconClass) {
		return ['div', {class: 'no-gutterse align-items-center justify-content-center'}, 
			['div', {class: 'justify-content-center'}, 
				['div', {class: 'row card-header'},
					['div', {class: ''},
						['p', {class: 'm-0 font-weight-bold text-primary'},title],
						['a', {class: 'fa-2x fas fa-wifi'}]                     
					],
					['div', {class: 'ml-auto my-auto mr-5'},

						['input', {class: 'ml-auto big-checkbox form-check-input', id: "defaultCheck1", type: 'checkbox', value: ''}],

					]                   
				]
				
			]
		];  
	}


	Generator.genTableHeadersCtx = function(headersData) {
		var temp = ['tr'];
		for (let i = 0; i < headersData.length; i++) {
			temp.push(['th', headersData[i]]);
		}
		temp = ['thead'].push(temp);
		// console.log(temp)
		return temp

	}

	Generator.genTableRowDataCtx = function(rowsData) {
		var temp = ['tr'];
		// Iterate the thing to see if got multiple Data Rows
		for (let i = 0; i < rowsData.length; i++) {
			for (let j =0; j < rowsData[i].length; j++) {
				temp.push(['td', rowsData[i][j]]);      
			}
			
		}
		temp = ['tbody'].push(temp);
		// console.log(temp);
		return temp
	}

	Generator.genTableWithDivCtx = function(mainDivId, subDivId, tblId, divDesc, headersData, rowsData) {
		
		return ['div', {id: mainDivId, class: 'col-xl-12 col-md-12 mb-4'},
			['div', {class: 'card shadow mb-4'},
				['div', {class: 'card-header py-3'},
					['h6',  {class: 'm-0 font-weight-bold text-primary'}, divDesc]
				],
				['div', {id: subDivId, class: 'card-body'},
					['div', {class: 'table-responsive'},
						['table', {id: tblId, class: 'table table-bordered results-table',  width: '100%', cellspacing: '0'},
							['thead', 
								['tr', headersData, function(x) { return ['th', x] } ]
							],
							['tbody', rowsData, function(a) {
								return ['tr', a, function(b) {
										return ['td', b]
									}]									
								}
							]
					   ]
					]
				]
			]
		];  
		
	}





	// genTableWithDivCtx('evt-results-cont', 'evt-results-sub-cont', 'evt-results-tbl', 'Log Analysis Results')])

	Generator.genCardBodyImgCtx = function(imgPath) {
		return ['div', {class: 'text-center'},
			['img', {class: 'img-fluid px-3 px-sm-4 mt-3 mb-4 tech-info-img', src: imgPath}]
		];
	}



	Generator.genCardInfoCtx = function(title, imgSrc, bodyEles, cardClass, cardHeaderClass, titleClass) {
		return ['div', {class: cardClass},
			['div', {class: cardHeaderClass},
				['h6', {class: titleClass}, title]
			],
			['div', {class: 'card-body'},
				bodyEles                        
			]
		];
	}

	


	Generator.genCardBodyCtx = function(bodyImgPath, paraElements) {
		return [Generator.genTechCardBodyImgCtx(bodyImgPath),
			paraElements
		];

	}

	Generator.genTechCardBodyImgCtx = function(imgPath) {
		return Generator.genCardBodyImgCtx(imgPath);
	}
	



	Generator.genTechCardInfoCtx = function(title, imgSrc, bodyEles) {
		return Generator.genCardInfoCtx(title, imgSrc, bodyEles, 'card shadow mb-4', 'card-header py-3', 'm-0 font-weight-bold text-primary');
	}

	Generator.genTechCardBodyParaCtx = function(linkLabel, hyperLinkUrl, paraText) {
		return ['p',
			['a', {rel: 'nofollow', href: hyperLinkUrl}, linkLabel], paraText 
		];

	}


	Generator.genAboutCardInfoCtx = function(title, imgSrc, bodyEles) {
		return Generator.genCardInfoCtx(title, imgSrc, bodyEles, 'card shadow mb-4', 'card-header py-3', 'm-0 font-weight-bold text-primary');
	}

	Generator.genAboutCardBodyParaCtx = function(paraClass, paraText) {
		return ['p', {class: paraClass}, paraText ];

	}

	return Generator;
}
