var aboutIntroDetails = [
	{"Name":"Kevin Tan", "imagePath":"img/kevin.png"},		
	{"Name":"Patrick Kang", "imagePath":"img/patrick.jpeg"},
	{"Name":"Jerome Tan", "imagePath":"img/jerome.jpeg"},
	{"Name":"Lim Long Xian", "imagePath":"img/longxian.jpg"},
	{"Name":"Cleaven Goh", "imagePath":"img/cleaven.jpeg"}				
];

var aboutIntroCtx = ctxHelper.genAboutCardInfoCtx(
		"Introduction",
		'img/enigma.png',
		ctxHelper.genCardBodyCtx('img/enigma.png',[
			ctxHelper.genAboutCardBodyParaCtx("","As technologies advance over the years, the rates of targeted cyber-attacks become even more prevalent. When these attacks happen, many companies do not know when or how their infrastructures are being compromised, and thus are unable to provide a direction for forensic investigations."),
			ctxHelper.genAboutCardBodyParaCtx("","Our solution aims to provide as much information as possible within the forensic bailiwick of an investigation. It consists of a trilogy of modules - a Windows Event Log analyzer, a PE static analyzer, and an IOC detector. Together with an interactive GUI to ease navigation between modules and display our results, we believe that our solution will be extremely valuable in the forensics community.")]
		)
	);


var aboutPeopleCtx = [aboutIntroDetails, function (d) {
	return ['div', {class: 'col-lg-4'},
		['div', {class: 'card position-relative'},
			['div', {class: 'card-header py-3'},
				['h6', {class: 'm-0 font-weight-bold text-primary'}, d.Name]
			],
			['div', {class: 'card-body text-center justify-content-center'},
				['img', {class: 'img-fluid px-3 px-sm-4 mt-3 mb-4 about-info-img', src: d.imagePath}],					
				['div',  {class: 'mb-1'}],
				['p', {class: 'mb-0 small'}]
			]
		]
	]
}];

