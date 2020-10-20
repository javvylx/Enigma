HTML = function(context) {
		if (arguments.length > 1) {
			var a = new Array(arguments.length);
			for (var i = 0; i < a.length; ++i) a[i] = arguments[i];
			return HTML(a);
		}
		if (context.constructor != Array) return '' + context;
		if (context.length > 0 && context[0].constructor == Array) {
			var r = '';
			for (var i = 0; i < context.length; ++i) r += HTML(context[i]); 
			return r;
		}
		var tag = context[0], content = '', attrs = {}, concats = [];
		for (var i = 1; i < context.length; i++) if (context[i]) {
			var obj = context[i];
			if (obj.constructor == Array) {
				content += HTML(obj); 
			} else if (obj.constructor == Object) {
				for (var k in obj) {
					var v = obj[k];
					if (obj.hasOwnProperty(k) && v != null) {
						if (!attrs.hasOwnProperty(k)) attrs[k] = [];
						if (v.constructor == Object) {
							for (var k2 in v) if (v.hasOwnProperty(k2)) 
								attrs[k].push(k2 + ':' + v[k2])
						} else attrs[k].push(v);
					}
				}
			} else content += obj;
		}
		var r = '<' + tag;
		for (var k in attrs) {
			r += ' ' + k + '="';
			var e = attrs[k].length - 1;
			for (var i = 0; i < e; ++i) r += attrs[k][i] + '; ';
			if (e > -1) r += attrs[k][e];
			r += '"';
		}
		return r + '>' + content + '</' + tag + '>';
	}