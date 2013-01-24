window.addEventListener("load", function load(event){
	window.removeEventListener("load",load,false);
	gExt.init();
},false);

var gExt = {
	init : function(){
		if(gBrowser){
			gBrowser.addEventListener("DOMContentLoaded",this.onload,false);
		}
	},

	onload : function(aEvent){
		var doc = aEvent.originalTarget;
		var win = doc.defaultView;
		alert('préchargement');	
		win.ext_jq = gExt.loadJquery(win);
		alert('chargement');
		//var $ = JQuery = win.ext_jq;
		alert('chargement2');
		if((doc.nodeName == '#document') && (win.location.href == "https://fr-fr.facebook.com/")){
//			alert(win.location.href);
//			doc.body.innerHTML = '<b>' + doc.title + '</b>';
//			$('*').replaceWith('<b>test</b>');
			//alert($('*'));
			//b = doc.getElementsByClassName('lfloat')[0];
			//b.innerHTML = '<font size="6" color="white"><b>smartbook</b></font> ';
		}
	},

	loadJquery : function(wnd){
		alert('chargement3');
		var loader = Component.classes["@mozilla.org/moz/jssubscript-loader;1"]
		.getService(Component.interfaces.mozIJSSubScriptLoader);
		alert('chargement4');
		loader.loadSubScript("chrome://sample/content/jquery.min.js",wnd);
		alert('chargement5');
		var jQuery = wnd.jQuery.noConflict(true);
		alert('chargement6');
		return jQuery;
	}
		
		
}

function pop(){alert('test');}
