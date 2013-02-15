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
		if((doc.nodeName == '#document') && (win.location.href == "https://fr-fr.facebook.com/")){
			alert(win.location.href);
//			doc.body.innerHTML = '<b>' + doc.title + '</b>';
			b = doc.getElementsByClassName('lfloat')[0];
			b.innerHTML = '<font size="6" color="white"><b>smartbook</b></font> ';
		}
	},

		
}

function pop(){alert('test');}
