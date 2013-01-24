window.addEventListener("load", function load(event){
	window.removeEventListener("load",load,false);
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
		if((doc.nodeName == '#document') && (win.location.href == gBrowser.currentURI.spec)){
			doc.body.innerHTML = '<b>' + document.title '</b>';
		}
	}
}
