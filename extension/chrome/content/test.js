window.addEventListener("load", function load(event){
	window.removeEventListener("load",load,false);
	if(gBrowser){
		gBrowser.addEventListener("DOMContentLoaded",function plop(aEvent){
			var doc = aEvent.originalTarget;
			var win = doc.defaultView;
			if ((doc.nodeName == '#document') && 
			       (doc.defaultView.location.href == gBrowser.currentURI.spec)) 
		        {
				alert("page is loaded\n" + doc.location.href);
			}
		},false);
	}
},false);
function pop(){ alert('hello');} 
