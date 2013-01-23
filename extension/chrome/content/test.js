window.addEventListener("load", function load(event){
	window.removeEventListener("load",load,false);
	if(gBrowser){
		gBrowser.addEventListener("pageshow",function plop(aEvent){
			alert(document.title);
		},false);
	}
});
/.
function pop(){ alert('hello');} 
