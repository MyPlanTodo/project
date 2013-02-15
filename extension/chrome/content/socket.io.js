<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd"> <html><head> <meta http-equiv="Content-Type" CONTENT="text/html; charset=utf-8"> <title>ERREUR: L'URL demandée n'a pas pu être trouvé</title> <style type="text/css"><!--   /*
 Stylesheet for Squid Error pages
 Adapted from design by Free CSS Templates
 http://www.freecsstemplates.org
 Released for free under a Creative Commons Attribution 2.5 License
*/

/* Page basics */
* {
	font-family: verdana, sans-serif;
}

html body {
	margin: 0;
	padding: 0;
	background: #efefef;
	font-size: 12px;
	color: #1e1e1e;
}

/* Page displayed title area */
#titles {
	margin-left: 15px;
	padding: 10px;
	padding-left: 100px;
	background: url('http://www.squid-cache.org/Artwork/SN.png') no-repeat left;
}

/* initial title */
#titles h1 {
	color: #000000;
}
#titles h2 {
	color: #000000;
}

/* special event: FTP success page titles */
#titles ftpsuccess {
	background-color:#00ff00;
	width:100%;
}

/* Page displayed body content area */
#content {
	padding: 10px;
	background: #ffffff;
}

/* General text */
p {
}

/* error brief description */
#error p {
}

/* some data which may have caused the problem */
#data {
}

/* the error message received from the system or other software */
#sysmsg {
}

pre {
    font-family:sans-serif;
}

/* special event: FTP / Gopher directory listing */
#dirmsg {
    font-family: courier;
    color: black;
    font-size: 10pt;
}
#dirlisting {
    margin-left: 2%;
    margin-right: 2%;
}
#dirlisting tr.entry td.icon,td.filename,td.size,td.date {
    border-bottom: groove;
}
#dirlisting td.size {
    width: 50px;
    text-align: right;
    padding-right: 5px;
}

/* horizontal lines */
hr {
	margin: 0;
}

/* page displayed footer area */
#footer {
	font-size: 9px;
	padding-left: 10px;
}
  body :lang(fa) { direction: rtl; font-size: 100%; font-family: Tahoma, Roya, sans-serif; float: right; } :lang(he) { direction: rtl; }  --></style> </head><body id=ERR_CONNECT_FAIL> <div id="titles"> <h1>ERROR</h1> <h2>The requested URL could not be retrieved</h2> </div> <hr>  <div id="content"> <p>L'erreur suivante s'est produite en essayant d'accéder à l'URL : <a href="http://api.cerrio.com/socket.io/socket.io.js">http://api.cerrio.com/socket.io/socket.io.js</a></p>  <blockquote id="error"> <p><b>La connexion 107.20.254.54 a échouée.</b></p> </blockquote>  <p id="sysmsg">Le système a retourné : <i>(111) Connection refused</i></p>  <p>L'hôte distant ou le réseau sont peut-être défaillant. Veuillez renouveler votre requête.</p>  <p>Votre administrateur proxy est <a href="mailto:contact_dir@univ-rouen.fr?subject=CacheErrorInfo%20-%20ERR_CONNECT_FAIL&amp;body=CacheHost%3A%20inf-srv-enclos%0D%0AErrPage%3A%20ERR_CONNECT_FAIL%0D%0AErr%3A%20(111)%20Connection%20refused%0D%0ATimeStamp%3A%20Mon,%2004%20Feb%202013%2009%3A55%3A28%20GMT%0D%0A%0D%0AClientIP%3A%20192.168.34.6%0D%0AServerIP%3A%20api.cerrio.com%0D%0A%0D%0AHTTP%20Request%3A%0D%0AGET%20%2Fsocket.io%2Fsocket.io.js%20HTTP%2F1.1%0AHost%3A%20api.cerrio.com%0D%0AUser-Agent%3A%20Mozilla%2F5.0%20(X11%3B%20Ubuntu%3B%20Linux%20i686%3B%20rv%3A18.0)%20Gecko%2F20100101%20Firefox%2F18.0%0D%0AAccept%3A%20text%2Fhtml,application%2Fxhtml+xml,application%2Fxml%3Bq%3D0.9,*%2F*%3Bq%3D0.8%0D%0AAccept-Language%3A%20fr,fr-fr%3Bq%3D0.8,en-us%3Bq%3D0.5,en%3Bq%3D0.3%0D%0AAccept-Encoding%3A%20gzip,%20deflate%0D%0AReferer%3A%20http%3A%2F%2Fcerrio.com%2Fcerrio-docs%2Fwebsocket-api%2F%0D%0ACookie%3A%20__utma%3D74764928.1620019062.1359971257.1359971257.1359971257.1%3B%20__utmb%3D74764928.2.10.1359971257%3B%20__utmc%3D74764928%3B%20__utmz%3D74764928.1359971257.1.1.utmcsr%3Dgoogle%7Cutmccn%3D(organic)%7Cutmcmd%3Dorganic%7Cutmctr%3D(not%2520provided)%0D%0AProxy-Authorization%3A%20Basic%20YWRkaXphazptMWwyazNqNA%3D%3D%0D%0AConnection%3A%20keep-alive%0D%0APragma%3A%20no-cache%0D%0ACache-Control%3A%20no-cache%0D%0A%0D%0A%0D%0A">contact_dir@univ-rouen.fr</a>.</p>  <br> </div>  <hr> <div id="footer"> <p>Générer le Mon, 04 Feb 2013 09:55:28 GMT par inf-srv-enclos (squid/3.2.5-20121213-r11739)</p> <!-- ERR_CONNECT_FAIL --> </div> </body></html> 