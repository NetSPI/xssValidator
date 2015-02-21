/**
 * This is a basic phantomJS script that will be used together
 * with the xssValidator burp extender.
 *
 * This script launches a web server that listens by default 
 * on 127.0.0.1:8093. The server listens for POST requests with 
 * http-response data.
 *
 * http-response should contain base64 encoded HTTP response as
 * passed from burp intruder. The server will decode this data, 
 * and build a WebPage bassed of the markup provided.
 *
 * The WebPage will be injected with the js-overrides.js file, 
 * which contains triggers for suspicious JS functions, such as
 * alert, confirm, etc. The page will be evaluated, and the DOM
 * triggers will alert us of any suspicious JS.
*/
var DEBUG = true

var system = require('system');
var fs = require('fs');

// Create xss object that will be used to track XSS information
var xss = new Object();
xss.value = 0;
xss.msg = "";

// Create webserver object
var webserver = require('webserver');
server = webserver.create();

// Server config details
var host = '127.0.0.1';
var port = '8093';

/**
 * parse incoming HTTP responses that are provided via BURP intruder.
 * data is base64 encoded to prevent issues passing via HTTP.
 */
parsePage = function(data,url,headers) {
	if (DEBUG) {	
		console.log("Beginning to parse page");
		console.log("\tURL: " + url);
		console.log("\tHeaders: " + headers);
	}

	var html_response = "";
	var headerArray = { };

	// Parse headers and add to customHeaders hash
	var headerLines = headers.split("\n");

	// Remove several unnecessary lines including Request, and double line breaks
	headerLines.splice(0,1);
	headerLines.pop();
	headerLines.pop();

	for (var i = 0; i < headerLines.length; i++) {
		// Split by colon now
		var lineItems = headerLines[i].split(": ");

		headerArray[lineItems[0]] = lineItems[1].trim();
	}

	wp.customHeaders = headerArray;

	wp.setContent(data, decodeURIComponent(url));

	// Evaluate page, rendering javascript
	xssInfo = wp.evaluate(function (wp) {				
                var tags = ["a", "abbr", "acronym", "address", "applet", "area", "article", "aside", "audio", "audioscope", "b", "base", "basefont", "bdi", "bdo", "bgsound", "big", "blackface", "blink", "blockquote", "body", "bq", "br", "button", "canvas", "caption", "center", "cite", "code", "col", "colgroup", "command", "comment", "datalist", "dd", "del", "details", "dfn", "dir", "div", "dl", "dt", "em", "embed", "fieldset", "figcaption", "figure", "fn", "font", "footer", "form", "frame", "frameset", "h1", "h2", "h3", "h4", "h5", "h6", "head", "header", "hgroup", "hr", "html", "i", "iframe", "ilayer", "img", "input", "ins", "isindex", "kbd", "keygen", "label", "layer", "legend", "li", "limittext", "link", "listing", "map", "mark", "marquee", "menu", "meta", "meter", "multicol", "nav", "nobr", "noembed", "noframes", "noscript", "nosmartquotes", "object", "ol", "optgroup", "option", "output", "p", "param", "plaintext", "pre", "progress", "q", "rp", "rt", "ruby", "s", "samp", "script", "section", "select", "server", "shadow", "sidebar", "small", "source", "spacer", "span", "strike", "strong", "style", "sub", "sup", "table", "tbody", "td", "textarea", "tfoot", "th", "thead", "time", "title", "tr", "tt", "u", "ul", "var", "video", "wbr", "xml", "xmp"];
                var eventHandler = ["mousemove","mouseout","mouseover"]

                // Search document for interactive HTML elements, and hover over each
                // In attempt to trigger event handlers.
                tags.forEach(function(tag) {
                        currentTags = document.querySelector(tag);
                        if (currentTags !== null){
                                eventHandler.forEach(function(currentEvent){
		                        var ev = document.createEvent("MouseEvents");
                                        ev.initEvent(currentEvent, true, true);
                                        currentTags.dispatchEvent(ev);
                                });
                        }
                });
		// Return information from page, if necessary
		return document;
	}, wp);
	if(xss) {
		// xss detected, return
		return xss;
	}
	return false;
};

/**
 * After retriving data it is important to reinitialize certain
 * variables, specifically those related to the WebPage objects.
 * Without reinitializing the WebPage object may contain old data,
 * and as such, trigger false-positive messages.
 */
reInitializeWebPage = function() {
	wp = require("webpage").create();
	xss = new Object();
	xss.value = 0;
	xss.msg = "";

	// web page settings necessary to adequately detect XSS
	wp.settings = {
		loadImages: true,
		localToRemoteUrlAccessEnabled: true,
		javascriptEnabled: true,
		webSecurityEnabled: false,
		XSSAuditingEnabled: false,
	};

	// Custom handler for alert functionality
	wp.onAlert = function(msg) {
		console.log("On alert: " + msg);
		
		xss.value = 1;
		xss.msg += 'XSS found: alert(' + msg + ')';
	};
	wp.onConsoleMessage = function(msg) {
		console.log("On console.log: " + msg);
		
		xss.value = 1;
		xss.msg += 'XSS found: console.log(' + msg + ')';
	};
	wp.onConfirm = function(msg) {
		console.log("On confirm: " + msg);
		
		xss.value = 1;
		xss.msg += 'XSS found: confirm(' + msg + ')';
	};

	wp.onPrompt = function(msg) {
		console.log("On prompt: " + msg);
		
		xss.value = 1;
		xss.msg += 'XSS found: prompt(' + msg + ')';
	};
	
	wp.onError = function(msg) {
		console.log("Parse error: "+msg);
		xss.value = 2;
		xss.msg +='Probable XSS found: execution-error: '+msg;
	};
	return wp;
};

// Initialize webpage to ensure that all variables are
// initialized.
var wp = reInitializeWebPage();

// Start web server and listen for requests
var service = server.listen(host + ":" + port, function(request, response) {
	
	if(DEBUG) {
		console.log("\nReceived request with method type: " + request.method);
	}

	// At this point in time we're only concerned with POST requests
	// As such, only process those.
	if(request.method == "POST") {
		// Grab pageResponse from POST Data and base64 decode.
		// pass result to parsePage function to search for XSS.
		var pageResponse = request.post['http-response'];
		var pageUrl = request.post['http-url'];
		var responseHeaders = request.post['http-headers'];

		pageResponse = atob(pageResponse);
		pageUrl = atob(pageUrl);
		responseHeaders = atob(responseHeaders);

		//headers = JSON.parse(responseHeaders);
		headers = responseHeaders;

		if(DEBUG) {
			console.log("Processing Post Request");
		}

		xssResults = parsePage(pageResponse,pageUrl,headers);

		// Return XSS Results
		if(xssResults) {
			// XSS is found, return information here
			response.statusCode = 200;
			response.write(JSON.stringify(xssResults));
			response.close();
		} else {
			response.statusCode = 201;
			response.write("No XSS found in response");
			response.close();
		}
	} else {
		response.statusCode = 500;
		response.write("Server is only designed to handle POST requests");
		response.close();
	}

	// Re-initialize webpage after parsing request
	wp = reInitializeWebPage();
	pageResponse = null;
	xssResults = null;
});
	
