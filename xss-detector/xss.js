/**
 * This is a basic phantomJS script that will be used together
 * with the XSS auditor burp extender.
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
var system = require('system');
var fs = require('fs');

var wp = new WebPage();
var webserver = require('webserver');
server = webserver.create();


// web page settings necessary to adequately detect XSS
wp.settings = {
	loadImages: true,
	localToRemoteUrlAccessEnabled: true,
	javascriptEnabled: true,
	webSecurityEnabled: true,
	XSSAuditingEnabled: true
};


// Server config details
var host = '127.0.0.1';
var port = '8093';

// Start web server and listen for requests
var service = server.listen(host + ":" + port, function(request, response) {
	console.log("Received request with method type: " + request.method);

	// At this point in time we're only concerned with POST requests
	// As such, only process those.
	if(request.method == "POST") {
		console.log("Processing Post Request");

		// Grab pageResponse from POST Data and base64 decode.
		// pass result to parsePage function to search for XSS.
		var pageResponse = request.post['http-response'];
		pageResponse = atob(pageResponse);
		xssResults = parsePage(pageResponse);

		// Return XSS Results
		if(xssResults) {
			// XSS is found, return information here
			response.statusCode = 200;
			response.write("XSS Detected");
			response.close();
		} else {
			response.statusCode = 201;
			response.write("No XSS found in response");
			response.close();
		}
	} else {
		response.statusCode = 500;
		response.write("Server is not designed to handle GET requests");
		response.close();
	}

	// Re-initialize webpage after parsing request
	wp = new WebPage();
	pageResponse = null;
	xssResults = null;
});
	
/**
 * parse incoming HTTP responses that are provided via BURP intruder.
 * data is base64 encoded to prevent issues passing via HTTP.
 *
 * This function appends the js-overrides.js file to all responses
 * to inject xss triggers into every page. Webkit will parse all responses
 * and alert us of any seemingly malicious Javascript execution, such as
 * alert, confirm, fromCharCode, etc.
 */
parsePage = function(data) {
	console.log("Beginning to parse page");
	// Set variables to default, indicating no intial xss
	var isXSS = new Object();
	isXSS.value = 0;
	isXSS.msg = 'Safe';

	var html_response = "";
	wp.content = fs.read('js-overrides.js') + data;

	// Evaluate page, rendering javascript
	xssInfo = wp.evaluate(function (wp) {
		return xss;
	}, wp);

	if(xssInfo["message"] != 0) {
		// xss detected, return
		console.log("Xss detected:" + isXSS);
		return xssInfo;
	}
	return false;
}