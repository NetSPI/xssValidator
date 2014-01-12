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

// Start web server
var service = server.listen(host + ":" + port, function(request, response) {
	// Listen for requests
	// Grab data from request and pass along to parsePage function
	console.log("Received request");
	console.log("Request Method: " + request.method);

	if(request.method == "POST") {
		var pageResponse = request.post['http-response'];
		pageResponse = atob(pageResponse);
		xssResults = parsePage(pageResponse);

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
	console.log("Parsing: Here's post data - " + data);
	// Set variables to default, indicating no intial xss
	var isXSS = new Object();
	isXSS.value = 0;
	isXSS.msg = 'Safe';

	var html_response = "";
	wp.content = fs.read('js-overrides.js') + data;

	isXSS.msg = wp.evaluate(function () {
		return xss.message;
	});

	if(isXSS.msg) {
		// xss detected, return
		console.log(isXSS.msg);
		return isXSS.msg;
	}
	console.log("Finished parsing request");
	return false;
}