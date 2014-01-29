xssValidator
============

This is a burp intruder extender that is designed for automation and validation of XSS
vulnerabilities.


XSS Detection
-------------

The burp intruder extender will be designed to forward responses to the XSS detection
server, that will need to be running externally. 

The XSS detection server is powered by Phantom.js and leverages webkit's XSS auditor.

The XSS detection is influenced by Trustwave's blog post: Server-Side XSS Attack Detection with ModSecurity and PhantomJS:http://blog.spiderlabs.com/2013/02/server-site-xss-attack-detection-with-modsecurity-and-phantomjs.html

Usage
-----

Before starting an attack it is necessary to start the phantom server. Navigate to the xss-detector directory and execute the following:

	$ phantomjs xss.js 

The server will listen by default on port 8093. The server is expecting base64 encoded page responses passed via the http-response, which will be passed via the Burp extender. 

Examples
--------

Within the xss-detector directory there is a folder of examples which can be used to test
the extenders functionality.

* **Basic-xss.php**: This is the most basic example of a web application that is vulnerable to XSS. It demonstrates how legitimate javascript functionality, such as alerts and console logs, do not trigger false-positives.