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
