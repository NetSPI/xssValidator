<p align="center">
<img src="https://raw.githubusercontent.com/nVisium/xssValidator/gh-pages/images/xssValidator.png">
</p>

This is a burp intruder extender that is designed for automation and validation of XSS 
vulnerabilities.

For more information, check out this blog post: http://blog.nvisium.com/2014/01/accurate-xss-detection-with-burpsuite.html


XSS Detection
-------------

The burp intruder extender will be designed to forward responses to the XSS detection
server, that will need to be running externally. 

The XSS detection server is powered by Phantom.js.

The XSS detection is influenced by Trustwave's blog post: Server-Side XSS Attack Detection with ModSecurity and PhantomJS:http://blog.spiderlabs.com/2013/02/server-site-xss-attack-detection-with-modsecurity-and-phantomjs.html

Building Extender .Jar with bash script
----------------------

There is a script that will work with any debian-based distributions,
buildXssValidatorJar.sh. To run it:

    $ bash /path/to/xssValidator/buildXssValidatorJar.sh

After this has completed you should see a BUILD SUCCESSFUL message. The .jar file is located in /path/to/xssValidator/burp-extender/bin/burp/xssValidator.jar. Import this into Burp.

Building Extender .Jar
----------------------

To build the extender .jar file, we first need to ensure that the system has ant, and is running version Java 7 or higher.

First, download the apache HttpComponents Client libraries. These libraries are available for free from http://hc.apache.org/. Once the libraries have been downloaded, create a lib directory in the project root and move the .jar libraries into this directory:

    $ mkdir /path/to/xssValidator/burp-extender/lib
    $ mv /path/to/libs/*.jar /path/to/xssValidator/burp-extender/lib/
 
Now, navigate to the burp-extender/bin/burp directory:

    $ cd burp-extender/bin/burp

Build the jar using Apache ant:

    $ ant

After this has completed you should see a BUILD SUCCESSFUL message. The .jar file is located in /path/to/xssValidator/burp-extender/bin/burp/xssValidator.jar. Import this into Burp.

Building Extender .Jar using Puppet
----------------------

A puppet module to build xssValidator can be found at
https://github.com/l50/puppet-xss_validator.

Usage
-----

Before starting an attack it is necessary to start the phantom xss-detection server. Navigate to the xss-detector directory and execute the following to start phantom.js xss-detection script:

    $ phantomjss xss.js &

The server is expecting base64 encoded page responses passed via the http-response, which will be passed via the Burp extender. 

Examples
--------

Within the xss-detector directory there is a folder of examples which can be used to test
the extenders functionality.

* **Basic-xss.php**: This is the most basic example of a web application that is vulnerable to XSS. It demonstrates how legitimate javascript functionality, such as alerts and console logs, do not trigger false-positives.
* **Bypass-regex.php**: This demonstrates a XSS vulnerability that occurs when users attempt to filter input by running it through a single-pass regex.
* **Dom-xss.php**: A basic script that demonstrates the tools ability to inject payloads into javascript functionality, and detect their success.
