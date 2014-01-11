<script>
var flag = new Object;
flag.set = 0;
var xss = new Object;

xss.message = 0;

(function () {
	var XSSTripwire = new Object();

	XSSTripwire.lockdown = function(obj, name) {
		if(Object.defineProperty) {
			Object.defineProperty(obj, name, {
			get: function(){flag.set = 1; xss.message = "[PhantomJS Alert] Suspicious Client-Side Code Execution Detected: " + obj + "." + name; return function(){}},
			set: function(){return false;},
			configurable: false
			})
		}
	}

	XSSTripwire.proxy = function(obj, name, report_function_name,exec_original) {
	var proxy = obj[name];
	obj[name] = function() {
		if(exec_original) {
		return proxy.apply(this,arguments);
		}
	};
	XSSTripwire.lockdown(obj,name);
	};

	XSSTripwire.proxy(console, 'log', 'console.log', true);
	XSSTripwire.proxy(window, 'alert', 'window.alert', true);
	XSSTripwire.proxy(window, 'confirm', 'window.confirm', true);
	XSSTripwire.proxy(window, 'prompt', 'window.prompt', true);
	XSSTripwire.proxy(window, 'unescape', 'window.unescape', true);
	XSSTripwire.proxy(document, 'write', 'document.write', true);
	XSSTripwire.proxy(String, 'fromCharCode', 'String.fromCharCode', true);
})();
</script>
