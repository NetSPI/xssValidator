var webserver = require('webserver');
var server = webserver.create();
var service = server.listen('127.0.0.1:8080', function(request, response) {
  response.statusCode = 200;
  response.write('<html><body>Hello!</body></html>');
  response.close();
});