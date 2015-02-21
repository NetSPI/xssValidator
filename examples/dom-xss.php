<html>
<body>
Hello
<script>
var pos=document.URL.indexOf("context=")+8; 
document.write(decodeURIComponent(document.URL.substring(pos,document.URL.length)));
</script>
</body>
</html>
