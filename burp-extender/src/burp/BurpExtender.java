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
	
	public static final byte[][] PAYLOADS = {
		"|".getBytes(),
		"<script>alert(1)</script>".getBytes()
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
    public String getProcessorName()
    {
        return "XSS Validator";
    }
    
    @Override
    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue) {
    	return helpers.stringToBytes(helpers.urlEncode(helpers.bytesToString(currentPayload)));
    }
    
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		stdout.println("HTTP Listener started...");
		
        if (toolFlag == 32 && messageIsRequest) {
        	stdout.println("HTTP Listener intruder http request match found...");
        	// Manipulate intruder request, if necessary
        } else if (toolFlag == 32 && ! messageIsRequest) {
        	stdout.println("Response Received");
        	HttpPost PhantomJs = new HttpPost(phantomServer);
        	
        	try {
        		byte[] encodedBytes = Base64.encodeBase64(messageInfo.getResponse());
        		String encodedResponse = helpers.bytesToString(encodedBytes);
        		
	        	List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>(1);
	        	nameValuePairs.add(new BasicNameValuePair("http-response", encodedResponse));
	        	//PhantomJs.setEntity(nameValuePairs);
	        	PhantomJs.setEntity(new UrlEncodedFormEntity(nameValuePairs));

	        	HttpResponse response = client.execute(PhantomJs);
	        	String responseAsString = EntityUtils.toString(response.getEntity());
	            stdout.println(responseAsString);
        	} catch (Exception e) {
        		stderr.println(e.getMessage());
        	}
        }
        stdout.println("HTTP Listener finished...");
	}
		
	class IntruderPayloadGenerator implements IIntruderPayloadGenerator {
		int payloadIndex;
		
		@Override
		public boolean hasMorePayloads() {
			System.out.println("Checking for more payloadz");
			return payloadIndex < PAYLOADS.length;
		}
		
		@Override
		public byte[] getNextPayload(byte[] baseValue) {
			System.out.println("Getting next payload");
			
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
