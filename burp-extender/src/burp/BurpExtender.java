package burp;
import burp.*;

public class BurpExtender implements IBurpExtender	{
	public burp.IBurpExtenderCallbacks mCallbacks;
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		mCallbacks = callbacks;
	}
	
	public static void main(String[] args) {
		System.out.println("test");
	}
}
