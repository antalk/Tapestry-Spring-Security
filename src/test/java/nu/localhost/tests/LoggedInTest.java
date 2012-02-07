package nu.localhost.tests;

import java.security.Principal;

import junit.framework.TestCase;
import nu.localhost.testsite.utils.MockFactory;

import org.apache.tapestry5.dom.Document;
import org.apache.tapestry5.test.PageTester;
import org.easymock.EasyMock;

public class LoggedInTest extends TestCase {
	
	@Override
	protected void setUp() throws Exception {
		EasyMock.reset(MockFactory.getInstance().getMockedObjects());
		super.setUp();
	}
	
	@Override
	protected void tearDown() throws Exception {
		EasyMock.reset(MockFactory.getInstance().getMockedObjects());
	}
	
	public void testIsLoggedIn() {
		String appPackage = "nu.localhost.testsite";
        String appName = "test";
        PageTester tester = new PageTester(appPackage, appName, "src/test/resources/webapp");
        
        EasyMock.expect(MockFactory.getInstance().getMockedServletRequest().getUserPrincipal()).andReturn(null).times(2);
        
        EasyMock.replay(MockFactory.getInstance().getMockedObjects());
        Document dom = tester.renderPage("LoggedIn");
        EasyMock.verify(MockFactory.getInstance().getMockedObjects());
        
        assertTrue(dom.toString().contains("Welcome back anonymous"));
        
        EasyMock.reset(MockFactory.getInstance().getMockedObjects());
        
        
        EasyMock.expect(MockFactory.getInstance().getMockedServletRequest().getUserPrincipal()).andReturn(new Principal() {

			@Override
			public String getName() {
				return "User1";
			}}).times(2);
        
        EasyMock.replay(MockFactory.getInstance().getMockedObjects());
        dom = tester.renderPage("LoggedIn");
        EasyMock.verify(MockFactory.getInstance().getMockedObjects());
        EasyMock.reset(MockFactory.getInstance().getMockedObjects());
       	assertTrue(dom.toString().contains("Welcome back user"));
        
	}
	
	

}
