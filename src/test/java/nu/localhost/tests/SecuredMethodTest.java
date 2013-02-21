package nu.localhost.tests;

import junit.framework.TestCase;
import nu.localhost.testsite.utils.MockFactory;

import org.apache.tapestry5.internal.test.TestableResponse;
import org.apache.tapestry5.test.PageTester;
import org.easymock.EasyMock;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

public class SecuredMethodTest extends TestCase {
	
	@Override
	protected void setUp() throws Exception {
		SecurityContextHolder.getContext().setAuthentication(null);
		EasyMock.resetToNice(MockFactory.getInstance().getMockedObjects());
		super.setUp();
	}
	
	@Override
	protected void tearDown() throws Exception {
		EasyMock.resetToStrict(MockFactory.getInstance().getMockedObjects());
	}
	
	public void testPage() {
		String appPackage = "nu.localhost.testsite";
        String appName = "test";
        PageTester tester = new PageTester(appPackage, appName, "src/test/resources/webapp");
        
        EasyMock.replay(MockFactory.getInstance().getMockedObjects());
        TestableResponse resp = tester.renderPageAndReturnResponse("SecuredMethod");
        EasyMock.verify(MockFactory.getInstance().getMockedObjects());
        assertEquals(500,resp.getStatus()); //err not allowed!

        // login..! (wrong role)
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("user1","user1","ROLE_DENIED"));
        
        EasyMock.reset(MockFactory.getInstance().getMockedObjects());
        EasyMock.replay(MockFactory.getInstance().getMockedObjects());
        
        
        try {
        	tester.renderPage("securedmethod");
        	fail("Should not render a document");
        } catch (Exception e) {
        	
        }
        EasyMock.verify(MockFactory.getInstance().getMockedObjects());
        // status = 200 , output = '', coz of redirect to login page
        
        assertEquals(200,resp.getStatus()); //err not allowed!
        
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("user1","user1","ROLE_LOGGEDIN"));
        
        EasyMock.reset(MockFactory.getInstance().getMockedObjects());
        EasyMock.replay(MockFactory.getInstance().getMockedObjects());
        
        assertTrue(tester.renderPage("securedmethod").toString().contains("Welcome back user !"));
        EasyMock.verify(MockFactory.getInstance().getMockedObjects());
        
        assertEquals(200,resp.getStatus()); //err not allowed!
        
	}
}
