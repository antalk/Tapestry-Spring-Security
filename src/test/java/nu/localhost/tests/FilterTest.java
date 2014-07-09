package nu.localhost.tests;

import java.io.IOException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import junit.framework.TestCase;
import nu.localhost.testsite.utils.MockFactory;

import org.apache.tapestry5.services.HttpServletRequestHandler;
import org.apache.tapestry5.test.PageTester;
import org.easymock.EasyMock;

/**
 * This will test https://github.com/antalk/Tapestry-Spring-Security/issues/10
 * 
 * @author antalk
 *
 */
public class FilterTest extends TestCase {
	
	@Override
	protected void setUp() throws Exception {
		EasyMock.reset(MockFactory.getInstance().getMockedObjects());
		super.setUp();
	}
	
	@Override
	protected void tearDown() throws Exception {
		EasyMock.reset(MockFactory.getInstance().getMockedObjects());
	}

	public void testFilter() {
		String appPackage = "nu.localhost.testsite";
        String appName = "test";
        PageTester tester = new PageTester(appPackage, appName, "src/test/resources/webapp");
        
        HttpServletRequest mockRequest = MockFactory.getInstance().getMockedServletRequest();
        HttpServletResponse mockResponse = MockFactory.getInstance().getMockedServletResponse();
        
        EasyMock.expect(mockRequest.getAttribute("__spring_security_scpf_applied")).andReturn(false).anyTimes();
        EasyMock.expect(mockRequest.getServletPath()).andReturn("/").anyTimes();
        EasyMock.expect(mockRequest.getPathInfo()).andReturn("/").anyTimes();
        EasyMock.expect(mockRequest.getRequestURI()).andReturn("/").anyTimes();
        EasyMock.expect(mockRequest.getProtocol()).andReturn("http").anyTimes();
        EasyMock.expect(mockRequest.getContextPath()).andReturn("/").anyTimes();
        EasyMock.expect(mockRequest.getHeader("Accept-Encoding")).andReturn("UTF8").anyTimes();
        EasyMock.expect(mockRequest.getCookies()).andReturn(new Cookie[]{}).anyTimes();
        EasyMock.expect(mockRequest.getRemoteAddr()).andReturn("").anyTimes();
        EasyMock.expect(mockRequest.getSession(false)).andReturn(null).anyTimes();
        EasyMock.expect(mockRequest.getAttribute("__spring_security_filterSecurityInterceptor_filterApplied")).andReturn(false).anyTimes();
        
        EasyMock.replay(MockFactory.getInstance().getMockedObjects());
        try {
			tester.getService(HttpServletRequestHandler.class).service(mockRequest, mockResponse);
		} catch (IOException e) {
			fail(e.getMessage());
		}
        
	}
}
