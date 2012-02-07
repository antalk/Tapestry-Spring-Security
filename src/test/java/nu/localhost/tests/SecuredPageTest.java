package nu.localhost.tests;

import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

import javax.servlet.ServletContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionContext;

import junit.framework.TestCase;
import nu.localhost.testsite.utils.MockFactory;

import org.apache.tapestry5.internal.test.TestableResponse;
import org.apache.tapestry5.test.PageTester;
import org.easymock.EasyMock;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.SavedRequest;

public class SecuredPageTest extends TestCase {
	
	private HttpSession internalSession;
	
	
	@Override
	protected void setUp() throws Exception {
		EasyMock.reset(MockFactory.getInstance().getMockedObjects());
		internalSession = new MySession();
		super.setUp();
	}
	
	@Override
	protected void tearDown() throws Exception {
		EasyMock.reset(MockFactory.getInstance().getMockedObjects());
	}
	
	
	public void testDisplaySecureContent() {
		String appPackage = "nu.localhost.testsite";
        String appName = "test";
        PageTester tester = new PageTester(appPackage, appName, "src/test/resources/webapp");
        
        HttpServletRequest mockRequest = MockFactory.getInstance().getMockedServletRequest();
        HttpServletResponse mockResponse = MockFactory.getInstance().getMockedServletResponse();
        
        
        EasyMock.expect(mockRequest.getCookies()).andReturn(new Cookie[] {}).anyTimes();
        EasyMock.expect(mockRequest.getHeaderNames()).andReturn(new Vector<String>().elements());
        EasyMock.expect(mockRequest.getLocales()).andReturn(new Vector<String>().elements());
        EasyMock.expect(mockRequest.getParameterMap()).andReturn(new HashMap<String, Object>());
        
        
        EasyMock.expect(mockRequest.getMethod()).andReturn("GET");
        EasyMock.expect(mockRequest.getPathInfo()).andReturn("/");
        EasyMock.expect(mockRequest.getQueryString()).andReturn("");
        EasyMock.expect(mockRequest.getRequestURI()).andReturn("");
        
        
        EasyMock.expect(mockRequest.getServerPort()).andReturn(80).anyTimes();
        EasyMock.expect(mockRequest.getScheme()).andReturn("http").anyTimes();
        
        EasyMock.expect(mockRequest.getRequestURL()).andReturn(new StringBuffer(""));
        EasyMock.expect(mockRequest.getServerName()).andReturn("localhost").anyTimes();
        EasyMock.expect(mockRequest.getContextPath()).andReturn("").anyTimes();
        EasyMock.expect(mockRequest.getServletPath()).andReturn("").anyTimes();
        
        EasyMock.expect(mockRequest.getSession()).andReturn(internalSession).anyTimes();
        
        EasyMock.expect(mockResponse.encodeRedirectURL("http://localhost/loginpage")).andReturn("http://localhost/loginpage").atLeastOnce();
        
        try {
			mockResponse.sendRedirect("http://localhost/loginpage");
		} catch (IOException e) {
			fail(e.getMessage());
		}
        EasyMock.expectLastCall();
        
        EasyMock.replay(MockFactory.getInstance().getMockedObjects());
        TestableResponse  resp = tester.renderPageAndReturnResponse("SecuredPage");
        
        assertEquals(200,resp.getStatus());
        
        EasyMock.verify(MockFactory.getInstance().getMockedObjects());
        EasyMock.reset(MockFactory.getInstance().getMockedObjects());
        
        assertEquals("DefaultSavedRequest[http://localhost?]",internalSession.getAttribute("SPRING_SECURITY_SAVED_REQUEST").toString());
	}
	
	private class MySession implements HttpSession {

		private Map<String,Object> atrs = new HashMap<String, Object>();
		private Map<String,Object> vals = new HashMap<String, Object>();
		
		
		@Override
		public Object getAttribute(String name) {
			return atrs.get(name);
		}

		@Override
		public Enumeration getAttributeNames() {
			return (Enumeration) atrs.keySet();
		}

		@Override
		public long getCreationTime() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public String getId() {
			// TODO Auto-generated method stub
			return "1";
		}

		@Override
		public long getLastAccessedTime() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public int getMaxInactiveInterval() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public ServletContext getServletContext() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public HttpSessionContext getSessionContext() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public Object getValue(String name) {
			return vals.get(name);
		}

		@Override
		public String[] getValueNames() {
			return (String[]) vals.keySet().toArray();
		}

		@Override
		public void invalidate() {
			// TODO Auto-generated method stub
			
		}

		@Override
		public boolean isNew() {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public void putValue(String name, Object value) {
			vals.put(name, value);
			
		}

		@Override
		public void removeAttribute(String name) {
			atrs.remove(name);
			
		}

		@Override
		public void removeValue(String name) {
			vals.remove(name);
			
		}

		@Override
		public void setAttribute(String name, Object value) {
			atrs.put(name, value);
			
		}

		@Override
		public void setMaxInactiveInterval(int interval) {
			// TODO Auto-generated method stub
			
		}

		/**
		 * Constructs a <code>String</code> with all attributes
		 * in name = value format.
		 *
		 * @return a <code>String</code> representation 
		 * of this object.
		 */
		public String toString()
		{
		    final String TAB = "    ";
		    
		    String retValue = "";
		    
		    retValue = "MySession ( "
		        + super.toString() + TAB
		        + "atrs = " + this.atrs + TAB
		        + "vals = " + this.vals + TAB
		        + " )";
		
		    return retValue;
		}
		
		
		
	}
	
	

}
