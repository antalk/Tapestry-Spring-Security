package nu.localhost.testsite.utils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.ArrayUtils;
import org.apache.tapestry5.services.Request;
import org.easymock.EasyMock;

public class MockFactory {

	private HttpServletResponse mockedServletResponse;
	private HttpServletRequest mockedServletRequest;
	private Request mockedRequest;
	
	private Object[] mocks;
	
	private static MockFactory me;

	private MockFactory() {
		mocks = new Object[] {};
		// Pre-register all mocks
		getMockedServletRequest();
		getMockedRequest();
		getMockedServletResponse();
	}
	
	public static MockFactory getInstance() {
		if (me == null) {
			me = new MockFactory();
			
		}
		return me;
	}
	

	
	public HttpServletRequest getMockedServletRequest() {
		if (mockedServletRequest == null) {
			mockedServletRequest = EasyMock.createMock(HttpServletRequest.class);
			mocks = ArrayUtils.add(mocks, mockedServletRequest);
		}
		return mockedServletRequest;	
	}
	
	public HttpServletResponse getMockedServletResponse() {
		if (mockedServletResponse == null) {
			mockedServletResponse = EasyMock.createMock(HttpServletResponse.class);
			mocks = ArrayUtils.add(mocks, mockedServletResponse);
		}
		return mockedServletResponse;	
	}
	
	public Request getMockedRequest() {
		if (mockedRequest == null) {
			mockedRequest = EasyMock.createMock(Request.class);
			mocks = ArrayUtils.add(mocks, mockedRequest);
		}
		return mockedRequest;	
	}
	
	public void reset() {
		EasyMock.reset(mocks);
	}
	
	public Object[] getMockedObjects() {
		return mocks;
	}

}
