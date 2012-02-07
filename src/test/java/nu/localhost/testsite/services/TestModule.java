package nu.localhost.testsite.services;

import java.io.IOException;

import nu.localhost.tapestry5.springsecurity.services.SecurityModule;
import nu.localhost.testsite.utils.MockFactory;

import org.apache.tapestry5.SymbolConstants;
import org.apache.tapestry5.ioc.MappedConfiguration;
import org.apache.tapestry5.ioc.OrderedConfiguration;
import org.apache.tapestry5.ioc.annotations.SubModule;
import org.apache.tapestry5.services.Request;
import org.apache.tapestry5.services.RequestFilter;
import org.apache.tapestry5.services.RequestGlobals;
import org.apache.tapestry5.services.RequestHandler;
import org.apache.tapestry5.services.Response;

@SubModule(SecurityModule.class)
public class TestModule {

	
	public static void contributeApplicationDefaults(
			final MappedConfiguration<String, String> configuration) {
				
		configuration.add(SymbolConstants.PRODUCTION_MODE, "true");
	}
	
	/**
     * Ensure that there are valid HTTP request/response objects in the test, otherwise the spring security integration tends to blow up.
     * 
     * From: http://tapestry.1045711.n5.nabble.com/Tapestry-Spring-Security-amp-Page-Testing-td2433482.html
     */
    public static void contributeRequestHandler(OrderedConfiguration<RequestFilter> config, 
    		final RequestGlobals requestGlobals) {
        
    	RequestFilter filter = new RequestFilter() {
    		
    		@Override
    		public boolean service(Request request, Response response,
    				RequestHandler handler) throws IOException {
    		
                requestGlobals.storeServletRequestResponse(MockFactory.getInstance().getMockedServletRequest(), MockFactory.getInstance().getMockedServletResponse());
                return handler.service(request, response);
            }
        };
        config.add("EnsureNonNullHttpRequestAndResponse", filter,"before:*");
    } 
}
