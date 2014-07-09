package nu.localhost.tests;

import java.util.ArrayList;
import java.util.Collection;

import junit.framework.TestCase;
import nu.localhost.testsite.utils.MockFactory;

import org.apache.tapestry5.internal.test.TestableResponse;
import org.apache.tapestry5.test.PageTester;
import org.easymock.EasyMock;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * test for https://github.com/antalk/Tapestry-Spring-Security/issues/5
 * 
 * @author avankalleveen
 *
 */
public class AllRolesTest extends TestCase {
	
	@Override
	protected void setUp() throws Exception {
		EasyMock.reset(MockFactory.getInstance().getMockedObjects());
		super.setUp();
	}
	
	@Override
	protected void tearDown() throws Exception {
		EasyMock.reset(MockFactory.getInstance().getMockedObjects());
	}
	
	public void testHasAllRoles() {
		String appPackage = "nu.localhost.testsite";
        String appName = "test";
        PageTester tester = new PageTester(appPackage, appName, "src/test/resources/webapp");
        
        // lets login..
        SecurityContextHolder.setContext(new SecurityContext() {
			
			@Override
			public void setAuthentication(Authentication authentication) {
				// TODO Auto-generated method stub
				
			}
			
			@Override
			public Authentication getAuthentication() {
				return new Authentication() {
					
					@Override
					public String getName() {
						// TODO Auto-generated method stub
						return null;
					}
					
					@Override
					public void setAuthenticated(boolean isAuthenticated)
							throws IllegalArgumentException {
						// TODO Auto-generated method stub
						
					}
					
					@Override
					public boolean isAuthenticated() {
						return true;
					}
					
					@Override
					public Object getPrincipal() {
						return "user";
					}
					
					@Override
					public Object getDetails() {
						// TODO Auto-generated method stub
						return null;
					}
					
					@Override
					public Object getCredentials() {
						// TODO Auto-generated method stub
						return null;
					}
					
					@Override
					public Collection<? extends GrantedAuthority> getAuthorities() {
						// this is to test differences between implementations of GrantedAuthority,
						// see the containsAll method in ifRole
						Collection<GrantedAuthorityImpl> auth = new ArrayList<GrantedAuthorityImpl>();
						auth.add(new GrantedAuthorityImpl("GROUP1"));
						return  auth;
					}
				};
			}
		});
        
        
        TestableResponse response = tester.renderPageAndReturnResponse("AllRolesPage");
        if (response.getStatus() != 200) {
        	fail(response.getErrorMessage());
        } 
        System.err.println(response.getOutput());
        
        assertTrue(response.getOutput().contains("Welcome group1"));
        SecurityContextHolder.clearContext();
	}
}
