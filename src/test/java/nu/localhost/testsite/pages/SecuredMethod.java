package nu.localhost.testsite.pages;

import org.springframework.security.access.annotation.Secured;

public class SecuredMethod {
	
	@Secured("ROLE_LOGGEDIN")
	public String getWelcomeText() {
		return "Welcome back user !";
	}
		

}
