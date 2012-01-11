/*
 * Copyright 2009 Michael Gerzabek
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
package nu.localhost.tapestry5.springsecurity.services.internal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.tapestry5.services.RequestGlobals;
import org.apache.tapestry5.services.Session;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

/**
 * @author Michael Gerzabek
 */
public class TapestryLogoutHandler implements LogoutHandler {

    private RequestGlobals globals;
    
    public TapestryLogoutHandler( RequestGlobals globals ) {

        this.globals = globals;
    }

    public void logout( HttpServletRequest request, HttpServletResponse response, Authentication authentication ) {

        Session session = globals.getRequest().getSession( false );
        if ( null != session ) session.invalidate();
    }

}
