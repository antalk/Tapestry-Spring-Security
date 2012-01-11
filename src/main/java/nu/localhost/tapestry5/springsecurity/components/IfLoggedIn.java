/*
 * Copyright 2007 Robin Helgelin
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

package nu.localhost.tapestry5.springsecurity.components;

import java.security.Principal;

import org.apache.tapestry5.Block;
import org.apache.tapestry5.annotations.Parameter;
import org.apache.tapestry5.ioc.annotations.Inject;
import org.apache.tapestry5.services.RequestGlobals;

/**
 * Render it's body depending whether the user is logged in or not.
 * 
 * @author Robin Helgelin
 * @author Tapestry Project (doc comments)
 */
public class IfLoggedIn {
    /**
     * Optional parameter to invert the test. If true, then the body is rendered when the test
     * parameter is false (not true).
     */
    @Parameter
    private boolean negate;

    /**
     * An alternate {@link Block} to render if the test parameter is false. The default, null, means
     * render nothing in that situation.
     */
    @Parameter(name = "else")
    private Block elseBlock;

    @Inject
    private RequestGlobals requestGlobals;
    
    private boolean test() {
    	Principal principal = requestGlobals.getHTTPServletRequest().getUserPrincipal();
        return principal != null && principal.getName() != "";
    }

    /**
     * Returns null if the test method returns true, which allows normal rendering (of the body). If
     * the test parameter is false, returns the else parameter (this may also be null).
     */
    Object beginRender() {
        if (test() != negate) {
            return null;
        } else {
            return elseBlock;
        }
    }

    /**
     * If the test method returns true, then the body is rendered, otherwise not. The component does
     * not have a template or do any other rendering besides its body.
     */
    boolean beforeRenderBody() {
        return test() != negate;
    }

    void setup(String role, boolean negate, Block elseBlock) {
        this.negate = negate;
        this.elseBlock = elseBlock;
    }
}
