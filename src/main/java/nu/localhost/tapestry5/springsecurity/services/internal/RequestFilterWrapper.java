/*
 * Copyright 2007 Ivan Dubrov
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

package nu.localhost.tapestry5.springsecurity.services.internal;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.tapestry5.services.Request;
import org.apache.tapestry5.services.RequestFilter;
import org.apache.tapestry5.services.RequestGlobals;
import org.apache.tapestry5.services.RequestHandler;
import org.apache.tapestry5.services.Response;

/**
 * @author Ivan Dubrov
 */
public class RequestFilterWrapper implements RequestFilter {
    private RequestGlobals globals;
    private Filter filter;

    public RequestFilterWrapper(final RequestGlobals globals,
            final Filter filter) {
        this.globals = globals;
        this.filter = filter;
    }

    public final boolean service(final Request request,
            final Response response, final RequestHandler handler)
            throws IOException {

        // TODO: Thread safety!
        // Assume request handled if filter chain is NOT executed
        final boolean[] res = new boolean[] {true};
        try {
            filter.doFilter(globals.getHTTPServletRequest(), globals
                    .getHTTPServletResponse(), new FilterChain() {
                public void doFilter(final ServletRequest req,
                        final ServletResponse resp) throws IOException,
                        ServletException {
                    res[0] = handler.service(request, response);
                }
            });
        } catch (ServletException e) {
            IOException ex = new IOException(e.getMessage());
            ex.initCause(e);
            throw ex;
        }
        return res[0];
    }
}
