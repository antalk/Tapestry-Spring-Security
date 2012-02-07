/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 * Copyright 2007, 2008 Robin Helgelin
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

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import nu.localhost.tapestry5.springsecurity.util.DefaultThrowableAnalyzer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * @author Ben Alex
 * @author Colin Sampaleanu
 * @author Robin Helgelin
 * @author Michael Gerzabek
 */
/*
 * Since we need this filter also in the chain of the HttpServletRequestFilters
 * I copied the ExceptionTranslationFilter from Spring and adapted it to
 * fullfill both our T5 HttpServletRequestFilterWrapper and RequestFilterWrapper
 * signatures.
 */
public class SpringSecurityExceptionTranslationFilter extends GenericFilterBean {

    //~ Instance fields ================================================================================================

    private static final Logger logger = LoggerFactory.getLogger(SpringSecurityExceptionTranslationFilter.class);
    
    private AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandlerImpl();
    private AuthenticationEntryPoint authenticationEntryPoint;
    private AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();
    private PortResolver portResolver = new PortResolverImpl();
    private ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();

    private RequestCache requestCache = new HttpSessionRequestCache();
    
    @Override
    public void afterPropertiesSet() throws ServletException {
    	Assert.notNull(authenticationEntryPoint, "authenticationEntryPoint must be specified");
    }

    //~ Methods ========================================================================================================

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        try {
            chain.doFilter(request, response);

            if (logger.isDebugEnabled()) {
                logger.debug("Chain processed normally");
            }
        } catch (IOException ex) {
            throw ex;
        } catch (Exception ex) {
            // Try to extract a SpringSecurityException from the stacktrace
            Throwable[] causeChain = throwableAnalyzer.determineCauseChain(ex);
            RuntimeException ase = (AuthenticationException)
                    throwableAnalyzer.getFirstThrowableOfType(AuthenticationException.class, causeChain);

            if (ase == null) {
                ase = (AccessDeniedException)throwableAnalyzer.getFirstThrowableOfType(AccessDeniedException.class, causeChain);
			}

            if (ase != null) {
                handleException(request, response, chain, ase);
            } else {
                // Rethrow ServletExceptions and RuntimeExceptions as-is
                if (ex instanceof ServletException) {
                    throw (ServletException) ex;
                } else if (ex instanceof RuntimeException) {
                    throw (RuntimeException) ex;
                }

                // Wrap other Exceptions. These are not expected to happen
                throw new RuntimeException(ex);
            }
        }
    }

    public AuthenticationEntryPoint getAuthenticationEntryPoint() {
        return authenticationEntryPoint;
    }

    public AuthenticationTrustResolver getAuthenticationTrustResolver() {
        return authenticationTrustResolver;
    }


    public PortResolver getPortResolver() {

        return portResolver;
    }

    private void handleException(HttpServletRequest request,
            HttpServletResponse response, FilterChain chain,
            RuntimeException exception) throws IOException,
            ServletException {

        if (exception instanceof AuthenticationException) {
            if (logger.isDebugEnabled()) {
                logger.debug("Authentication exception occurred; redirecting to authentication entry point", exception);
            }

            sendStartAuthentication(request, response, chain, (AuthenticationException) exception);
        }
        else if (exception instanceof AccessDeniedException) {
            if (authenticationTrustResolver.isAnonymous(SecurityContextHolder.getContext().getAuthentication())) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Access is denied (user is anonymous); redirecting to authentication entry point",
                                    exception);
                }

                sendStartAuthentication(request, response, chain, new InsufficientAuthenticationException(
                                "Full authentication is required to access this resource"));
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug("Access is denied (user is not anonymous); delegating to AccessDeniedHandler",
                                    exception);
                }

                accessDeniedHandler.handle(request, response, (AccessDeniedException) exception);
            }
        }
    }

    protected void sendStartAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            AuthenticationException reason) throws ServletException, IOException {
        // SEC-112: Clear the SecurityContextHolder's Authentication, as the
        // existing Authentication is no longer considered valid
        SecurityContextHolder.getContext().setAuthentication(null);
        requestCache.saveRequest(request, response);
        logger.debug("Calling Authentication entry point.");
        authenticationEntryPoint.commence(request, response, reason);
    }

    public void setAccessDeniedHandler(AccessDeniedHandler accessDeniedHandler) {
        Assert.notNull(accessDeniedHandler, "AccessDeniedHandler required");
        this.accessDeniedHandler = accessDeniedHandler;
    }

    public void setAuthenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    public void setAuthenticationTrustResolver(AuthenticationTrustResolver authenticationTrustResolver) {
        Assert.notNull(authenticationTrustResolver, "authenticationTrustResolver must not be null");
        this.authenticationTrustResolver = authenticationTrustResolver;
    }

//    public void setCreateSessionAllowed(boolean createSessionAllowed) {
//        this.createSessionAllowed = createSessionAllowed;
//    }

//    public void setPortResolver(PortResolver portResolver) {
//        this.portResolver = portResolver;
//    }

    public void setThrowableAnalyzer(ThrowableAnalyzer throwableAnalyzer) {
        Assert.notNull(throwableAnalyzer, "throwableAnalyzer must not be null");
        this.throwableAnalyzer = throwableAnalyzer;
    }

	//    public int getOrder() {
//
//        return FilterChainOrder.EXCEPTION_TRANSLATION_FILTER;
//    }
    /**
     * The RequestCache implementation used to store the current request before starting authentication.
     * Defaults to an {@link HttpSessionRequestCache}.
     */
    public void setRequestCache(RequestCache requestCache) {
        Assert.notNull(requestCache, "requestCache cannot be null");
        this.requestCache = requestCache;
	}
}
