package nu.localhost.tapestry5.springsecurity.util;

import javax.servlet.ServletException;

import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.security.web.util.ThrowableCauseExtractor;

public class DefaultThrowableAnalyzer extends ThrowableAnalyzer {

	/**
     * @see org.springframework.security.util.ThrowableAnalyzer#initExtractorMap()
     */
    protected void initExtractorMap() {
        super.initExtractorMap();

        registerExtractor(ServletException.class, new ThrowableCauseExtractor() {
                    public Throwable extractCause(Throwable throwable) {
                ThrowableAnalyzer.verifyThrowableHierarchy(throwable, ServletException.class);
                return ((ServletException) throwable).getRootCause();
                    }
                });
    }
}
