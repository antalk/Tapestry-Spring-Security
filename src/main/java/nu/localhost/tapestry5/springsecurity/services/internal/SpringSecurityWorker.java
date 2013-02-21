/*
 * Copyright 2007 Ivan Dubrov
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

import java.util.ArrayList;
import java.util.List;

import org.apache.tapestry5.ComponentResources;
import org.apache.tapestry5.annotations.BeginRender;
import org.apache.tapestry5.annotations.CleanupRender;
import org.apache.tapestry5.model.MutableComponentModel;
import org.apache.tapestry5.plastic.FieldHandle;
import org.apache.tapestry5.plastic.MethodAdvice;
import org.apache.tapestry5.plastic.MethodInvocation;
import org.apache.tapestry5.plastic.PlasticClass;
import org.apache.tapestry5.plastic.PlasticField;
import org.apache.tapestry5.plastic.PlasticMethod;
import org.apache.tapestry5.services.TransformConstants;
import org.apache.tapestry5.services.transform.ComponentClassTransformWorker2;
import org.apache.tapestry5.services.transform.TransformationSupport;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.intercept.InterceptorStatusToken;

/**
 * @author Ivan Dubrov
 */
public class SpringSecurityWorker implements ComponentClassTransformWorker2 {

    private SecurityChecker securityChecker;
    private final static String STATUS_TOKEN ="$_token";

    public SpringSecurityWorker(final SecurityChecker securityChecker) {

        this.securityChecker = securityChecker;
    }
    
    public void transform(PlasticClass plasticClass,
    		TransformationSupport support, MutableComponentModel model) {
    	
        // Secure methods
        for (PlasticMethod method : plasticClass.getMethodsWithAnnotation(Secured.class)) {
            transformMethod(plasticClass, method);
        }

        // Secure pages
        Secured annotation = plasticClass.getAnnotation(Secured.class);
        if (annotation != null) {
        	model.addRenderPhase(BeginRender.class);
            model.addRenderPhase(CleanupRender.class);
            transformPage(plasticClass, annotation);
        }
    }
   
    private void transformPage(final PlasticClass plasticClass, final Secured annotation) {

        final ConfigAttributeHolder confAttrHolder = createConfigAttributeDefinitionField(plasticClass, annotation);
        
        PlasticMethod beginRenderMethod = plasticClass.introduceMethod(TransformConstants.BEGIN_RENDER_DESCRIPTION);

        final SecurityChecker secChecker = this.securityChecker;
        MethodAdvice beginRenderAdvice = new MethodAdvice() {
        	
        	public void advise(MethodInvocation invocation) {
        		
        		invocation.proceed();
                final InterceptorStatusToken statusTokenVal = secChecker.checkBefore(confAttrHolder);
                final ComponentResources componentResources = invocation.getInstanceContext().get(ComponentResources.class);
        		componentResources.storeRenderVariable(STATUS_TOKEN, statusTokenVal);        		
            }
        };

        beginRenderMethod.addAdvice(beginRenderAdvice);

        // ---------------- END TRANSFORMATION ------------------------


        PlasticMethod cleanupRenderMethod = plasticClass.introduceMethod(TransformConstants.CLEANUP_RENDER_DESCRIPTION);

        MethodAdvice cleanupRenderAdvice = new MethodAdvice() {
        	
        	public void advise(MethodInvocation invocation) {
        	    invocation.proceed();

        	    final ComponentResources componentResources = invocation.getInstanceContext().get(ComponentResources.class);
        	    final InterceptorStatusToken tokenFieldValue = (InterceptorStatusToken) componentResources.getRenderVariable(STATUS_TOKEN);
                secChecker.checkAfter(tokenFieldValue, null);
            }
        };

        cleanupRenderMethod.addAdvice(cleanupRenderAdvice);

        // ------------- END TRANSFORMATION ------------------------

    }

    private void transformMethod(final PlasticClass plasticClass, final PlasticMethod method) {

        final PlasticField tokenFieldInstance = plasticClass.introduceField(InterceptorStatusToken.class,"_$token");
        final FieldHandle tokenFieldHandle = tokenFieldInstance.getHandle();
        
        
        // Attribute definition
        final Secured annotation = method.getAnnotation(Secured.class);
        //final String configField = createConfigAttributeDefinitionField(transformation, annotation);
        final ConfigAttributeHolder confAttrHolder = createConfigAttributeDefinitionField(plasticClass, annotation);

        final SecurityChecker secChecker = this.securityChecker;
        MethodAdvice securedMethodAdvice = new MethodAdvice() {
        	
        	public void advise(MethodInvocation invocation) {
        		
        	    InterceptorStatusToken statusTokenVal = secChecker.checkBefore(confAttrHolder);
        	    tokenFieldHandle.set(invocation.getInstance(), statusTokenVal);
                
                invocation.proceed();

                InterceptorStatusToken tokenFieldValue = (InterceptorStatusToken) tokenFieldHandle.get(invocation.getInstance());
                secChecker.checkAfter(tokenFieldValue, null);
            }
        };

        method.addAdvice(securedMethodAdvice);
    }

    private ConfigAttributeHolder createConfigAttributeDefinitionField(
            final PlasticClass plasticClass,
            final Secured annotation) {

        List<ConfigAttribute> configAttributeDefinition = new ArrayList<ConfigAttribute>();
        for (String annValue : annotation.value()) {
            configAttributeDefinition.add(new SecurityConfig(annValue));
        }
        ConfigAttributeHolder configAttributeHolder = new ConfigAttributeHolder(configAttributeDefinition);
        plasticClass.introduceField(
                ConfigAttributeHolder.class,
                "_$configAttributeDefinition").inject(configAttributeHolder);
        return configAttributeHolder;
    }
}
