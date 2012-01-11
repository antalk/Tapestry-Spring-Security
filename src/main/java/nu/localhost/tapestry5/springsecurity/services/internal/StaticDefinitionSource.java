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

import java.util.Collection;
import java.util.List;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityMetadataSource;

/**
 * Implementation of {@link MethodDefinitionSource} that simply casts security
 * object to the {@link ConfigAttributeDefinition}.
 * 
 * @author Ivan Dubrov
 */
public class StaticDefinitionSource implements SecurityMetadataSource {

    /**
     * This implementation simply casts security object to the
     * {@link ConfigAttributeDefinition}.
     * 
     * @param object
     *            security object
     * @return security object casted to {@link ConfigAttributeDefinition}.
     */
    public final List<ConfigAttribute> getAttributes(final Object object) {
        ConfigAttributeHolder attrHolder = (ConfigAttributeHolder) object;
        return (List<ConfigAttribute>) attrHolder.getAttributes();
    }

    /**
     * Returns true if clazz is extension of {@link ConfigAttributeHolder}.
     * 
     * @param clazz
     *            the class that is being queried
     * @return true if clazz is extension of {@link ConfigAttributeHolder}.
     */
    @SuppressWarnings("unchecked")
    public final boolean supports(final Class clazz) {
        return ConfigAttributeHolder.class.isAssignableFrom(clazz);
    }

    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }
}
