/*
 *  Copyright 2009 polrtex.
 * 
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *  under the License.
 */

package nu.localhost.tapestry5.springsecurity.services.internal;

import java.util.List;

import org.springframework.security.access.ConfigAttribute;

/**
 *
 * @author akochnev
 */
public class ConfigAttributeHolder {
    private List<ConfigAttribute> attributes;

    public ConfigAttributeHolder(List<ConfigAttribute> attributes) {
        this.attributes = attributes;
    }
    public List<ConfigAttribute> getAttributes() {
        return attributes;
    }
}
