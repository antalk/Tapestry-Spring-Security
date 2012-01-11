/*
 * Copyright 2008 Robin Helgelin
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

package nu.localhost.tapestry5.springsecurity.services;

import org.springframework.security.authentication.dao.SaltSource;


/**
 * Interface used for making it easier to override the SaltSource service.
 * 
 * @author Robin Helgelin
 */
public interface SaltSourceService extends SaltSource {

}
