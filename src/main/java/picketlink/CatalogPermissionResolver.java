/*
* JBoss, Home of Professional Open Source
* Copyright 2013, Red Hat, Inc. and/or its affiliates, and individual
* contributors by the @authors tag. See the copyright.txt in the
* distribution for a full listing of individual contributors.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
* http://www.apache.org/licenses/LICENSE-2.0
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package picketlink;

import org.picketlink.Identity;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.model.Agent;
import org.picketlink.idm.model.Role;
import org.picketlink.permission.PermissionResolver;

import javax.inject.Inject;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.io.Serializable;

/**
 * An implementation of the {@link PermissionResolver} that checks
 * whether the user has superuser role
 *
 * @author Anil Saldhana
 * @since 05/5/30
 */
public class CatalogPermissionResolver implements PermissionResolver{
    @Inject Identity identity;
    @Inject IdentityManager identityManager;

    @Override
    public PermissionStatus hasPermission(Object resource, String permission) {
        if("next".equals(permission)){
            Role role = identityManager.getRole("superuser");
            Agent agent = identity.getAgent();
            if(identityManager.hasRole(agent, role)){
                return PermissionStatus.ALLOW;
            }
        }
        return PermissionStatus.DENY;
    }

    @Override
    public PermissionStatus hasPermission(Class<?> resource, Serializable identifier, String permission) {
        throw new RuntimeException(resource + ":" + identifier + ":" + permission );
    }
}