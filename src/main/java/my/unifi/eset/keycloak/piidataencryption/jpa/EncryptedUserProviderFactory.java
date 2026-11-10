/*
 * Copyright (C) 2025 Muhammad Lukman Nasaruddin <lukman.nasaruddin@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at 
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 */
package my.unifi.eset.keycloak.piidataencryption.jpa;

import jakarta.persistence.EntityManager;
import my.unifi.eset.keycloak.piidataencryption.utils.LogicUtils;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.jpa.JpaUserProviderFactory;

public class EncryptedUserProviderFactory extends JpaUserProviderFactory {

    @Override
    public UserProvider create(KeycloakSession ks) {
        EntityManager em = ks.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new EncryptedUserProvider(ks, em);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        super.postInit(factory);
        // Realm import (POST /admin/realms, --import-realm, kc.sh import) creates its users in
        // batch mode, where EncryptedUserProvider#addUser cannot encrypt them, and fires no
        // USER events. RealmPostCreateEvent is published once the whole realm, users included,
        // has been imported (same transaction): encrypt the realm's users at that point.
        factory.register(event -> {
            if (event instanceof RealmModel.RealmPostCreateEvent created) {
                LogicUtils.encryptImportedUserEntities(created.getKeycloakSession(), created.getCreatedRealm());
            }
        });
    }

    @Override
    public int order() {
        return 1000;
    }

}
