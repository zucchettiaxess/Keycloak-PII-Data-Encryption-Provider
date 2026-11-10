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

package my.unifi.eset.keycloak.piidataencryption.listeners;

import my.unifi.eset.keycloak.piidataencryption.utils.LogicUtils;
import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;

/**
 * Registers event listener pii-data-encryption to be in the event listeners 
 * drop-down in the realm settings
 * 
 * @author MLukman (https://github.com/MLukman)
 */
public class EventListenerFactory implements EventListenerProviderFactory {

    public static final String ID = "pii-data-encryption";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public void close() {
    }

    @Override
    public EventListenerProvider create(KeycloakSession ks) {
        return new EventListener(ks);
    }

    @Override
    public void init(Config.Scope scope) {
    }

    @Override
    public void postInit(KeycloakSessionFactory ksf) {
        // Realm import (POST /admin/realms, --import-realm, kc.sh import) creates its users in
        // batch mode, where EncryptedUserProvider#addUser cannot encrypt them, and fires no
        // USER events. RealmPostCreateEvent is published once the whole realm, users included,
        // has been imported (same transaction): encrypt the realm's users at that point.
        // Registered here because this factory exists once, while the user provider factory is
        // loaded twice (ids "jpa" and "jpa-encrypted").
        ksf.register(event -> {
            if (event instanceof RealmModel.RealmPostCreateEvent created) {
                LogicUtils.encryptImportedUserEntities(created.getKeycloakSession(), created.getCreatedRealm());
            }
        });
    }

}
