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

import my.unifi.eset.keycloak.piidataencryption.utils.EncryptionContext;
import my.unifi.eset.keycloak.piidataencryption.utils.EncryptionUtils;
import my.unifi.eset.keycloak.piidataencryption.utils.LogicUtils;
import jakarta.persistence.EntityManager;
import java.util.HashMap;
import java.util.Map;
import my.unifi.eset.keycloak.piidataencryption.jpa.EncryptedUserAttributeEntity;
import my.unifi.eset.keycloak.piidataencryption.jpa.EncryptedUserEntity;
import my.unifi.eset.keycloak.piidataencryption.utils.DecryptionFailureException;
import org.hibernate.boot.Metadata;
import org.hibernate.boot.spi.BootstrapContext;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.event.service.spi.EventListenerRegistry;
import org.hibernate.event.spi.EventType;
import org.hibernate.event.spi.PreLoadEvent;
import org.hibernate.event.spi.PreLoadEventListener;
import org.hibernate.integrator.spi.Integrator;
import org.hibernate.service.spi.SessionFactoryServiceRegistry;
import org.jboss.logging.Logger;
import org.keycloak.models.jpa.entities.UserAttributeEntity;
import org.keycloak.models.jpa.entities.UserEntity;

/**
 * Listens to PreLoad entity event to perform decryption of UserEntity &
 * UserAttributeEntity
 *
 * @author MLukman (https://github.com/MLukman)
 */
public class EntityListener implements Integrator, PreLoadEventListener {

    static final Logger logger = Logger.getLogger(EntityListener.class);

    @Override
    public void integrate(Metadata metadata, BootstrapContext bootstrapContext, SessionFactoryImplementor sessionFactory) {
        EventListenerRegistry eventListenerRegistry = sessionFactory.getServiceRegistry().getService(EventListenerRegistry.class);
        eventListenerRegistry.appendListeners(EventType.PRE_LOAD, this);
        EncryptOnWriteListener encryptOnWrite = new EncryptOnWriteListener();
        eventListenerRegistry.appendListeners(EventType.PRE_INSERT, encryptOnWrite);
        eventListenerRegistry.appendListeners(EventType.PRE_UPDATE, encryptOnWrite);
        eventListenerRegistry.appendListeners(EventType.POST_INSERT, encryptOnWrite);
        eventListenerRegistry.appendListeners(EventType.POST_UPDATE, encryptOnWrite);
    }

    @Override
    public void disintegrate(SessionFactoryImplementor sfi, SessionFactoryServiceRegistry sfsr) {
    }

    @Override
    public void onPreLoad(PreLoadEvent ple) {
        try {
            if (ple.getEntity() instanceof UserEntity ue) {
                handlePreLoadEventUserEntity(ple, ue);
            }
            if (ple.getEntity() instanceof UserAttributeEntity uae) {
                handlePreLoadEventUserAttributeEntity(ple, uae);
            }
        } catch (DecryptionFailureException ex) {
            ex.outputToLog(logger);
        }
    }

    protected void handlePreLoadEventUserEntity(PreLoadEvent ple, UserEntity ue) {
        EntityManager em = ple.getSession().getSessionFactory().createEntityManager();
        EncryptedUserEntity eue = LogicUtils.getEncryptedUserEntity(em, ue, false);
        Object[] states = ple.getState();
        Map<String, Integer> cols = collectColumnIndices(ple.getPersister().getEntityMetamodel().getPropertyNames());
        String realmId = (String) states[cols.get("realmId")];
        String[] names = {"username", "email", "firstName", "lastName"};
        String[] ciphers = eue == null ? new String[4]
                : new String[]{eue.getUsername(), eue.getEmail(), eue.getFirstName(), eue.getLastName()};
        boolean anyHash = false;
        boolean allDecrypted = true;
        boolean allHashes = true;
        // Each column is decrypted on its own, and only when its ciphertext matches the stored
        // hash: a partial or stale encrypted row can never replace a value with a wrong one.
        for (int c = 0; c < names.length; c++) {
            int i = cols.get(names[c]);
            if (!(states[i] instanceof String stored)) {
                continue;
            }
            if (!LogicUtils.isHash(stored)) {
                allHashes = false;
                continue;
            }
            anyHash = true;
            if (ciphers[c] != null && validateHashValueVsEncryptedValue(stored, ciphers[c])) {
                states[i] = EncryptionUtils.decryptValue(ciphers[c]);
            } else {
                allDecrypted = false;
            }
        }
        if (!anyHash) {
            return; // stored in clear (encryption off for this user)
        }
        if (allDecrypted) {
            logger.debugf("Event: USER_DECRYPTION, Realm: %s, User: %s", realmId, ue.getId());
            // Any later write of this user in the request must store hashes again.
            EncryptionContext.markEncryptedUser(ue.getId());
            return;
        }
        // Some hashes could not be decrypted. Without an encrypted row, a clear value that merely
        // looks like a hash (e.g. a 40-hex username) must not be taken for one: require every
        // value to be a hash and the realm to have encryption on.
        if (eue != null || (allHashes && EncryptionContext.isRealmEncrypted(ple.getSession(), realmId))) {
            // Those columns stay hashes: writes keep them as they are (EncryptOnWriteListener).
            EncryptionContext.markUndecryptableUser(ue.getId());
            new DecryptionFailureException(realmId, ue.getId()).outputToLog(logger);
        }
    }

    protected void handlePreLoadEventUserAttributeEntity(PreLoadEvent ple, UserAttributeEntity uae) {
        EntityManager em = ple.getSession().getSessionFactory().createEntityManager();
        Map<String, Integer> cols = collectColumnIndices(ple.getPersister().getEntityMetamodel().getPropertyNames());
        Object[] states = ple.getState();
        String valueColumn;
        if (states[cols.get("value")] != null) {
            valueColumn = "value";
        } else if (states[cols.get("longValue")] != null) {
            valueColumn = "longValue";
        } else {
            return; // null value = do nothing
        }
        UserEntity user = (UserEntity) states[cols.get("user")];
        EncryptedUserAttributeEntity euae = LogicUtils.getEncryptedUserAttributeEntity(em, user, String.valueOf(states[cols.get("name")]), false);
        if (euae != null) {
            // if record exist, decrypt it and set as value column
            if (validateHashValueVsEncryptedValue((String) states[cols.get(valueColumn)], euae.getValue())) {
                logger.debugf("Event: USER_ATTRIBUTE_DECRYPTION, Realm: %s, User: %s, Attribute: %s", user.getRealmId(), user.getId(), states[cols.get("name")]);
                states[cols.get(valueColumn)] = EncryptionUtils.decryptValue(euae.getValue());
            } else {
                throw new DecryptionFailureException(user.getRealmId(), user.getId(), (String) states[cols.get("name")]);
            }
        } else if (EncryptionUtils.isEncryptedValue(String.valueOf(states[cols.get("value")]))) {
            // if the value column is encrypted value (backward compatibility with version 1.x)
            states[cols.get("value")] = EncryptionUtils.decryptValue(String.valueOf(states[cols.get("value")]));
        }
    }

    protected static Map<String, Integer> collectColumnIndices(String[] columnNames) {
        Map<String, Integer> cols = new HashMap<>();
        for (int i = 0; i < columnNames.length; i++) {
            cols.put(columnNames[i], i);
        }
        return cols;
    }

    /**
     * Validate if the passed hash value matches with the pass encrypted value
     *
     * @param hash The hash value String
     * @param encryptedValue The encrypted value String
     * @return True if matches, false otherwise
     */
    public static boolean validateHashValueVsEncryptedValue(String hash, String encryptedValue) {
        return hash.equalsIgnoreCase(LogicUtils.hash(EncryptionUtils.decryptValue(encryptedValue)));
    }

}
