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

import java.sql.PreparedStatement;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.WeakHashMap;
import java.util.regex.Pattern;
import my.unifi.eset.keycloak.piidataencryption.jpa.EncryptedUserEntity;
import my.unifi.eset.keycloak.piidataencryption.utils.EncryptionContext;
import my.unifi.eset.keycloak.piidataencryption.utils.EncryptionUtils;
import my.unifi.eset.keycloak.piidataencryption.utils.LogicUtils;
import org.hibernate.engine.spi.SharedSessionContractImplementor;
import org.hibernate.event.spi.PostInsertEvent;
import org.hibernate.event.spi.PostInsertEventListener;
import org.hibernate.event.spi.PostUpdateEvent;
import org.hibernate.event.spi.PostUpdateEventListener;
import org.hibernate.event.spi.PreInsertEvent;
import org.hibernate.event.spi.PreInsertEventListener;
import org.hibernate.event.spi.PreUpdateEvent;
import org.hibernate.event.spi.PreUpdateEventListener;
import org.hibernate.persister.entity.EntityPersister;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;

/**
 * Encrypts USER_ENTITY on write, whatever Keycloak code path changed the user.
 * <p>
 * The managed UserEntity always holds clear values (EntityListener decrypts them on load).
 * Before Hibernate writes the row, the PII slots of the statement's state array are replaced
 * with their hashes, so clear values never reach the database (not even transiently, as
 * happened when the row was written in clear and re-hashed afterwards). The pre-event records
 * exactly which slots it replaced; the post-event puts those clear values back into the same
 * array, which Hibernate keeps as the entity's loaded state (so the entity is not seen as
 * dirty again), and upserts the matching columns of USER_ENTITY_ENCRYPTED with plain JDBC on
 * the same connection and transaction.
 * <p>
 * Relies on Hibernate passing the same state array to the pre-event, the SQL statement, the
 * loaded state and the post-event (verified on Hibernate ORM 7.4.9, Keycloak 26.8.2); the e2e
 * tests check that no clear PII is ever bound to a USER_ENTITY write.
 */
public class EncryptOnWriteListener implements PreInsertEventListener, PreUpdateEventListener,
        PostInsertEventListener, PostUpdateEventListener {

    private static final Pattern UUID = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final String[] CIPHER_COLUMNS = {"USERNAME", "EMAIL", "FIRST_NAME", "LAST_NAME"};

    /**
     * Clear values of the slots hashed by the pre-event, keyed by the state array (arrays
     * compare by identity; weak keys so an aborted flush leaves nothing behind).
     */
    private final Map<Object[], Map<Integer, String>> hashedSlots = Collections.synchronizedMap(new WeakHashMap<>());

    /** Property indices of UserEntity, resolved once from the persister. */
    private volatile Indices indices;
    private volatile String encryptedTable;

    private static final class Indices {

        final int username, email, emailConstraint, firstName, lastName, realmId, serviceAccount;
        final int[] pii;

        Indices(String[] names) {
            username = find(names, "username");
            email = find(names, "email");
            emailConstraint = find(names, "emailConstraint");
            firstName = find(names, "firstName");
            lastName = find(names, "lastName");
            realmId = find(names, "realmId");
            serviceAccount = find(names, "serviceAccountClientLink");
            pii = new int[]{username, email, firstName, lastName}; // same order as CIPHER_COLUMNS
        }

        private static int find(String[] names, String name) {
            for (int i = 0; i < names.length; i++) {
                if (names[i].equals(name)) {
                    return i;
                }
            }
            throw new IllegalStateException("UserEntity has no property '" + name
                    + "': this Keycloak version is not supported by the PII encryption provider");
        }
    }

    private Indices indices(EntityPersister persister) {
        Indices i = indices;
        if (i == null) {
            i = new Indices(persister.getPropertyNames());
            indices = i;
        }
        return i;
    }

    private String encryptedTable(SharedSessionContractImplementor session) {
        String t = encryptedTable;
        if (t == null) {
            t = session.getFactory().getMappingMetamodel().getEntityDescriptor(EncryptedUserEntity.class)
                    .getIdentifierTableDetails().getTableName();
            encryptedTable = t;
        }
        return t;
    }

    @Override
    public boolean onPreInsert(PreInsertEvent event) {
        if (event.getEntity() instanceof UserEntity user) {
            hashState(event.getSession(), event.getPersister(), user, event.getState(), null);
        }
        return false;
    }

    @Override
    public boolean onPreUpdate(PreUpdateEvent event) {
        if (event.getEntity() instanceof UserEntity user) {
            hashState(event.getSession(), event.getPersister(), user, event.getState(), event.getOldState());
        }
        return false;
    }

    @Override
    public void onPostInsert(PostInsertEvent event) {
        if (event.getEntity() instanceof UserEntity user) {
            afterWrite(event.getSession(), event.getPersister(), user, event.getState(), null);
        }
    }

    @Override
    public void onPostUpdate(PostUpdateEvent event) {
        if (event.getEntity() instanceof UserEntity user) {
            afterWrite(event.getSession(), event.getPersister(), user, event.getState(), event.getOldState());
        }
    }

    @Override
    public boolean requiresPostCommitHandling(EntityPersister persister) {
        return false;
    }

    /**
     * @param oldState null for an INSERT
     */
    private void hashState(SharedSessionContractImplementor session, EntityPersister persister, UserEntity user,
            Object[] state, Object[] oldState) {
        Indices ix = indices(persister);
        // Service accounts are never encrypted (the link may be set after the insert snapshot).
        if (state[ix.serviceAccount] != null || user.getServiceAccountClientLink() != null) {
            return;
        }
        if (!EncryptionContext.shouldEncryptUser(session, user.getId(), (String) state[ix.realmId])) {
            return;
        }
        boolean undecryptable = EncryptionContext.isUndecryptableUser(user.getId());
        Map<Integer, String> clear = new LinkedHashMap<>();
        for (int i : ix.pii) {
            String value = (String) state[i];
            if (value == null) {
                continue;
            }
            if (oldState != null && keepsStoredHash(undecryptable, value, oldState[i])) {
                continue; // a hash loaded from the DB that could not be decrypted: leave it as is
            }
            clear.put(i, value);
            state[i] = LogicUtils.hash(value);
        }
        String constraint = (String) state[ix.emailConstraint];
        if (constraint != null) {
            String clearEmail = clear.get(ix.email);
            if (clearEmail != null && constraint.equalsIgnoreCase(clearEmail)) {
                clear.put(ix.emailConstraint, constraint); // duplicate emails not allowed
                state[ix.emailConstraint] = state[ix.email];
            } else if (!LogicUtils.isHash(constraint) && !UUID.matcher(constraint).matches()) {
                clear.put(ix.emailConstraint, constraint); // never store a clear value
                state[ix.emailConstraint] = LogicUtils.hash(constraint);
            }
            // a hash, or a random id (duplicate emails allowed / no email), is left untouched
        }
        if (!clear.isEmpty()) {
            hashedSlots.put(state, clear);
        }
    }

    private static boolean keepsStoredHash(boolean undecryptable, String value, Object oldValue) {
        // Without a request context undecryptable users are unknown: fall back to "unchanged and
        // looks like a hash", which can only miss users whose clear value is 40 hex characters.
        boolean unchanged = Objects.equals(value, oldValue);
        return unchanged && LogicUtils.isHash(value)
                && (undecryptable || EncryptionContext.current() == null);
    }

    /**
     * @param oldState null for an INSERT
     */
    private void afterWrite(SharedSessionContractImplementor session, EntityPersister persister, UserEntity user,
            Object[] state, Object[] oldState) {
        Indices ix = indices(persister);
        Map<Integer, String> clear = hashedSlots.remove(state);
        if (clear == null) {
            if (oldState != null && oldState[ix.serviceAccount] == null && state[ix.serviceAccount] != null) {
                deleteEncryptedRow(session, user.getId()); // became a service account after addUser
            }
            return;
        }
        for (Map.Entry<Integer, String> slot : clear.entrySet()) {
            state[slot.getKey()] = slot.getValue(); // the array is the entity's loaded state: clear again
        }
        boolean knownEncrypted = EncryptionContext.isEncryptedUser(user.getId());
        Map<String, String> columns = new LinkedHashMap<>(); // columns to update
        Map<String, String> known = new LinkedHashMap<>();   // every column whose clear value is known
        for (int c = 0; c < ix.pii.length; c++) {
            int i = ix.pii[c];
            String value = (String) state[i];
            boolean changed = oldState == null || !Objects.equals(oldState[i], value);
            if (clear.containsKey(i)) {
                String cipher = encrypt(value);
                known.put(CIPHER_COLUMNS[c], cipher);
                if (changed || !knownEncrypted) {
                    columns.put(CIPHER_COLUMNS[c], cipher);
                }
            } else if (value == null && changed) {
                columns.put(CIPHER_COLUMNS[c], null); // value removed: drop its ciphertext too
            }
        }
        if (!columns.isEmpty()) {
            upsertEncryptedRow(session, user.getId(), columns, known);
        }
        EncryptionContext.markEncryptedUser(user.getId());
    }

    /**
     * Updates the given columns of the user's encrypted row; if there is no row yet, inserts one
     * with every known column (a stored hash that could not be decrypted stays without one).
     */
    private void upsertEncryptedRow(SharedSessionContractImplementor session, String userId, Map<String, String> columns,
            Map<String, String> known) {
        String table = encryptedTable(session);
        // The user row must be executed first: USER_ENTITY_ENCRYPTED.USER_ID references it.
        session.getJdbcCoordinator().executeBatch();
        session.doWork(conn -> {
            StringBuilder set = new StringBuilder();
            for (String col : columns.keySet()) {
                set.append(set.length() == 0 ? "" : ", ").append(col).append(" = ?");
            }
            int updated;
            try (PreparedStatement ps = conn.prepareStatement("UPDATE " + table + " SET " + set + " WHERE USER_ID = ?")) {
                int p = 1;
                for (String value : columns.values()) {
                    ps.setString(p++, value);
                }
                ps.setString(p, userId);
                updated = ps.executeUpdate();
            }
            if (updated == 0) {
                try (PreparedStatement ps = conn.prepareStatement("INSERT INTO " + table
                        + " (ID, USER_ID, USERNAME, EMAIL, FIRST_NAME, LAST_NAME) VALUES (?, ?, ?, ?, ?, ?)")) {
                    ps.setString(1, KeycloakModelUtils.generateId());
                    ps.setString(2, userId);
                    for (int c = 0; c < CIPHER_COLUMNS.length; c++) {
                        ps.setString(c + 3, known.get(CIPHER_COLUMNS[c]));
                    }
                    ps.executeUpdate();
                }
            }
        });
    }

    private void deleteEncryptedRow(SharedSessionContractImplementor session, String userId) {
        String table = encryptedTable(session);
        session.getJdbcCoordinator().executeBatch();
        session.doWork(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("DELETE FROM " + table + " WHERE USER_ID = ?")) {
                ps.setString(1, userId);
                ps.executeUpdate();
            }
        });
    }

    /** Encrypts or fails: a clear value must never be stored as "ciphertext". */
    private static String encrypt(String value) {
        if (value == null) {
            return null;
        }
        String cipher = EncryptionUtils.encryptValue(value);
        if (!EncryptionUtils.isEncryptedValue(cipher)) {
            throw new IllegalStateException("PII encryption failed: check KC_PII_ENCKEY");
        }
        return cipher;
    }
}
