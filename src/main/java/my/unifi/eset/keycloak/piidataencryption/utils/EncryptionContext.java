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
package my.unifi.eset.keycloak.piidataencryption.utils;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.hibernate.engine.spi.SharedSessionContractImplementor;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.jpa.entities.RealmAttributeEntity;
import org.keycloak.utils.KeycloakSessionUtil;

/**
 * Per-request encryption state shared by the Hibernate listeners, which cannot call the Keycloak
 * model while Hibernate is loading or flushing.
 * <p>
 * Kept as an attribute of the KeycloakSession bound to the thread, so nested EntityManagers of
 * the same request share it. Without a bound KeycloakSession every decision falls back to the
 * database (realm attribute), which is always correct, only slower.
 */
public final class EncryptionContext {

    private static final String ATTRIBUTE = EncryptionContext.class.getName();

    /** Realm flag set in this request by LogicUtils.setUserEncryptionEnabled: beats everything. */
    private final Map<String, Boolean> overrides = new HashMap<>();
    /** Realm flag as read from the database, once per realm per request. */
    private final Map<String, Boolean> realmFlags = new HashMap<>();
    /** Users loaded decrypted or written encrypted in this request. */
    private final Set<String> encryptedUsers = new HashSet<>();
    /** Users whose stored hashes could not be decrypted on load (they stay hashes). */
    private final Set<String> undecryptableUsers = new HashSet<>();

    private static volatile String realmAttributeTable;

    private EncryptionContext() {
    }

    /**
     * The context of the KeycloakSession bound to the current thread, or null if there is none.
     */
    public static EncryptionContext current() {
        KeycloakSession ks = KeycloakSessionUtil.getKeycloakSession();
        if (ks == null) {
            return null;
        }
        EncryptionContext ctx = ks.getAttribute(ATTRIBUTE, EncryptionContext.class);
        if (ctx == null) {
            ctx = new EncryptionContext();
            ks.setAttribute(ATTRIBUTE, ctx);
        }
        return ctx;
    }

    public static void setOverride(String realmId, boolean enabled) {
        EncryptionContext ctx = current();
        if (ctx != null) {
            ctx.overrides.put(realmId, enabled);
            ctx.realmFlags.remove(realmId);
        }
    }

    public static void markEncryptedUser(String userId) {
        EncryptionContext ctx = current();
        if (ctx != null) {
            ctx.encryptedUsers.add(userId);
        }
    }

    public static boolean isEncryptedUser(String userId) {
        EncryptionContext ctx = current();
        return ctx != null && ctx.encryptedUsers.contains(userId);
    }

    /**
     * A user whose stored hashes could not all be decrypted. Not marked as encrypted: it has no
     * (complete) ciphertext, so the realm flag decides and every hashed column gets written.
     */
    public static void markUndecryptableUser(String userId) {
        EncryptionContext ctx = current();
        if (ctx != null) {
            ctx.undecryptableUsers.add(userId);
        }
    }

    /** Realm flag (request override, else the database). Safe while Hibernate is loading. */
    public static boolean isRealmEncrypted(SharedSessionContractImplementor session, String realmId) {
        EncryptionContext ctx = current();
        if (ctx != null) {
            Boolean override = ctx.overrides.get(realmId);
            if (override != null) {
                return override;
            }
            return ctx.realmFlags.computeIfAbsent(realmId, id -> queryRealmFlag(session, id));
        }
        return queryRealmFlag(session, realmId);
    }

    public static boolean isUndecryptableUser(String userId) {
        EncryptionContext ctx = current();
        return ctx != null && ctx.undecryptableUsers.contains(userId);
    }

    /**
     * Whether a write of this user must store hashes. Safe to call inside a Hibernate flush: it
     * only uses this context and plain JDBC on the flushing session's own connection.
     */
    public static boolean shouldEncryptUser(SharedSessionContractImplementor session, String userId, String realmId) {
        EncryptionContext ctx = current();
        if (ctx != null) {
            Boolean override = ctx.overrides.get(realmId);
            if (override != null) {
                return override;
            }
            if (ctx.encryptedUsers.contains(userId)) {
                return true;
            }
            return ctx.realmFlags.computeIfAbsent(realmId, id -> readRealmFlag(session, id));
        }
        return readRealmFlag(session, realmId);
    }

    private static boolean readRealmFlag(SharedSessionContractImplementor session, String realmId) {
        // Statements of the current flush (e.g. the realm attribute of a realm being imported)
        // must be executed before they can be read back.
        session.getJdbcCoordinator().executeBatch();
        return queryRealmFlag(session, realmId);
    }

    private static boolean queryRealmFlag(SharedSessionContractImplementor session, String realmId) {
        String table = realmAttributeTable;
        if (table == null) {
            // resolved from the mapping, so a custom DB schema (KC_DB_SCHEMA) is honoured
            table = session.getFactory().getMappingMetamodel().getEntityDescriptor(RealmAttributeEntity.class)
                    .getIdentifierTableDetails().getTableName();
            realmAttributeTable = table;
        }
        String sql = "SELECT VALUE FROM " + table + " WHERE REALM_ID = ? AND NAME = 'users.encrypt'";
        return session.doReturningWork(conn -> {
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, realmId);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() && Boolean.parseBoolean(rs.getString(1));
                }
            }
        });
    }
}
