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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import my.unifi.eset.keycloak.piidataencryption.utils.LogicUtils;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.support.EntityManagers;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.jpa.JpaUserProvider;
import org.keycloak.models.jpa.entities.UserEntity;

public class EncryptedUserProvider extends JpaUserProvider {

    private static final Logger logger = Logger.getLogger(EncryptedUserProvider.class);
    private final KeycloakSession ks;

    public EncryptedUserProvider(KeycloakSession session, EntityManager em) {
        super(session, em);
        this.ks = session;
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        UserModel user;
        if (null != (user = super.getUserByUsername(realm, username))) {
            return user;
        }
        logger.debugf("getUserByUsername (using hash): " + username);
        return super.getUserByUsername(realm, LogicUtils.hash(username));
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        UserModel user;
        if (null != (user = super.getUserByEmail(realm, email))) {
            return user;
        }
        logger.debugf("getUserByEmail (using hash): " + email);
        return super.getUserByEmail(realm, LogicUtils.hash(email));
    }

    /**
     * For encrypted users, compare the email constraint with the email hash.
     * <p>
     * {@link JpaUserProvider#getUserByEmail} calls this after loading the user. For an encrypted
     * user the entity holds the decrypted email (see EntityListener) while email_constraint holds
     * its hash, so the default implementation sees them as different, sets the constraint to the
     * clear email and persists the entity: Hibernate then writes the whole row, and username,
     * email, first and last name end up in clear text in user_entity on every login by email.
     */
    @Override
    protected void ensureEmailConstraint(List<UserEntity> users, RealmModel realm) {
        UserEntity user = users.get(0);
        String email = user.getEmail();
        if (users.size() == 1 && !realm.isDuplicateEmailsAllowed() && email != null && !LogicUtils.isHash(email)
                && LogicUtils.getEncryptedUserEntity(em, user, false) != null) {
            String emailHash = LogicUtils.hash(email);
            if (!emailHash.equals(user.getEmailConstraint())) {
                // Bulk update of the single column: changing the managed entity would make
                // Hibernate flush the decrypted values of the whole row.
                em.createQuery("UPDATE UserEntity u SET u.emailConstraint = :emailConstraint WHERE u.id = :id")
                        .setParameter("emailConstraint", emailHash)
                        .setParameter("id", user.getId())
                        .executeUpdate();
            }
            return;
        }
        super.ensureEmailConstraint(users, realm);
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> attributes, Integer firstResult, Integer maxResults) {
        List<UserModel> results = super.searchForUserStream(realm, attributes, firstResult, maxResults).toList();
        if (!results.isEmpty()) {
            return results.stream();
        }
        try {
            logger.debugf("searchForUserStream (using hash): " + new ObjectMapper().writeValueAsString(attributes));
        } catch (JsonProcessingException ex) {
            logger.warnf("searchForUserStream (using hash): <unable to convert into JSON>");
        }
        List<String> encrypted = Arrays.asList(UserModel.SEARCH, "username", "email", "firstName", "lastName");
        for (Map.Entry<String, String> attribute : attributes.entrySet()) {
            if (encrypted.contains(attribute.getKey()) || LogicUtils.shouldEncryptAttribute(ks, realm.getId(), attribute.getKey())) {
                attribute.setValue(LogicUtils.hash(attribute.getValue()));
            }
        }
        return super.searchForUserStream(realm, attributes, firstResult, maxResults);
    }

    @Override
    public UserModel addUser(RealmModel realm, String id, String username, boolean addDefaultRoles, boolean addDefaultRequiredActions) {
        UserModel userModel = super.addUser(realm, id, username, addDefaultRoles, addDefaultRequiredActions);
        if (EntityManagers.isBatchMode()) {
            // Realm import (POST /admin/realms, --import-realm, kc.sh import) creates users in
            // batch mode. Since Keycloak 26.5 JpaUserProvider#addUser does not flush there and
            // batched queries run with FlushModeType.COMMIT, so the lookup below cannot see the
            // new row (NoResultException, import aborted). The import also sets email and names
            // only after addUser, so encrypting here would store an encrypted copy without them,
            // and disabling encryption later would wipe those fields. Leave batched imports to
            // the normal flow instead.
            return userModel;
        }
        LogicUtils.encryptUserEntity(ks, em, LogicUtils.getUserEntity(em, userModel.getId()));
        em.flush();
        logger.debugf("addUser (encrypted): " + username);
        return userModel;
    }

}
