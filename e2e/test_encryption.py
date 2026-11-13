"""End-to-end tests: PII must never be stored in clear text in USER_ENTITY.

Run with ./run.sh (builds nothing: expects ../target/keycloak-pii-data-encryption.jar).
Every test uses its own realm, so tests are independent and can run in any order.
"""
import time
import unittest

import kc

PASSWORD = "Pw-123456"
SMTP = {"host": "mailpit", "port": "1025", "from": "noreply@example.com"}


def setUpModule():
    kc.wait_for_keycloak()
    kc.wait_for_ldap()


class EncryptionTestCase(unittest.TestCase):
    admin = kc.Admin()

    def assertEncrypted(self, user_id, clear=None, random_constraint=False):
        """USER_ENTITY holds only hashes, and a complete encrypted copy exists.

        clear: optional dict of expected clear values (username/email/first_name/last_name).
        random_constraint: email_constraint is Keycloak's random id (duplicate emails allowed,
        or no email) instead of the email hash.
        """
        row = kc.user_row(user_id)
        self.assertIsNotNone(row, "user %s not found" % user_id)
        for col in ("username", "email", "first_name", "last_name"):
            if row[col] is not None:
                self.assertTrue(kc.is_hash(row[col]),
                                "%s stored in clear text: %r (row %s)" % (col, row[col], row))
        if random_constraint:
            # NULL when there is no email and the user was encrypted by the enable sweep
            # (LogicUtils.encryptUserEntity writes hash(null)); PostgreSQL allows several NULLs
            if not (row["email"] is None and row["email_constraint"] is None):
                self.assertRegex(row["email_constraint"] or "", kc.UUID_RE, "email_constraint is not a random id")
        else:
            self.assertEqual(row["email_constraint"], row["email"], "email_constraint is not the email hash")
        for col, value in (clear or {}).items():
            self.assertEqual(row[col], kc.sha1(value), "%s is not the hash of %r" % (col, value))
        enc = kc.sql("select count(*) from user_entity_encrypted where user_id = '%s' "
                     "and username is not null" % user_id)
        self.assertEqual(enc[0][0], "1", "no single complete encrypted row for user %s" % user_id)

    def assertNoClearWrites(self, *values, since=0):
        """No INSERT/UPDATE on user_entity ever bound these clear values (WAL proxy)."""
        hits = kc.clear_writes(values, since)
        self.assertEqual(hits, [], "clear PII written to user_entity:\n" + "\n".join(hits[:5]))

    def assertNoClearPii(self, username, *extra, since=0):
        """No write bound the user's username, email or default names (plus extra values)."""
        self.assertNoClearWrites(username, username + "@example.com", kc.first_name(username),
                                 kc.last_name(username), *extra, since=since)

    def admin_view(self, realm, user_id):
        return self.admin.get("/%s/users/%s" % (realm, user_id))


class Regressions(EncryptionTestCase):
    """Paths already fixed or never broken: must stay green."""

    def test_admin_api_create_update_reset_password(self):
        r = self.admin.create_realm("reg-admin")
        plain = self.admin.create_user(r, "plain.user", password=PASSWORD)
        inline = self.admin.create_user(r, "inline.user", password=PASSWORD, inline_password=True)
        self.assertEncrypted(plain, {"username": "plain.user", "email": "plain.user@example.com"})
        self.assertEncrypted(inline, {"username": "inline.user"})
        self.admin.call("PUT", "/%s/users/%s" % (r, plain),
                        {"firstName": "AdminChanged", "lastName": "Last", "email": "plain.new@example.com"})
        self.admin.call("PUT", "/%s/users/%s" % (r, plain), {"enabled": False})
        self.assertEncrypted(plain, {"email": "plain.new@example.com", "first_name": "AdminChanged"})
        self.assertEqual(self.admin_view(r, plain)["email"], "plain.new@example.com")
        self.assertNoClearPii("plain.user", "plain.new@example.com", "AdminChanged")
        self.assertNoClearPii("inline.user")

    def test_login_with_username_and_email(self):
        r = self.admin.create_realm("reg-login", loginWithEmailAllowed=True)
        uid = self.admin.create_user(r, "luigi.verdi", password=PASSWORD)
        kc.password_grant(r, "luigi.verdi", PASSWORD)
        kc.password_grant(r, "luigi.verdi@example.com", PASSWORD)
        kc.password_grant(r, "Luigi.Verdi@Example.COM", PASSWORD)
        self.assertEncrypted(uid, {"username": "luigi.verdi", "email": "luigi.verdi@example.com"})
        self.assertNoClearPii("luigi.verdi")

    def test_realm_import_then_disable_encryption(self):
        users = [{"username": "imp.%d" % i, "email": "imp.%d@example.com" % i, "firstName": "Imp",
                  "lastName": "User%d" % i, "enabled": True} for i in range(3)]
        self.admin.call("POST", "", {"realm": "reg-import", "enabled": True,
                                     "attributes": {"users.encrypt": "true"},
                                     "eventsListeners": ["jboss-logging", "pii-data-encryption"],
                                     "users": users})
        ids = [self.admin.user_id("reg-import", u["username"]) for u in users]
        for uid, u in zip(ids, users):
            self.assertEncrypted(uid, {"username": u["username"], "email": u["email"]})
        self.assertNoClearWrites(*[u["email"] for u in users])
        self.admin.set_encryption("reg-import", False)
        for uid, u in zip(ids, users):
            row = kc.user_row(uid)
            self.assertEqual((row["username"], row["email"], row["email_constraint"], row["first_name"],
                              row["last_name"]),
                             (u["username"], u["email"], u["email"], u["firstName"], u["lastName"]),
                             "value lost on decryption")
            self.assertEqual(kc.sql("select count(*) from user_entity_encrypted where user_id = '%s'" % uid),
                             [["0"]], "encrypted row left after disabling")
        # a write after disabling stays clear, and re-enabling encrypts again
        self.admin.call("PUT", "/reg-import/users/%s" % ids[0],
                        {"firstName": "Imp", "lastName": "AfterDisable", "email": users[0]["email"]})
        self.assertEqual(kc.user_row(ids[0])["last_name"], "AfterDisable")
        self.admin.set_encryption("reg-import", True)
        for uid, u in zip(ids, users):
            self.assertEncrypted(uid, {"username": u["username"], "email": u["email"]})

    def test_partial_import_skip_and_overwrite(self):
        r = self.admin.create_realm("reg-partial")
        self.admin.call("POST", "/%s/partialImport" % r, {"ifResourceExists": "SKIP", "users": [
            {"username": "part.user", "email": "part.user@example.com", "firstName": "Part",
             "lastName": "User", "enabled": True}]})
        uid = self.admin.user_id(r, "part.user")
        self.assertEncrypted(uid, {"email": "part.user@example.com"})
        self.admin.call("POST", "/%s/partialImport" % r, {"ifResourceExists": "OVERWRITE", "users": [
            {"username": "part.user", "email": "part.new@example.com", "firstName": "Part",
             "lastName": "New", "enabled": True}]})
        uid = self.admin.user_id(r, "part.user")
        self.assertEncrypted(uid, {"email": "part.new@example.com", "last_name": "New"})
        self.assertNoClearWrites("part.user", "part.new@example.com")

    def test_import_multivalued_encrypted_attribute(self):
        self.admin.call("POST", "", {"realm": "reg-multi", "enabled": True,
                                     "attributes": {"users.encrypt": "true"},
                                     "eventsListeners": ["jboss-logging", "pii-data-encryption"],
                                     "users": [{"username": "multi.user", "email": "multi.user@example.com",
                                                "firstName": "Multi", "lastName": "User", "enabled": True,
                                                "attributes": {"pii-phone": ["111", "222"]}}]})
        uid = self.admin.user_id("reg-multi", "multi.user")
        self.assertEncrypted(uid)
        rows = kc.sql("select count(*) from user_attribute_encrypted where user_id = '%s' "
                      "and name = 'pii-phone'" % uid)
        self.assertEqual(rows[0][0], "1", "duplicate encrypted rows for a multi-valued attribute")
        self.admin_view("reg-multi", uid)  # must not fail (NonUniqueResultException before)
        self.assertNoClearWrites("multi.user")

    def test_pii_attribute_via_admin_api(self):
        r = self.admin.create_realm("reg-attr")
        # Keycloak drops attributes that the user profile does not declare (unmanaged attributes)
        profile = self.admin.get("/%s/users/profile" % r)
        profile["attributes"].append({"name": "pii-phone", "displayName": "Phone",
                                      "permissions": {"view": ["admin"], "edit": ["admin"]}})
        self.admin.call("PUT", "/%s/users/profile" % r, profile)
        uid = self.admin.create_user(r, "attr.user", attributes={"pii-phone": ["+39123456"]})
        self.admin.call("PUT", "/%s/users/%s" % (r, uid), {
            "firstName": kc.first_name("attr.user"), "lastName": kc.last_name("attr.user"),
            "email": "attr.user@example.com", "attributes": {"pii-phone": ["+39654321"]}})
        self.assertEncrypted(uid, {"username": "attr.user"})
        stored = kc.sql("select value from user_attribute where user_id = '%s' and name = 'pii-phone'" % uid)
        self.assertEqual(stored, [[kc.sha1("+39654321")]], "PII attribute not stored as a hash")
        self.assertEqual(kc.sql("select count(*) from user_attribute_encrypted where user_id = '%s' "
                                "and name = 'pii-phone'" % uid), [["1"]])
        self.assertEqual(self.admin_view(r, uid)["attributes"]["pii-phone"], ["+39654321"])

    def test_ldap_full_sync_import(self):
        r = self.admin.create_realm("reg-ldap")
        uid = LdapHelper.import_anna(self, r)
        self.assertEncrypted(uid, {"username": "anna.bianchi"})
        self.assertNoClearWrites("anna.bianchi@example.com")


class LdapHelper:
    @staticmethod
    def component(test, realm):
        realm_id = test.admin.get("/" + realm)["id"]
        test.admin.call("POST", "/%s/components" % realm, {
            "name": "ldap", "providerId": "ldap", "providerType": "org.keycloak.storage.UserStorageProvider",
            "parentId": realm_id, "config": {
                "enabled": ["true"], "vendor": ["other"], "connectionUrl": ["ldap://ldap:1389"],
                "bindDn": ["cn=admin,dc=example,dc=org"], "bindCredential": ["admin"],
                "usersDn": ["ou=users,dc=example,dc=org"], "usernameLDAPAttribute": ["uid"],
                "rdnLDAPAttribute": ["cn"], "uuidLDAPAttribute": ["entryUUID"],
                "userObjectClasses": ["inetOrgPerson"], "editMode": ["READ_ONLY"],
                "importEnabled": ["true"], "searchScope": ["1"], "authType": ["simple"],
                "pagination": ["false"]}})
        comps = test.admin.get("/%s/components?type=org.keycloak.storage.UserStorageProvider" % realm)
        return comps[0]["id"]

    @staticmethod
    def set_ldap_names(mail, sn):
        kc.ldap_modify("dn: cn=anna.bianchi,ou=users,dc=example,dc=org\nchangetype: modify\n"
                       "replace: mail\nmail: %s\n-\nreplace: sn\nsn: %s\n" % (mail, sn))

    @staticmethod
    def import_anna(test, realm):
        LdapHelper.set_ldap_names("anna.bianchi@example.com", "Bianchi")
        comp = LdapHelper.component(test, realm)
        test.admin.call("POST", "/%s/user-storage/%s/sync?action=triggerFullSync" % (realm, comp))
        test.ldap_component = comp
        return test.admin.user_id(realm, "anna.bianchi")


class KnownLeaks(EncryptionTestCase):
    """Paths that write the user in clear text with upstream v2.7 (fix 5: encrypt on write)."""

    def test_admin_logout(self):
        r = self.admin.create_realm("leak-logout")
        uid = self.admin.create_user(r, "logout.user")
        self.admin.call("POST", "/%s/users/%s/logout" % (r, uid))
        self.assertEncrypted(uid, {"username": "logout.user"})
        self.assertNoClearPii("logout.user")

    def test_verify_email_link(self):
        r = self.admin.create_realm("leak-verify", smtpServer=SMTP)
        uid = self.admin.create_user(r, "verify.user")
        self.admin.call("PUT", "/%s/users/%s/send-verify-email" % (r, uid))
        link = next(l for l in kc.mail_links_to("verify.user@example.com") if "action-token" in l)
        b = kc.Browser().get(link)
        for _ in range(3):  # follow "click here to proceed" confirmation pages, if any
            if kc.user_row(uid)["email_verified"] == "t":
                break
            nxt = [l for l in b.links() if "login-actions" in l]
            if not nxt:
                break
            b.get(nxt[0])
        self.assertEqual(kc.user_row(uid)["email_verified"], "t", "email not verified:\n" + b.page[:800])
        self.assertEncrypted(uid, {"username": "verify.user", "email": "verify.user@example.com"})
        self.assertNoClearPii("verify.user")

    def test_update_email_required_action(self):
        r = self.admin.create_realm("leak-update-email")
        action = self.admin.get("/%s/authentication/required-actions/UPDATE_EMAIL" % r)
        action["enabled"] = True  # registered but disabled by default in new realms
        self.admin.call("PUT", "/%s/authentication/required-actions/UPDATE_EMAIL" % r, action)
        uid = self.admin.create_user(r, "upd.user", password=PASSWORD, requiredActions=["UPDATE_EMAIL"])
        b = kc.Browser().start_login(r)
        b.submit({"username": "upd.user", "password": PASSWORD})
        if not b.arrived:
            b.submit({"email": "upd.new@example.com"})
        self.assertIsNotNone(b.arrived, "login did not complete:\n" + b.page[:800])
        self.assertEqual(self.admin_view(r, uid)["email"], "upd.new@example.com")
        self.assertEncrypted(uid, {"username": "upd.user", "email": "upd.new@example.com"})
        self.assertNoClearPii("upd.user", "upd.new@example.com")

    def test_ldap_changed_users_sync(self):
        r = self.admin.create_realm("leak-ldap-sync")
        uid = LdapHelper.import_anna(self, r)
        self.assertEncrypted(uid)
        time.sleep(2)  # changed-users sync compares LDAP modifyTimestamp with the last sync
        LdapHelper.set_ldap_names("anna.new@example.com", "Rossi")
        _, res, _ = self.admin.call("POST", "/%s/user-storage/%s/sync?action=triggerChangedUsersSync"
                                    % (r, self.ldap_component))
        self.assertEqual(res.get("updated"), 1, "LDAP sync did not update the user: %s" % res)
        self.assertEncrypted(uid, {"email": "anna.new@example.com", "last_name": "Rossi"})
        self.assertNoClearWrites("anna.new@example.com", "Rossi")

    def test_identity_provider_login_with_force_sync(self):
        # the source realm is encrypted too, so that every write of these values must be hashed
        src = self.admin.create_realm("idp-src", clients=[{
            "clientId": "broker", "secret": "broker-secret", "publicClient": False,
            "standardFlowEnabled": True, "redirectUris": ["*"]}])
        bob = self.admin.create_user(src, "bob", password=PASSWORD, firstName="Bob", lastName="Builder")
        dst = self.admin.create_realm("idp-dst", identityProviders=[{
            "alias": "src", "providerId": "oidc", "enabled": True, "trustEmail": True,
            "config": {"syncMode": "FORCE", "clientId": "broker", "clientSecret": "broker-secret",
                       "clientAuthMethod": "client_secret_post",
                       "authorizationUrl": kc.KC_URL + "/realms/idp-src/protocol/openid-connect/auth",
                       "tokenUrl": kc.KC_INTERNAL_URL + "/realms/idp-src/protocol/openid-connect/token",
                       # claims come from the ID token: the back-channel userinfo call fails in
                       # this stack (browser and server see Keycloak under different hostnames)
                       "disableUserInfo": "true",
                       "validateSignature": "false", "useJwksUrl": "false",
                       "defaultScope": "openid email profile", "pkceEnabled": "false"}}])

        def broker_login():
            b = kc.Browser().start_login(dst, "&kc_idp_hint=src")
            b.submit({"username": "bob", "password": PASSWORD})
            if not b.arrived:  # e.g. first broker login "review profile" page
                b.submit()
            self.assertIsNotNone(b.arrived, "broker login did not complete:\n" + b.page[:800])

        broker_login()
        uid = self.admin.user_id(dst, "bob")
        self.assertEncrypted(uid, {"username": "bob", "last_name": "Builder"})
        # FORCE sync copies changed IdP claims into the local user on every login
        self.admin.call("PUT", "/%s/users/%s" % (src, bob),
                        {"firstName": "Bob", "lastName": "BrokerChanged", "email": "bob@example.com"})
        broker_login()
        self.assertEqual(self.admin_view(dst, uid)["lastName"], "BrokerChanged")
        self.assertEncrypted(uid, {"username": "bob", "last_name": "BrokerChanged"})
        self.assertNoClearWrites("bob@example.com", "Builder", "BrokerChanged")

    def test_create_without_username_in_email_as_username_realm(self):
        r = self.admin.create_realm("leak-email-as-username", registrationEmailAsUsername=True)
        self.admin.call("POST", "/%s/users" % r, {"email": "eau.user@example.com", "firstName": "Eau",
                                                   "lastName": "User", "enabled": True})
        uid = self.admin.get("/%s/users?email=eau.user@example.com&exact=true" % r)[0]["id"]
        self.assertEncrypted(uid, {"username": "eau.user@example.com", "email": "eau.user@example.com"})
        self.assertNoClearWrites("eau.user@example.com")


class EncryptOnWrite(EncryptionTestCase):
    """Edge cases of encrypting on write (fix 5)."""

    def test_realm_import_with_encryption_off_stays_clear(self):
        users = [{"username": "off.%d" % i, "email": "off.%d@example.com" % i, "firstName": "Off",
                  "lastName": "User%d" % i, "enabled": True} for i in range(3)]
        self.admin.call("POST", "", {"realm": "wr-import-off", "enabled": True,
                                     "eventsListeners": ["jboss-logging", "pii-data-encryption"],
                                     "users": users})
        for u in users:
            uid = self.admin.user_id("wr-import-off", u["username"])
            row = kc.user_row(uid)
            self.assertEqual((row["username"], row["email"], row["last_name"]),
                             (u["username"], u["email"], u["lastName"]), "user of a non-encrypted realm changed")
            self.assertEqual(kc.sql("select count(*) from user_entity_encrypted where user_id = '%s'" % uid),
                             [["0"]], "encrypted row for a user of a non-encrypted realm")

    def test_enable_on_existing_users_then_resave_is_idempotent(self):
        r = self.admin.create_realm("wr-enable", encrypted=False)
        ids = [self.admin.create_user(r, "pre.%d" % i) for i in range(3)]
        self.admin.set_encryption(r, True)
        for i, uid in enumerate(ids):
            self.assertEncrypted(uid, {"username": "pre.%d" % i})
        before = kc.sql("select user_id, id, email from user_entity_encrypted where user_id in (%s) order by user_id"
                        % ",".join("'%s'" % u for u in ids))
        self.admin.set_encryption(r, True)
        after = kc.sql("select user_id, id, email from user_entity_encrypted where user_id in (%s) order by user_id"
                       % ",".join("'%s'" % u for u in ids))
        self.assertEqual([b[:2] for b in before], [a[:2] for a in after], "re-saving duplicated encrypted rows")

    def test_login_does_not_rewrite_the_user(self):
        r = self.admin.create_realm("wr-churn", loginWithEmailAllowed=True)
        uid = self.admin.create_user(r, "churn.user", password=PASSWORD)
        cipher = kc.sql("select username, email, first_name, last_name from user_entity_encrypted "
                        "where user_id = '%s'" % uid)
        mark = len(kc.pg_log())
        kc.password_grant(r, "churn.user", PASSWORD)
        kc.password_grant(r, "churn.user@example.com", PASSWORD)
        self.assertEqual(kc.user_entity_updates_of(uid, mark), 0, "login rewrote user_entity")
        self.assertEqual(kc.sql("select username, email, first_name, last_name from user_entity_encrypted "
                                "where user_id = '%s'" % uid), cipher, "login re-encrypted the user")

    def test_admin_logout_writes_once_and_keeps_ciphertext(self):
        r = self.admin.create_realm("wr-logout")
        uid = self.admin.create_user(r, "once.user")
        cipher = kc.sql("select username, email from user_entity_encrypted where user_id = '%s'" % uid)
        mark = len(kc.pg_log())
        self.admin.call("POST", "/%s/users/%s/logout" % (r, uid))
        self.assertEqual(kc.user_entity_updates_of(uid, mark), 1, "expected exactly one UPDATE of the user")
        self.assertEqual(kc.sql("select username, email from user_entity_encrypted where user_id = '%s'" % uid),
                         cipher, "unchanged values were re-encrypted")
        self.assertEncrypted(uid, {"username": "once.user"})

    def test_duplicate_emails_allowed_keeps_random_constraint(self):
        r = self.admin.create_realm("wr-dup", duplicateEmailsAllowed=True, loginWithEmailAllowed=False)
        a = self.admin.create_user(r, "dup.a", password=PASSWORD, email="shared@example.com")
        b = self.admin.create_user(r, "dup.b", password=PASSWORD, email="shared@example.com")
        self.admin.call("PUT", "/%s/users/%s" % (r, a), {"firstName": "Dup", "lastName": "A", "email": "shared@example.com"})
        kc.password_grant(r, "dup.b", PASSWORD)
        for uid, name in ((a, "dup.a"), (b, "dup.b")):
            self.assertEncrypted(uid, {"username": name, "email": "shared@example.com"}, random_constraint=True)
        self.assertNoClearWrites("shared@example.com")

    def test_user_without_email(self):
        r = self.admin.create_realm("wr-noemail")
        self.admin.call("POST", "/%s/users" % r, {"username": "no.mail", "firstName": "NoMailFirst",
                                                   "lastName": "NoMailLast", "enabled": True})
        uid = self.admin.user_id(r, "no.mail")
        row = kc.user_row(uid)
        self.assertIsNone(row["email"])
        self.assertEncrypted(uid, {"username": "no.mail", "first_name": "NoMailFirst"}, random_constraint=True)
        self.assertNoClearWrites("no.mail", "NoMailFirst", "NoMailLast")

    def test_username_that_looks_like_a_hash(self):
        r = self.admin.create_realm("wr-hexname")
        name = "ab" * 20  # 40 hex characters
        uid = self.admin.create_user(r, name, email="hex.user@example.com", firstName="HexFirst")
        self.admin.call("PUT", "/%s/users/%s" % (r, uid), {"firstName": "HexFirst", "lastName": "HexChanged",
                                                           "email": "hex.user@example.com"})
        self.assertEncrypted(uid, {"username": name, "last_name": "HexChanged"})
        view = self.admin_view(r, uid)
        self.assertEqual((view["username"], view["email"], view["lastName"]), (name, "hex.user@example.com", "HexChanged"))

    def test_hex_username_in_realm_without_encryption_stays_clear(self):
        r = self.admin.create_realm("wr-hex-off", encrypted=False)
        name = "cd" * 20
        uid = self.admin.create_user(r, name, email="hexoff@example.com", firstName="HexOffFirst")
        self.admin.call("POST", "/%s/users/%s/logout" % (r, uid))
        row = kc.user_row(uid)
        self.assertEqual((row["username"], row["email"], row["first_name"]), (name, "hexoff@example.com", "HexOffFirst"))
        self.assertEqual(kc.sql("select count(*) from user_entity_encrypted where user_id = '%s'" % uid), [["0"]])

    def test_hex_username_created_before_enabling(self):
        r = self.admin.create_realm("wr-hex-pre", encrypted=False)
        name = "ef" * 20
        uid = self.admin.create_user(r, name, email="hexpre@example.com", firstName="HexPreFirst")
        self.admin.set_encryption(r, True)
        self.admin.call("POST", "/%s/users/%s/logout" % (r, uid))  # any later write must encrypt it fully
        self.assertEncrypted(uid, {"username": name, "email": "hexpre@example.com", "first_name": "HexPreFirst"})
        view = self.admin_view(r, uid)
        self.assertEqual((view["username"], view["email"], view["firstName"]), (name, "hexpre@example.com", "HexPreFirst"))

    def test_service_account_stays_clear(self):
        r = self.admin.create_realm("wr-sa", clients=[{"clientId": "svc", "secret": "svc-secret",
                                                       "publicClient": False, "serviceAccountsEnabled": True}])
        uid = self.admin.user_id(r, "service-account-svc")
        self.assertIsNotNone(uid, "service account user not created")
        self.assertEqual(kc.user_row(uid)["username"], "service-account-svc")
        self.assertEqual(kc.sql("select count(*) from user_entity_encrypted where user_id = '%s'" % uid), [["0"]])

    def test_undecryptable_user_is_not_double_hashed(self):
        r = self.admin.create_realm("wr-undec")
        uid = self.admin.create_user(r, "undec.user")
        before = kc.user_row(uid)
        kc.sql("delete from user_entity_encrypted where user_id = '%s'" % uid)
        self.admin.call("POST", "/%s/users/%s/logout" % (r, uid))
        after = kc.user_row(uid)
        for col in ("username", "email", "email_constraint", "first_name", "last_name"):
            self.assertEqual(after[col], before[col], "%s of an undecryptable user was rewritten" % col)

    def test_user_left_in_clear_by_an_older_version_is_repaired(self):
        r = self.admin.create_realm("wr-repair", encrypted=False)
        uid = self.admin.create_user(r, "left.clear")
        # simulate a deployment upgraded with a clear row in an encrypted realm: turn the flag on
        # behind Keycloak's back (no sweep), then drop the cached realm
        kc.sql("insert into realm_attribute (name, realm_id, value) select 'users.encrypt', id, 'true' "
               "from realm where name = '%s'" % r)
        self.admin.call("POST", "/%s/clear-realm-cache" % r)
        self.assertEqual(kc.user_row(uid)["username"], "left.clear")
        # an admin update that re-sends the same values (nothing in the row changes)
        self.admin.call("PUT", "/%s/users/%s" % (r, uid), {"firstName": kc.first_name("left.clear"),
                                                           "lastName": kc.last_name("left.clear"),
                                                           "email": "left.clear@example.com"})
        self.assertEncrypted(uid, {"username": "left.clear", "email": "left.clear@example.com"})
        self.assertEqual(self.admin_view(r, uid)["email"], "left.clear@example.com")

    def test_email_as_username_create_has_no_listener_error(self):
        r = self.admin.create_realm("wr-eau", registrationEmailAsUsername=True)
        self.admin.call("POST", "/%s/users" % r, {"email": "eau.npe@example.com", "firstName": "Eau",
                                                   "lastName": "Npe", "enabled": True})
        self.assertNotIn("NullPointerException", kc.keycloak_log())

    @unittest.expectedFailure
    def test_multivalued_attribute_values_are_preserved(self):
        """Known limit until PII attributes are encrypted on write too (one encrypted row per name)."""
        self.admin.call("POST", "", {"realm": "wr-multi", "enabled": True,
                                     "attributes": {"users.encrypt": "true"},
                                     "eventsListeners": ["jboss-logging", "pii-data-encryption"],
                                     "users": [{"username": "mv.user", "email": "mv.user@example.com",
                                                "firstName": "Mv", "lastName": "User", "enabled": True,
                                                "attributes": {"pii-phone": ["111", "222"]}}]})
        uid = self.admin.user_id("wr-multi", "mv.user")
        self.assertEqual(sorted(self.admin_view("wr-multi", uid)["attributes"]["pii-phone"]), ["111", "222"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
