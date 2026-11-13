"""Helpers for the end-to-end tests: Keycloak admin API, browser-like flows, DB access.

Python 3 standard library only. Talks to the stack started by run.sh (docker-compose.yml).
"""
import hashlib
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from http.cookiejar import CookieJar, DefaultCookiePolicy

KC_URL = os.environ.get("KC_URL", "http://localhost:18180")
MAILPIT_URL = os.environ.get("MAILPIT_URL", "http://localhost:18025")
# How Keycloak reaches itself from inside the container (IdP back-channel calls).
KC_INTERNAL_URL = "http://keycloak:8080"
REDIRECT_URI = "http://localhost/cb"
COMPOSE_DIR = os.path.dirname(os.path.abspath(__file__))
HASH_RE = re.compile(r"^[0-9a-f]{40}$")
UUID_RE = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"


def sha1(value):
    """The provider's lookup hash: SHA-1 of the trimmed, lower-cased value."""
    return hashlib.sha1(value.strip().lower().encode()).hexdigest()


def is_hash(value):
    return value is not None and bool(HASH_RE.match(value))


# --------------------------------------------------------------------------- docker / DB

def compose(*args, stdin=None):
    return subprocess.run(["docker", "compose", *args], cwd=COMPOSE_DIR, input=stdin,
                          capture_output=True, text=True, check=True).stdout


def sql(query):
    """Run a query in the stack's PostgreSQL; returns a list of rows (lists of strings)."""
    out = compose("exec", "-T", "postgres", "psql", "-U", "keycloak", "-d", "keycloak",
                  "-tA", "-F", "\x1f", "-c", query)
    return [line.split("\x1f") for line in out.splitlines() if line]


def user_row(user_id):
    """USER_ENTITY columns of a user, as stored in the database."""
    rows = sql("select username, email, email_constraint, first_name, last_name, "
               "email_verified, not_before from user_entity where id = '%s'" % user_id)
    if not rows:
        return None
    keys = ["username", "email", "email_constraint", "first_name", "last_name",
            "email_verified", "not_before"]
    return {k: (v if v != "" else None) for k, v in zip(keys, rows[0])}


_WRITE_RE = re.compile(r"\b(insert\s+into|update)\s+(public\.)?user_entity\b", re.I)


def pg_log():
    return compose("logs", "--no-log-prefix", "postgres").splitlines()


def user_entity_writes(since=0):
    """(statement, bound values) of every INSERT/UPDATE on user_entity in the PostgreSQL log.

    since: index in pg_log() to start from, to look only at what a test step did. The bound
    values are the DETAIL "parameters" line of a prepared statement, or the statement itself
    for the simple query protocol (literal values).
    """
    lines = pg_log()
    writes = []
    for i in range(since, len(lines)):
        if not _WRITE_RE.search(lines[i]):
            continue
        params = lines[i + 1] if i + 1 < len(lines) and "DETAIL:" in lines[i + 1] else None
        writes.append((lines[i], params if params is not None else lines[i]))
    return writes


def clear_writes(values, since=0):
    """Writes on user_entity that bound any of values (case-insensitive)."""
    needles = [v.lower() for v in values if v]
    return [(stmt + " " + bound)[:500] for stmt, bound in user_entity_writes(since)
            if any(n in bound.lower() for n in needles)]


def user_entity_updates_of(user_id, since=0):
    """Number of UPDATE statements on user_entity that targeted user_id."""
    return sum(1 for stmt, bound in user_entity_writes(since)
               if stmt.lower().find("update") >= 0 and user_id in bound)


def keycloak_log():
    return compose("logs", "--no-log-prefix", "keycloak")


def ldap_modify(ldif):
    compose("exec", "-T", "ldap", "/opt/bitnami/openldap/bin/ldapmodify", "-x",
            "-H", "ldap://localhost:1389", "-D", "cn=admin,dc=example,dc=org", "-w", "admin",
            stdin=ldif)


def wait_for_ldap(timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            compose("exec", "-T", "ldap", "/opt/bitnami/openldap/bin/ldapsearch", "-x",
                    "-H", "ldap://localhost:1389", "-b", "dc=example,dc=org",
                    "-D", "cn=admin,dc=example,dc=org", "-w", "admin", "(uid=anna.bianchi)", "dn")
            return
        except subprocess.CalledProcessError:
            time.sleep(2)
    raise RuntimeError("LDAP not ready")


# --------------------------------------------------------------------------- HTTP

def first_name(username):
    """Default first name of a test user: unique per user, never hex-like (good log marker)."""
    return "Fn" + re.sub(r"\W", "", username).capitalize()


def last_name(username):
    return "Ln" + re.sub(r"\W", "", username).capitalize()


class HttpError(Exception):
    def __init__(self, code, body):
        super().__init__("HTTP %s: %s" % (code, body[:300]))
        self.code = code
        self.body = body


def http(method, url, body=None, headers=None, form=None):
    data = None
    headers = dict(headers or {})
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw and raw[0] in "[{" else raw), resp.headers
    except urllib.error.HTTPError as e:
        raise HttpError(e.code, e.read().decode())


def wait_for_keycloak(timeout=240):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            http("GET", KC_URL + "/realms/master")
            return
        except Exception:
            time.sleep(2)
    raise RuntimeError("Keycloak not ready at " + KC_URL)


class Admin:
    """Admin REST client; refreshes its master-realm token as needed."""

    def __init__(self):
        self._token, self._at = None, 0

    def _auth(self):
        if not self._token or time.time() - self._at > 30:
            _, tok, _ = http("POST", KC_URL + "/realms/master/protocol/openid-connect/token",
                             form={"client_id": "admin-cli", "username": "admin",
                                   "password": "admin", "grant_type": "password"})
            self._token, self._at = tok["access_token"], time.time()
        return {"Authorization": "Bearer " + self._token}

    def call(self, method, path, body=None):
        return http(method, KC_URL + "/admin/realms" + path, body=body, headers=self._auth())

    def get(self, path):
        return self.call("GET", path)[1]

    # ---- convenience

    def create_realm(self, name, encrypted=True, **extra):
        rep = {"realm": name, "enabled": True,
               "eventsListeners": ["jboss-logging", "pii-data-encryption"],
               "clients": [{"clientId": "verify", "publicClient": True,
                            "directAccessGrantsEnabled": True, "standardFlowEnabled": True,
                            "redirectUris": [REDIRECT_URI + "*"]}]}
        rep.update(extra)
        self.call("POST", "", rep)
        if encrypted:
            self.set_encryption(name, True)
        return name

    def set_encryption(self, realm, enabled):
        realm_id = self.get("/" + realm)["id"]
        existing = self.get("/%s/components?type=org.keycloak.services.ui.extend.UiTabProvider" % realm)
        comp = {"name": "User Entity Encryption", "providerId": "User Entity Encryption",
                "providerType": "org.keycloak.services.ui.extend.UiTabProvider",
                "parentId": realm_id, "config": {"enable": ["true" if enabled else "false"]}}
        if existing:
            comp["id"] = existing[0]["id"]
            self.call("PUT", "/%s/components/%s" % (realm, comp["id"]), comp)
        else:
            self.call("POST", "/%s/components" % realm, comp)

    def user_id(self, realm, username):
        users = self.get("/%s/users?username=%s&exact=true" % (realm, urllib.parse.quote(username)))
        return users[0]["id"] if users else None

    def create_user(self, realm, username, password=None, inline_password=False, **fields):
        rep = {"username": username, "email": username + "@example.com",
               "firstName": first_name(username), "lastName": last_name(username), "enabled": True}
        rep.update(fields)
        if password and inline_password:
            rep["credentials"] = [{"type": "password", "value": password, "temporary": False}]
        self.call("POST", "/%s/users" % realm, rep)
        uid = self.user_id(realm, username)
        if password and not inline_password:
            self.call("PUT", "/%s/users/%s/reset-password" % (realm, uid),
                      {"type": "password", "value": password, "temporary": False})
        return uid


def password_grant(realm, username, password, client_id="verify"):
    _, tok, _ = http("POST", "%s/realms/%s/protocol/openid-connect/token" % (KC_URL, realm),
                     form={"client_id": client_id, "grant_type": "password",
                           "username": username, "password": password})
    return tok


# --------------------------------------------------------------------------- browser

class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms, self.links, self._form = [], [], None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._form = {"action": a.get("action", ""), "fields": {}}
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None and a.get("name"):
            if a.get("type") in ("checkbox", "radio") and "checked" not in a:
                return
            self._form["fields"][a["name"]] = a.get("value", "")
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


class _StopAtRedirectUri(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if newurl.startswith(REDIRECT_URI):
            raise _Arrived(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _Arrived(Exception):
    def __init__(self, url):
        super().__init__(url)
        self.url = url


class _LocalhostCookiePolicy(DefaultCookiePolicy):
    """Send Secure cookies over plain http, as browsers do for http://localhost.

    Keycloak marks its login cookies Secure; without this, every login flow fails with
    "Restart login cookie not found".
    """

    def return_ok_secure(self, cookie, request):
        return True


class Browser:
    """Cookie-keeping client that follows redirects and can submit HTML forms.

    Stops when Keycloak redirects to REDIRECT_URI (the end of a login flow) and records it.
    """

    def __init__(self):
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(CookieJar(policy=_LocalhostCookiePolicy())),
            _StopAtRedirectUri())
        self.page, self.url, self.arrived = "", None, None

    def _open(self, req):
        try:
            with self.opener.open(req, timeout=120) as resp:
                self.page, self.url = resp.read().decode(), resp.geturl()
        except _Arrived as done:
            self.arrived, self.page = done.url, ""
        except urllib.error.HTTPError as e:
            self.page, self.url = e.read().decode(), e.geturl()
            raise HttpError(e.code, self.page)
        return self

    def get(self, url):
        return self._open(urllib.request.Request(url))

    def submit(self, overrides=None, form_index=0):
        p = _FormParser()
        p.feed(self.page)
        if len(p.forms) <= form_index:
            raise AssertionError("no form on page %s:\n%s" % (self.url, self.page[:1500]))
        form = p.forms[form_index]
        fields = dict(form["fields"])
        fields.update(overrides or {})
        action = urllib.parse.urljoin(self.url, form["action"].replace("&amp;", "&"))
        data = urllib.parse.urlencode(fields).encode()
        return self._open(urllib.request.Request(action, data=data, method="POST"))

    def links(self):
        p = _FormParser()
        p.feed(self.page)
        return [urllib.parse.urljoin(self.url, h.replace("&amp;", "&")) for h in p.links]

    def start_login(self, realm, extra=""):
        url = ("%s/realms/%s/protocol/openid-connect/auth?client_id=verify&response_type=code"
               "&scope=openid&redirect_uri=%s%s" % (KC_URL, realm, urllib.parse.quote(REDIRECT_URI), extra))
        return self.get(url)


# --------------------------------------------------------------------------- mail

def mail_links_to(address, timeout=30):
    """Links in the newest Mailpit message sent to address."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        _, data, _ = http("GET", MAILPIT_URL + "/api/v1/search?query=" + urllib.parse.quote("to:" + address))
        if data.get("messages"):
            msg_id = data["messages"][0]["ID"]
            _, msg, _ = http("GET", MAILPIT_URL + "/api/v1/message/" + msg_id)
            return re.findall(r'https?://[^\s"<>]+', msg.get("Text", ""))
        time.sleep(1)
    raise AssertionError("no mail to " + address)
