import io
import urllib.error
import urllib.request

from urirun_connector_plesk import core
from urirun_connector_plesk.core import ensure_ftp_user


XML_OK = '<?xml version="1.0"?><packet><system><status>ok</status></system></packet>'
HTML_404 = "<html><head><title>404 Not Found</title></head><body>404 Not Found</body></html>"


class _FakeResponse:
    def __init__(self, body, status=200, content_type="text/xml"):
        self._body = body.encode("utf-8")
        self.status = status
        self.headers = {"content-type": content_type}

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_panel_xml_origin_candidates_add_8443_for_implicit_443():
    assert core.panel_xml_origin_candidates("https://prototypowanie.pl") == (
        "https://prototypowanie.pl",
        "https://prototypowanie.pl:8443",
    )
    assert core.canonical_panel_xml_origin("https://prototypowanie.pl") == "https://prototypowanie.pl:8443"
    assert core.canonical_panel_xml_origin("https://prototypowanie.pl:443") == "https://prototypowanie.pl:8443"
    assert core.canonical_panel_xml_origin("https://prototypowanie.pl:8443") == "https://prototypowanie.pl:8443"


def test_xml_agent_retries_8443_after_443_html_404(monkeypatch):
    calls = []

    def fake_urlopen(request, timeout=None, context=None):
        calls.append(request.full_url)
        if ":8443/" in request.full_url:
            return _FakeResponse(XML_OK, content_type="text/xml")
        raise urllib.error.HTTPError(
            request.full_url,
            404,
            "Not Found",
            {"content-type": "text/html"},
            io.BytesIO(HTML_404.encode("utf-8")),
        )

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    raw = core._xml_agent("https://prototypowanie.pl", "user", "pass", "<packet/>")
    assert raw == XML_OK
    assert calls == [
        "https://prototypowanie.pl/enterprise/control/agent.php",
        "https://prototypowanie.pl:8443/enterprise/control/agent.php",
    ]


def test_xml_agent_retries_8443_after_443_nginx_301(monkeypatch):
    calls = []

    def fake_urlopen(request, timeout=None, context=None):
        calls.append(request.full_url)
        if ":8443/" in request.full_url:
            return _FakeResponse(XML_OK, content_type="text/xml")
        raise urllib.error.HTTPError(
            request.full_url,
            301,
            "Moved Permanently",
            {"content-type": "text/html", "location": "https://www.prototypowanie.pl/enterprise/control/agent.php"},
            io.BytesIO(b"<html><head><title>301 Moved Permanently</title></head></html>"),
        )

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    raw = core._xml_agent("https://prototypowanie.pl", "user", "pass", "<packet/>")
    assert raw == XML_OK
    assert ":8443/" in calls[-1]


def test_vault_lease_panel_pair_matches_8443_when_443_misses(monkeypatch):
    seen = []

    def fake_lease(entry_id, origin, field, vault_url=""):
        seen.append((origin, field))
        if origin.endswith(":8443"):
            return f"{field}-secret"
        raise RuntimeError(f"plesk_vault_lease_failed:{field}")

    monkeypatch.setattr(core, "_vault_lease", fake_lease)
    origin, username, password = core._vault_lease_panel_pair(
        "plesk-subscription", "https://prototypowanie.pl",
    )
    assert origin == "https://prototypowanie.pl:8443"
    assert username == "username-secret"
    assert password == "password-secret"
    assert seen[0] == ("https://prototypowanie.pl:8443", "username")


def test_ensure_ftp_user_dry_run_target_canonicalizes_implicit_443_without_dropping_scope():
    dry = ensure_ftp_user(
        kind="system",
        domain="subactor.com",
        scope_domains=["auth.subactor.com", "wydruk.subactor.com"],
        base_url="https://prototypowanie.pl",
        credential_vault_entry_id="plesk-sftp",
        also_ftp_vault_entry_id="plesk-ftp",
    )
    assert dry["ok"] and dry["dry_run"]
    assert dry["target"].startswith("https://prototypowanie.pl:8443|deployment-credential:")
    assert dry["scope_domains"] == ["auth.subactor.com", "subactor.com", "wydruk.subactor.com"]
    assert dry["credential_origin"] == "https://prototypowanie.pl"
