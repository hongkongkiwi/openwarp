"""Standard-library client for the OpenWarp HTTP API."""

import json
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class OpenWarpError(Exception):
    """An HTTP, transport, or response decoding failure (status 0 for transport)."""

    def __init__(self, status, message, body):
        self.status = status
        self.message = message
        self.body = body
        super().__init__(f"OpenWarp ({status}): {message}")


class OpenWarp:
    def __init__(self, base_url, token, timeout=30):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    @staticmethod
    def _segment(value):
        return quote(str(value), safe="")

    def api(self, method, segments, body=None, query=None, step_up=None):
        """Call an API route with separately encoded path segments and query."""
        if step_up is not None and (not isinstance(step_up, str) or not step_up
                or len(step_up) > 512 or any(ord(c) < 32 or ord(c) > 126 for c in step_up)):
            raise ValueError("invalid step-up grant")
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            raise ValueError("unsupported HTTP method")
        base = urlsplit(self.base_url)
        if (base.scheme not in {"http", "https"} or not base.hostname
                or base.username is not None or base.password is not None
                or "?" in self.base_url or "#" in self.base_url):
            raise ValueError("base_url must be an HTTP(S) URL without credentials, query, or fragment")
        if not isinstance(segments, (list, tuple)) or not segments:
            raise ValueError("segments must be a non-empty list or tuple")
        for segment in segments:
            if not isinstance(segment, str) or not segment:
                raise ValueError("path segments must be non-empty strings")
            decoded = segment
            for _ in range(len(segment) + 1):
                if (any(part in {".", ".."} for part in decoded.split("/")) or "\\" in decoded
                        or any(ord(c) < 32 or ord(c) == 127 for c in decoded)
                        or "://" in decoded or decoded.startswith("//")):
                    raise ValueError("unsafe path segment")
                for index, char in enumerate(decoded):
                    if char == "%" and (index + 2 >= len(decoded)
                            or any(c not in "0123456789abcdefABCDEF" for c in decoded[index + 1:index + 3])):
                        raise ValueError("invalid percent escape")
                following = unquote(decoded, errors="strict")
                if following == decoded:
                    break
                decoded = following
            else:
                raise ValueError("invalid path encoding")
        path = "/api/" + "/".join(self._segment(s) for s in segments)
        if query:
            path += "?" + urlencode(query, doseq=True)
        return self._request(method, path, body, _opener=build_opener(_NoRedirect()), _step_up=step_up)

    def _request(self, method, path, body=None, *, _opener=None, _step_up=None):
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        if _step_up is not None:
            headers["X-OpenWarp-Step-Up"] = _step_up
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            open_request = _opener.open if _opener is not None else urlopen
            with open_request(request, timeout=self.timeout) as response:
                status = response.status
                raw = response.read().decode("utf-8", errors="replace")
        except HTTPError as exc:
            with exc:
                raw = exc.read().decode("utf-8", errors="replace")
            message = raw or exc.reason
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    message = parsed.get("error") or parsed.get("message") or message
            except ValueError:
                pass
            raise OpenWarpError(exc.code, str(message), raw) from exc
        except (URLError, OSError) as exc:
            raise OpenWarpError(0, str(exc), "") from exc
        if not raw:
            return None
        try:
            return json.loads(raw)
        except ValueError as exc:
            raise OpenWarpError(status, "Invalid JSON response", raw) from exc

    def me(self):
        return self._request("GET", "/api/me")

    def orgs(self):
        return self._request("GET", "/api/orgs")

    def apps(self, org):
        return self._request("GET", f"/api/orgs/{self._segment(org)}/apps")

    def envs(self, app):
        return self._request("GET", f"/api/apps/{self._segment(app)}/envs")

    def secrets(self, env):
        return self._request("GET", f"/api/envs/{self._segment(env)}/secrets")["secrets"]

    def _complete_secrets(self, env):
        url = f"/api/envs/{self._segment(env)}/secrets"
        offset, total, secrets = 0, None, []
        while True:
            page = self._request("GET", url if offset == 0 else f"{url}?offset={offset}")
            if not isinstance(page, dict) or not isinstance(page.get("secrets"), list):
                raise OpenWarpError(0, "Invalid secret pagination response", "")
            items = page["secrets"]
            fields = ("total", "limit", "offset")
            if offset == 0 and "limit" not in page and "offset" not in page:
                if (len(items) > 100_000 or ("total" in page
                        and (type(page["total"]) is not int or page["total"] != len(items)))):
                    raise OpenWarpError(0, "Invalid secret pagination response", "")
                return items
            if any(type(page.get(field)) is not int for field in fields):
                raise OpenWarpError(0, "Invalid secret pagination response", "")
            page_total, limit, page_offset = (page[field] for field in fields)
            if (page_total < 0 or page_total > 100_000 or limit < 1 or limit > 1000
                    or page_offset != offset or (total is not None and total != page_total)
                    or len(items) > limit or offset > page_total or len(items) > page_total - offset
                    or (offset < page_total and not items)):
                raise OpenWarpError(0, "Invalid secret pagination response", "")
            total = page_total
            offset += len(items)
            secrets.extend(items)
            if offset == total:
                return secrets

    def get_secret(self, env, key, path=None):
        """Return a unique case-insensitive key match at the optional exact path."""
        matches = [secret for secret in self._complete_secrets(env)
                   if secret["key"].casefold() == key.casefold()
                   and (path is None or secret["path"] == path)]
        if len(matches) > 1:
            raise OpenWarpError(409, f"Ambiguous secret: {key} matches multiple records", "")
        if not matches:
            raise OpenWarpError(404, f"Secret not found: {key}", "")
        return matches[0]

    def set_secret(self, env, key, value, path="/", type="secret", comment=""):
        return self._request("PUT", f"/api/envs/{self._segment(env)}/secrets", {
            "secrets": [{"key": key, "value": value, "path": path,
                         "type": type, "comment": comment, "tags": ""}]
        })

    def delete_secret(self, env, key, path=None):
        secret = self.get_secret(env, key, path)
        return self._request("DELETE", f"/api/secrets/{self._segment(secret['id'])}")

    def export(self, env):
        return self._request("GET", f"/api/envs/{self._segment(env)}/export")

    def leases(self, env):
        return self._request("GET", f"/api/envs/{self._segment(env)}/dynamic")

    def create_lease(self, env, name, ttl_secs=3600):
        return self._request("POST", f"/api/envs/{self._segment(env)}/dynamic",
                             {"name": name, "ttl_secs": ttl_secs})

    def audit(self, org):
        return self._request("GET", f"/api/orgs/{self._segment(org)}/audit")
