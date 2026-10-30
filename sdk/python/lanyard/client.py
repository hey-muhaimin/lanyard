import base64
import json
import secrets
import time
from typing import Any
from urllib import request
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _grant_proof(private_key_seed: bytes, method: str, target_url: str) -> str:
    if len(private_key_seed) != 32:
        raise ValueError("agent private key must be a 32-byte Ed25519 seed")
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_seed)
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    header = {
        "alg": "EdDSA",
        "typ": "dpop+jwt",
        "jwk": {"kty": "OKP", "crv": "Ed25519", "x": _b64url(public_key)},
    }
    claims = {"htm": method, "htu": target_url, "iat": int(time.time()), "jti": secrets.token_urlsafe(18)}
    unsigned = ".".join(_b64url(json.dumps(value, separators=(",", ":")).encode()) for value in (header, claims))
    signature = private_key.sign(unsigned.encode("ascii"))
    return unsigned + "." + _b64url(signature)


class LanyardError(Exception):
    def __init__(self, message: str, status: int):
        super().__init__(message.replace("Bearer ", "Bearer [REDACTED]"))
        self.status = status


class PendingGrant:
    def __init__(self, client: "Lanyard", response: dict[str, Any]):
        self._client = client
        self.response = response

    async def fetch(self, connector: str, path: str):
        token = self.response.get("access_token") or self.response.get("token")
        if not token:
            raise LanyardError("grant is pending approval", 202)
        return await self._client.proxy_fetch(connector, path, token)


class Lanyard:
    def __init__(self, control_plane_url: str, proxy_url: str, agent_private_key: bytes | None = None):
        self.control_plane_url = control_plane_url.rstrip("/")
        self.proxy_url = proxy_url.rstrip("/")
        self.agent_private_key = agent_private_key

    async def request_grant(self, request_data: dict[str, Any]) -> PendingGrant:
        if self.agent_private_key is None:
            raise LanyardError("agent private key is required for grant requests", 0)
        payload = json.dumps(request_data).encode()
        url = f"{self.control_plane_url}/grant"
        parsed_url = urlsplit(url)
        target_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        req = request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json", "DPoP": _grant_proof(self.agent_private_key, "POST", target_url)}, method="POST")
        try:
            with request.urlopen(req, timeout=10) as response:
                return PendingGrant(self, json.loads(response.read()))
        except request.HTTPError as exc:
            raise LanyardError(exc.read().decode(errors="replace"), exc.code) from exc

    async def proxy_fetch(self, connector: str, path: str, token: str):
        url = f"{self.proxy_url}/proxy/{connector}{path if path.startswith('/') else '/' + path}"
        req = request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with request.urlopen(req, timeout=15) as response:
            return response.status, response.read()
