import json
from typing import Any
from urllib import request


class LanyardError(Exception):
    def __init__(self, message: str, status: int):
        super().__init__(message.replace("Bearer ", "Bearer [REDACTED]"))
        self.status = status


class PendingGrant:
    def __init__(self, client: "Lanyard", response: dict[str, Any]):
        self._client = client
        self.response = response

    async def fetch(self, connector: str, path: str):
        token = self.response.get("token")
        if not token:
            raise LanyardError("grant is pending approval", 202)
        return await self._client.proxy_fetch(connector, path, token)


class Lanyard:
    def __init__(self, control_plane_url: str, proxy_url: str):
        self.control_plane_url = control_plane_url.rstrip("/")
        self.proxy_url = proxy_url.rstrip("/")

    async def request_grant(self, request_data: dict[str, Any]) -> PendingGrant:
        payload = json.dumps(request_data).encode()
        req = request.Request(
            f"{self.control_plane_url}/grant", data=payload,
            headers={"Content-Type": "application/json"}, method="POST")
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
