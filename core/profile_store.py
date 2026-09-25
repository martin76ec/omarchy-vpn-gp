"""Creating profiles from panel requests. NetworkManager is the store; this
layer only validates untrusted input before it reaches the driver."""

from core.drivers.nm_driver import NetworkManagerDriver
from core.errors import VpnError
from core.security import validate_gateway, validate_name, validate_ovpn_path

OPENCONNECT_PROTOCOLS = {"gp", "anyconnect", "pulse"}


def add(driver: NetworkManagerDriver, request: object) -> str:
    if not isinstance(request, dict):
        raise VpnError("INVALID_REQUEST", "Expected a JSON object.")
    kind, name = request.get("kind"), str(request.get("name") or "")
    if kind in OPENCONNECT_PROTOCOLS:
        return driver.add_openconnect(validate_name(name), kind, validate_gateway(str(request.get("gateway") or "")))
    if kind == "openvpn":
        return driver.import_openvpn(validate_ovpn_path(str(request.get("path") or "")), validate_name(name) if name.strip() else None)
    raise VpnError("INVALID_REQUEST", "Unknown profile type.")
