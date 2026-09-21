# GlobalConnect

Omarchy bar widget scaffold for a future NetworkManager VPN client. The current panel reports that the backend is not configured; it cannot connect to a VPN yet.

## Validate

Run `make validate` from this directory. Omarchy loads `BarWidget.qml` as a `bar-widget`; that file loads `Panel.qml` in the existing shell process.

## Planned runtime dependencies

The VPN implementation will require NetworkManager, the relevant `networkmanager-openconnect` or `networkmanager-openvpn` plugin, and a working user-session secret agent. Network changes are authorized through NetworkManager and polkit. The plugin will not invoke `sudo`.
