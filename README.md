# DHCP Lease Monitor for OpenBSD (written in Rust)

This is a daemon that monitors any lease changes for the specified
interfaces. When a change happens it then calls a script located
in /etc/dhcpleasemon. The script name should be:

    lease_trigger_<interface>

The script has access to the following environment variables:

* `$DHCP_IFACE` -- interface name
* `$DHCP_IP_ROUTE` -- default route for the interface
* `$DHCP_IP_ADDR` -- IP address from the lease


