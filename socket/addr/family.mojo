# Address family discriminant (POSIX `sa_family_t`, IETF "Address Family
# Numbers" registry). The platform-neutral tag that selects between the
# `Ipv4Address` (RFC 791) and `Ipv6Address` (RFC 8200) variants of a
# `SocketAddr`. This is NOT the raw Linux `AF_INET`/`AF_INET6` number —
# the sockaddr serializer in `socket_addr.mojo` maps this tag to the
# kernel UAPI constant. Only V4 and V6 are modeled; a future V_UNIX
# (AF_UNIX path sockets) would be the next variant.


@fieldwise_init
struct AddressFamily(Copyable, ImplicitlyCopyable, Movable):
    """Which address variant a `SocketAddr` carries. Callers compare
    against `AddressFamily.V4` / `AddressFamily.V6` rather than raw
    integers — the wire/kernel mapping lives in `socket_addr.mojo`."""

    var value: Int

    comptime V4 = AddressFamily(value=0)  # RFC 791 — IPv4
    comptime V6 = AddressFamily(value=1)  # RFC 8200 — IPv6

    def __eq__(self, other: AddressFamily) -> Bool:
        return self.value == other.value

    def __ne__(self, other: AddressFamily) -> Bool:
        return self.value != other.value

    def name(self) -> String:
        if self == AddressFamily.V4:
            return "v4"
        if self == AddressFamily.V6:
            return "v6"
        return "AddressFamily(" + String(self.value) + ")"
