# socket.addr — IP address and socket-address value types. Pure Mojo, no
# FFI. IPv4 (RFC 791) and IPv6 (RFC 8200) are DISTINCT types; `SocketAddr`
# is the family-discriminated sum that pairs either with a port and that
# the kernel sockaddr serializer round-trips.

from socket.addr.family import AddressFamily
from socket.addr.ipv4 import Ipv4Address, parse_ipv4
from socket.addr.ipv6 import Ipv6Address, parse_ipv6
from socket.addr.socket_addr import (
    SocketAddr,
    parse_ip,
    read_sockaddr,
    write_sockaddr,
)
