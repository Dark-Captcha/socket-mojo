# socket-mojo: pure-Mojo blocking TCP + UDP sockets over libc syscalls.
#
# This v0 layer provides the byte-stream interface that the TLS, HTTP,
# and QUIC layers build on top of. Blocking-only here; the same public
# API is preserved when later versions add epoll / io_uring backends.
#
# No external library dependencies — only libc/kernel syscalls
# (`socket`, `connect`, `bind`, `listen`, `accept`, `send`, `recv`,
# `recvfrom`, `sendto`, `setsockopt`, `close`, `getaddrinfo`,
# `freeaddrinfo`, `__errno_location`).
