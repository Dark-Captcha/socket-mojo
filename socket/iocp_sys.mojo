# Windows IOCP backend — STRUCTURAL SKELETON ONLY.
#
# This file does not work yet. It exists to lay out the port shape so
# a Windows contributor (or future-us with a Windows CI box) can fill
# in the bodies without redesigning the Ring API.
#
# Architectural parity with `uring_sys.mojo`:
#
#   io_uring                       │  Windows IOCP
#   -------------------------------┼-----------------------------------
#   io_uring_setup                 │  CreateIoCompletionPort(INVALID_HANDLE_VALUE, ..., 0, N)
#   io_uring_enter                 │  GetQueuedCompletionStatusEx (reap) + PostQueuedCompletionStatus (msg)
#   SQE submission                 │  per-op syscall (WSARecv / WSASend / ConnectEx / AcceptEx)
#   CQE                            │  OVERLAPPED-completed callback / GetQueuedCompletionStatusEx
#   IOSQE_FIXED_FILE               │  not applicable (HANDLE is already a slot)
#   IORING_OP_RECV multishot       │  WSARecv with a long-lived OVERLAPPED + re-issued on completion
#   IORING_REGISTER_PBUF_RING      │  WSARecv accepts caller-supplied buffer per op
#   IORING_OP_SEND_ZC              │  WSASend (zero-copy on Windows is opt-in via flags)
#   IORING_OP_MSG_RING             │  PostQueuedCompletionStatus
#
# Shape that callers see (Ring API): UNCHANGED. Ring.recv / send /
# accept etc. dispatch through a backend trait; on Linux it's the
# UringQueue, on Windows it's the IocpQueue defined here.
#
# Implementation notes:
#   * OVERLAPPED structures live in op slots (mirror of the io_uring
#     slot table) so the kernel can write completion info there.
#   * WSARecv must be re-issued per recv (no true multishot on Windows
#     pre-Server 2022); the engine emulates multishot by re-arming.
#   * AcceptEx requires a pre-created accepted socket — pool them.
#   * Connect via ConnectEx (needs WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER))
#     to get the function pointer at runtime.
#   * Error mapping: WSAGetLastError() — NOT the same as POSIX errno
#     numbers, needs a WSA→POSIX translation table.

from std.memory import UnsafePointer


comptime _NOT_IMPLEMENTED = (
    "socket.iocp: Windows backend not yet implemented; see "
    "WINDOWS.md for the port plan"
)


struct IocpQueue(Movable):
    """Mirror of UringQueue for Windows IOCP. Empty fields here mean
    the port still owes the implementation."""

    var port_handle: Int  # HANDLE returned by CreateIoCompletionPort
    var entries: Int

    def __init__(out self, entries: Int) raises:
        self.port_handle = 0
        self.entries = entries
        raise Error(_NOT_IMPLEMENTED)

    def __del__(deinit self):
        # CloseHandle(self.port_handle) when implemented
        pass

    def push_sqe(
        mut self,
        opcode: UInt8,
        fd: Int,
        addr: UInt64,
        length: UInt32,
        off_or_addr2: UInt64,
        op_flags: UInt32,
        user_data: UInt64,
    ) raises:
        """In IOCP this is a direct Win32 syscall (WSARecv etc.)
        rather than a deferred SQE — the function name dispatches on
        opcode."""
        raise Error(_NOT_IMPLEMENTED)

    def enter(mut self, min_complete: Int) raises -> Int:
        """GetQueuedCompletionStatusEx with min_complete entries,
        timeout=INFINITE (or 0 for non-blocking)."""
        raise Error(_NOT_IMPLEMENTED)
