#!/usr/bin/env python3

import argparse
import asyncio
import enum
from ipaddress import ip_address
import logging
import struct
import socket


VERSION = 5
PORT = 1080


class AddressType(enum.Enum):
    """SOCKS5 address type."""
    IP4 = 1
    DOMAIN = 3
    IP6 = 4


class AuthMethod(enum.Enum):
    """SOCKS5 authentication method."""
    NO_AUTH = 0
    GSSAPI = 1
    PASSWORD = 2
    INVALID = 255


class Command(enum.Enum):
    """SOCKS5 request command."""
    CONNECT = 1
    BIND = 2
    UPD_ASSOCIATE = 3


class Error(enum.Enum):
    """SOCKS5 reply status code."""
    FAILURE = 1
    NOT_ALLOWED = 2
    NETWORK_UNREACHABLE = 3
    HOST_UNREACHABLE =  4
    REFUSED = 5
    TTL_EXPIRED = 6
    NOT_SUPPORTED = 7
    ADDRESS_NOT_SUPPORTED = 8
    UNASSIGNED = 9


async def resolve_addr(host: str) -> str | None:
    """Resolve IP address from domain name.

    Args:
        host: Domain name.

    Returns:
        IP address string if found, otherwise None.
    """
    loop = asyncio.get_running_loop()
    info = await loop.getaddrinfo(host, None, proto=socket.SOCK_STREAM)

    return info[0][-1][0]


def send_error(transport: asyncio.WriteTransport, error: Error):
    """Send a reply indicating that the request has failed.

    Args:
        transport: Writeable transport to send reply to.
        error: Failed reply status code.
    """
    # As this is an error reply and we will be closing the connection
    # after it anyway, we just use all zeros for address and port.
    buffer = struct.pack("!4BIH", VERSION, error.value, 0, 1, 0, 0)
    transport.write(buffer)


def send_auth_message(transport: asyncio.WriteTransport, method: AuthMethod):
    """Send method selection message to the client.

    Args:
        transport: Writeable transport to send message to.
        method: Chosen authentication method.
    """
    buffer = struct.pack("!2B", VERSION, method.value)
    transport.write(buffer)


class BaseSocksMessage:
    """Base class for SOCKS5 requests/messages"""

    version = VERSION


class SocksRequest(BaseSocksMessage):
    """SOCKS5 request class."""
    
    def __init__(self, cmd: int, atyp: int,
                 dst_addr: str, dst_port: int):
        """Constructor.

        Args:
            cmd: SOCKS request command.
            atyp: SOCKS address type.
            dst_addr: Destination address. str for domain name, int for
                IPv4/6 addresses.
            dst_port: Destination port.
        """
        self.cmd = Command(cmd)
        self.atyp = AddressType(atyp)
        self.dst_addr = dst_addr
        self.dst_port = dst_port


class SocksReply(BaseSocksMessage):
    """SOCKS5 reply class."""

    def __init__(self, atyp: int, bnd_addr: str, bnd_port: int):
        """Constructor.
        
        Args:
            reply: Reply status code.
            atyp: SOCKS address type.
            bnd_addr: Server bound address.
            bnd_port: Server bound port.
        """
        self.atyp = AddressType(atyp)
        self.bnd_addr = bnd_addr
        self.bnd_port = bnd_port

    def dump(self) -> bytes:
        """Dump reply object as a bytes sequence."""
        buffer = struct.pack("!4B", VERSION, 0,
                             0, self.atyp.value)

        if self.atyp in (AddressType.IP4, AddressType.IP6):
            return (buffer
                    + ip_address(self.bnd_addr).packed
                    + struct.pack("!H", self.bnd_port))

        return buffer + struct.pack(
            f"!{len(self.bnd_addr)}sH",
            self.bnd_addr.encode("ascii"),
            self.bnd_port)


class IncorrectPacket(Exception):
    """Incorrect packet exception.

    Used when received packet or request is corrupted and can not be
        parsed.
    """


def get_methods_from_message(message: bytes) -> set[AuthMethod]:
    """Get a set of `AuthMethod` from method selection message.

    Raises:
        IncorrectPacket: If the packet is too short or corrupted.
    """
    if len(message) < 3:
        raise IncorrectPacket

    version, nmethods = struct.unpack_from("!2B", message)
    if version != VERSION or nmethods != len(message) - 2:
        raise IncorrectPacket

    return set(
        AuthMethod(m) for m in struct.unpack_from(f"!{nmethods}B", message, 2)
        if m in range(3))


# Minimum request length with domain name of 1 character.
MIN_REQUEST_LENGTH = 4 + 2 + 2
# Maximum request length with the domain name of 255 characters.
MAX_REQUEST_LENGTH = 4 + 256 + 2


def parse_request(buffer: bytes) -> SocksRequest:
    """Parse buffer as a SOCKS5 request."""
    if len(buffer) not in range(MIN_REQUEST_LENGTH, MAX_REQUEST_LENGTH + 1):
        raise IncorrectPacket()

    # First we unpack 4 starting bytes from the request.
    version, cmd, rsv, atyp = struct.unpack_from("!4B", buffer)

    # Now check the correctness of all the values.
    if (version != VERSION
        or cmd not in (1, 2, 3)
        or rsv != 0
        or atyp not in (1, 3, 4)):
        raise IncorrectPacket()

    if atyp in (AddressType.IP4.value, AddressType.IP6):
        # AddressType value is 1 for IPv4 address and 4 for IPv6 one.
        # The length of an IPv6Address is 4 bytes, whereas IPv6 is 16.
        # Therefore we can just multiply `atyp` by 4 to get the length
        # of the address, and the last two bytes are the port number.
        try:
            host = str(ip_address(buffer[4:4 + 4 * atyp]))
            port = struct.unpack_from("!H", buffer, 4 + 4 * atyp)[0]
        except (ValueError, struct.error):
            raise IncorrectPacket()
    else:
        # Get the domain name length.
        length = struct.unpack_from("!B", buffer, 4)[0]
        # Unpack variable length name and port from the buffer.
        try:
            host, port = struct.unpack_from(f"!{length}sH", buffer, 5)
            host = host.decode("ascii")
        except (UnicodeDecodeError, struct.error):
            raise IncorrectPacket()

    return SocksRequest(cmd, atyp, host, port)


class ConnectionProtocol(asyncio.Protocol):
    """Connection protocol class.

    This protocol is used when client sends a CONNECT request to send
        all received data from remote host back to the client.
    """

    def __init__(self, client: asyncio.WriteTransport):
        """Constructor.

        Args:
            client: A transport through which the client will receive
                data.
        """
        self.client = client

    def data_received(self, data: bytes):
        """Write data back to the client."""
        self.client.write(data)


class SocksProtocol(asyncio.Protocol):
    """Proxy protocol class.

    This protocol is used to handle initial authentication and
        connection negotiation, as well as request processing.
    """

    remote: asyncio.Transport

    def __init__(self, auth_method: AuthMethod = AuthMethod.NO_AUTH):
        """Constructor.

        Args:
            auth_method: SOCKS5 authentication method. No auth by
                default.
        """
        self.auth_method = auth_method
        self.logger = logging.getLogger()
        # TODO: Write a proper state machine.
        self.state = 0

    def connection_made(self, transport: asyncio.Transport):
        """Client connection handler."""
        self.transport = transport
        self.peer = self.transport.get_extra_info("peername")
        self._log_connected()

    def connection_lost(self, error: Exception | None):
        """Client disconnect handler."""
        self._log_disconnected()

        if error is not None:
            self.logger.exception(error)

    def data_received(self, data: bytes):
        """Data received callback."""
        self._log_data(data)

        if self.state == 0:
            return self.handle_auth(data)

        if self.state == 1:
            return self.on_request(data)

        if self.state == 2:
            assert self.remote is not None
            self.remote.write(data)

    def on_request(self, buffer: bytes):
        """SOCKS5 request handler.

        If the packet is correct, a corresponding handler is called
            based on the request command, otherwise, an error reply
            is sent to the client and the connection is closed.

        Args:
            buffer: Raw data from the client.
        """
        try:
            request = parse_request(buffer)
        except IncorrectPacket:
            send_error(self.transport, Error.FAILURE)
            return self.transport.close()

        self._log_request(request)
        self.__getattribute__(f"on_{request.cmd.name.lower()}")(request)

    def on_connect(self, request: SocksRequest):
        """CONNECT request handler."""
        task = asyncio.ensure_future(self._connect_to(
            request.dst_addr,
            request.dst_port))

        @task.add_done_callback
        def _(task: asyncio.Task):
            try:
                self.remote = task.result()
            except socket.gaierror:
                send_error(self.transport, Error.HOST_UNREACHABLE)
                self.transport.close()
            except Exception as exc:
                self.logger.exception(
                    f"DEBUG: {task.get_name()} raised {exc}",
                    exc_info=exc)
                send_error(self.transport, Error.FAILURE)
                self.transport.close()
            else:
                sock = self.remote.get_extra_info("socket")
                host, port, *_ = sock.getsockname()
                reply = SocksReply(
                    atyp=1 if sock.family == socket.AF_INET else 4,
                    bnd_addr=host,
                    bnd_port=port)
                self.transport.write(reply.dump())
                self.state = 2

    async def _connect_to(self, host: str, port: int):
        """Connect to remote host.

        Args:
            host: Destination IP address or a domain name.
            port: Destination port.

        Raises:
            ValueError: if host could not be resolved.
        """
        addr = await resolve_addr(host)
        if addr is None:
            raise ValueError("Unknown destination")

        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_connection(
            lambda: ConnectionProtocol(client=self.transport),
            host,
            port)
        return transport

    def on_bind(self, _: SocksRequest):
        raise NotImplementedError

    def on_upd_associate(self, _: SocksRequest):
        raise NotImplementedError

    def handle_auth(self, message: bytes):
        """Handle authentication negotiation.

        Sends method selection message with the chosen methods and
            closes the connection if we can not agree on any of the
            methods.
        """
        try:
            methods = get_methods_from_message(message)
        except IncorrectPacket:
            return self.transport.close()

        if self.auth_method not in methods:
            send_auth_message(self.transport, AuthMethod.INVALID)
            return self.transport.close()

        send_auth_message(self.transport, self.auth_method)
        self._log_authed()
        self.state = 1

    def _log_data(self, data):
        """Log received data. Debug only."""
        self.logger.debug(
            f"Got {len(data)} bytes: "
            f"{data if len(data) < 32 else data[:32] + b'...'}")

    def _log_request(self, request: SocksRequest):
        """Log incoming request."""
        self.logger.info(
            f"{self.peer[0]}:{self.peer[1]} {request.cmd.name} -> "
            f"{request.dst_addr}:{request.dst_port}")

    def _log_authed(self):
        """Log client authentication message."""
        self.logger.info(
            f"Authenticated {self.peer[0]}:{self.peer[1]} "
            f"with {self.auth_method.name}")

    def _log_connected(self):
        """Log client connection message."""
        self.logger.info(f"{self.peer[0]}:{self.peer[1]} connected")

    def _log_disconnected(self):
        """Log client disconnect message."""
        self.logger.info(f"{self.peer[0]}:{self.peer[1]} disconnected")


parser = argparse.ArgumentParser(description="SOCKS5 proxy server")
parser.add_argument("-p", dest="port", type=int, help="Port to listen on.")
 
        
async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s -- %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S")

    args = parser.parse_args()

    loop = asyncio.get_running_loop()
    server = await loop.create_server(
        SocksProtocol,
        "0.0.0.0",
        args.port or PORT)

    logging.info(f"Listening on {args.port or PORT}...")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    finally:
        logging.info("Stopping the server")
