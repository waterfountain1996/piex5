#!/usr/bin/env python3

import argparse
import asyncio
import enum
from functools import partial
from ipaddress import IPv4Address, ip_address
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


async def resolve_addr(host: str) -> str:
    """Resolve IP address from domain name.

    Args:
        host: Domain name.

    Raises:
        socket.gaierror: If the address can not be resolved.

    Returns:
        IP address string.
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
    write_to(transport, buffer)


def send_auth_message(transport: asyncio.WriteTransport, method: AuthMethod):
    """Send method selection message to the client.

    Args:
        transport: Writeable transport to send message to.
        method: Chosen authentication method.
    """
    buffer = struct.pack("!2B", VERSION, method.value)
    write_to(transport, buffer)


def write_to(transport: asyncio.WriteTransport | asyncio.DatagramTransport,
             buffer: bytes,
             address: tuple[str, int] = None):
    """Write data to transport.

    Args:
        transport: Either a TCP or an UDP transport.
        buffer: Data to write.
        address: Optional address. Used to write data to UDP transport.
    """
    if isinstance(transport, asyncio.DatagramTransport):
        if address is None:
            raise ValueError(
                "Address must not be None "
                "to write to UDP transport")

        _write = partial(transport.sendto, addr=address)
    else:
        _write = transport.write

    _write(data=buffer)


def _get_atyp_from_ip_address(addr: str) -> AddressType:
    """Get address type of an IP address.

    Returns:
        AddressType enum.

    Raises:
        ValueError if `addr` is not a valid IP address.
    """
    ip = ip_address(addr)

    if isinstance(ip, IPv4Address):
        return AddressType.IP4

    return AddressType.IP6



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


class UDPHeader:
    """UDP datagram header class."""

    def __init__(self, frag: int, atyp: int, dst_addr: str, dst_port: int):
        """Constructor.

        Args:
            frag: Fragment number.
            atyp: Address type.
            dst_addr: Desired destination address.
            dst_port: Desired destination port.
        """
        self.frag = frag
        self.atyp = AddressType(atyp)
        self.dst_addr = dst_addr
        self.dst_port = dst_port

    def __len__(self):
        # 2 bytes reserved
        # + 1 byte fragment
        # + 1 byte address type
        # + 2 bytes port number
        length = 2 + 1 + 1 + 2
        if self.atyp == AddressType.IP4:
            return length + 4

        if self.atyp == AddressType.IP6:
            return length + 16

        return length + 1 + len(self.dst_addr)
    
    def dump(self) -> bytes:
        """Dump UDP header as bytes."""
        buffer = struct.pack("!H2B", 0, self.frag, self.atyp.value)

        if self.atyp in (AddressType.IP4, AddressType.IP6):
            return (buffer
                    + ip_address(self.dst_addr).packed
                    + struct.pack("!H", self.dst_port))

        return buffer + struct.pack(
            f"!{len(self.dst_addr)}sH",
            self.dst_addr.encode("ascii"),
            self.dst_port)


class IncorrectPacket(Exception):
    """Incorrect packet exception.

    Used when received packet or request is corrupted and can not be
        parsed.
    """


class IncorrectUDPHeader(IncorrectPacket):
    """Incorrect datagram header exception.

    Used when received datagram contains a corrupt header.
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


def _unpack_address_from_buffer(atyp: AddressType,
                                buffer: bytes) -> tuple[str, int]:
    """Unpack address and port from buffer based on AddressType.

    Args:
        atyp: Address type.
        buffer: Buffer to extract address from.

    Raises:
        IncorrectPacket: If address is invalid.
    """
    if atyp in (AddressType.IP4, AddressType.IP6):
        # AddressType value is 1 for IPv4 address and 4 for IPv6 one.
        # The length of an IPv6Address is 4 bytes, whereas IPv6 is 16.
        # Therefore we can just multiply `atyp` by 4 to get the length
        # of the address, and the last two bytes are the port number.
        try:
            host = str(ip_address(buffer[4 * atyp.value]))
            port = struct.unpack_from("!H", buffer, 4 * atyp.value)[0]
        except (ValueError, struct.error):
            raise IncorrectPacket()
    else:
        # Get the domain name length.
        length = struct.unpack_from("!B", buffer)[0]
        # Unpack variable length name and port from the buffer.
        try:
            host, port = struct.unpack_from(f"!{length}sH", buffer, 1)
            host = host.decode("ascii")
        except (UnicodeDecodeError, struct.error):
            raise IncorrectPacket()

    return host, port


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

    host, port = _unpack_address_from_buffer(AddressType(atyp), buffer[4:])

    return SocksRequest(cmd, atyp, host, port)


def parse_udp_header(buffer: bytes) -> UDPHeader:
    """Parse udp header from buffer."""
    try:
        rsv, frag, atyp = struct.unpack_from("!H2B", buffer)
    except struct.error:
        raise IncorrectUDPHeader()
    else:
        if rsv != 0 or atyp not in (1, 3, 4):
            raise IncorrectUDPHeader()

    try:
        host, port = _unpack_address_from_buffer(AddressType(atyp), buffer[4:])
    except IncorrectPacket:
        raise IncorrectUDPHeader()

    return UDPHeader(frag, atyp, host, port)


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
        write_to(self.client, data)


class UDPRelayProtocol(asyncio.DatagramProtocol):
    """UDP relay protocol class.

    This protocol is used with a datagram endpoint when the client
        makes an UDP ASSOCIATE request. It does (de)encapsulation
        of datagrams and relays them.
    """

    def __init__(self, client_addr: tuple[str, int],
                 remote_addr: tuple[str, int]):
        """Constructor.

        Args:
            client_addr: Client address.
            remote_addr: Address to relay datagrams to.
        """
        self.client_addr = client_addr
        self.remote_addr = remote_addr

    def connection_made(self, transport: asyncio.DatagramTransport):
        """Setup datagram transport."""
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]):
        """Relay data to the other host."""
        if addr == self.client_addr:
            # If datagram is coming from the client.
            try:
                header = parse_udp_header(data)
            except IncorrectUDPHeader:
                # Ignore incorrect datagram.
                return

            if header.frag != 0:
                # According to RFC 1918, servers that do NOT support
                # fragmentation must drop all datagrams whose FRAG
                # field is not 0.
                return

            # Offset the header
            write_to(self.transport, data[len(header):], self.remote_addr)
        elif addr == self.remote_addr:
            # If the datagram is coming from the remote host.
            header = UDPHeader(
                frag=0,
                atyp=_get_atyp_from_ip_address(self.client_addr[0]).value,
                dst_addr=self.client_addr[0],
                dst_port=self.client_addr[1])

            # Encapsulate datagram with the UDP header.
            write_to(self.transport, header.dump() + data, self.client_addr)


class BoundRelayProtocol(ConnectionProtocol):
    
    def __init__(self, relay_to: asyncio.WriteTransport, accept_from: str):
        """Constructor.

        Args:
            relay_to: Writeable transport to send data to the client.
            accept_from: DST_ADDR specified in BIND request.
        """
        self.accept_from = accept_from
        self.relay_to = relay_to

    def connection_made(self, transport: asyncio.Transport):
        self.transport = transport
        host, *_ = self.transport.get_extra_info("peername")

        if host != self.accept_from:
            # TODO: Close connection.
            send_error(self.relay_to, Error.FAILURE)
            return

        bnd_addr, bnd_port, *_ = self.transport.get_extra_info("sockname")
        reply = SocksReply(
            atyp=_get_atyp_from_ip_address(bnd_addr).value,
            bnd_addr=bnd_addr,
            bnd_port=bnd_port)

        write_to(self.relay_to, reply.dump())
    
    def data_received(self, data: bytes):
        write_to(self.relay_to, data)


class SocksProtocol(asyncio.Protocol):
    """Proxy protocol class.

    This protocol is used to handle initial authentication and
        connection negotiation, as well as request processing.
    """

    relay: asyncio.WriteTransport | asyncio.DatagramTransport | None

    def __init__(self, auth_method: AuthMethod, host: str):
        """Constructor.

        Args:
            auth_method: SOCKS5 authentication method.
            host: Host the server is listening on.
        """
        self.auth_method = auth_method
        self.logger = logging.getLogger()
        self.relay = None
        self.ignore = False
        self.host = host
        # TODO: Write a proper state machine.
        self.state = 0

    def connection_made(self, transport: asyncio.Transport):
        """Client connection handler."""
        self.transport = transport
        self.peer = self.transport.get_extra_info("peername")
        self._log_connected()

    def connection_lost(self, error: Exception | None):
        """Client disconnect handler."""
        if self.relay is not None:
            # Close UDP relay when the TCP connection is lost.
            self.relay.close()

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
            assert self.relay is not None
            if not self.ignore:
                write_to(self.relay, data)

    def on_request(self, buffer: bytes):
        """SOCKS5 request handler.

        If the packet is not correct, an error reply is sent to 
            the client and the connection is closed.

        Args:
            buffer: Raw data from the client.
        """
        try:
            request = parse_request(buffer)
        except IncorrectPacket:
            send_error(self.transport, Error.FAILURE)
            return self.close()

        self._log_request(request)

        if request.cmd == Command.CONNECT:
            awaitable = self._connect_to
        elif request.cmd == Command.BIND:
            awaitable = self._open_bound_relay
        else:
            # Ignore packets from client on this socket because
            # they will be using UDP relay.
            self.ignore = True
            awaitable = self._open_udp_relay

        task = asyncio.ensure_future(awaitable(
            request.dst_addr,
            request.dst_port))

        task.add_done_callback(self._relay_established_callback)

    async def _open_bound_relay(self, dst_addr: str, dst_port: int):
        dst_addr = await resolve_addr(dst_addr)
        return await asyncio.get_running_loop().create_server(
            lambda: BoundRelayProtocol(self.transport, dst_addr),
            dst_addr,
            dst_port)

    async def _open_udp_relay(self, dst_addr: str, dst_port: int):
        """Open UDP relay."""
        dst_addr = await resolve_addr(dst_addr)
        return await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: UDPRelayProtocol(self.peer, (dst_addr, dst_port)),
            local_addr=(self.host, 0))

    async def _connect_to(self, host: str, port: int):
        """Connect to remote host.

        Args:
            host: Destination IP address or a domain name.
            port: Destination port.

        Raises:
            ValueError: if host could not be resolved.
        """
        addr = await resolve_addr(host)
        transport, _ = await asyncio.get_running_loop().create_connection(
            lambda: ConnectionProtocol(client=self.transport),
            addr,
            port)
        return transport

    def _relay_established_callback(self, task: asyncio.Task):
        try:
            self.relay = task.result()
        except Exception as exc:
            self.logger.error(f"{task.get_name()} failed", exc_info=exc)
            send_error(self.transport, Error.FAILURE)
            return self.close()

        sock = self.relay.get_extra_info("socket")
        host, port, *_ = sock.getsockname()

        reply = SocksReply(
            atyp=_get_atyp_from_ip_address(host).value,
            bnd_addr=host,
            bnd_port=port)

        write_to(self.transport, reply.dump())
        self.state = 2

    def handle_auth(self, message: bytes):
        """Handle authentication negotiation.

        Sends method selection message with the chosen methods and
            closes the connection if we can not agree on any of the
            methods.
        """
        try:
            methods = get_methods_from_message(message)
        except IncorrectPacket:
            return self.close()

        if self.auth_method not in methods:
            send_auth_message(self.transport, AuthMethod.INVALID)
            return self.close()

        send_auth_message(self.transport, self.auth_method)
        self._log_authed()
        self.state = 1

    def close(self):
        """Close the TCP connection."""
        self.transport.close()

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


class SocksServer:
    """SOCKS5 proxy server."""

    def __init__(self, host: str, port: int, auth_method: AuthMethod):
        """Constructor.

        Args:
            host: IP address to listen on.
            port: Port to listen on.
            auth_method: SOCKS5 authentication method.
        """
        self.host = host
        self.port = port
        self.auth_method = auth_method

        self._loop = asyncio.get_running_loop()
        self._logger = logging.getLogger()

    async def run(self):
        """Start the server.

        Calls `serve_forever` internally.
        """
        self._server = await self._loop.create_server(
            lambda: SocksProtocol(self.auth_method, self.host),
            host=self.host,
            port=self.port)

        self._logger.info(f"Listening on {self.host}:{self.port}")

        async with self._server:
            await self._server.serve_forever()


parser = argparse.ArgumentParser(description="SOCKS5 proxy server")
parser.add_argument("-p", dest="port", type=int, help="Port to listen on.")
 
        
async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s -- %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S")

    args = parser.parse_args()

    server = SocksServer("0.0.0.0", args.port or PORT, AuthMethod.NO_AUTH)
    await server.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
