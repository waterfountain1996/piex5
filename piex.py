#!/usr/bin/env python3

import asyncio
import enum
from ipaddress import IPv4Address, IPv6Address, ip_address
import logging
import struct


VERSION = 5
NO_METHOD = b"\x05\xFF"


class AddressType(enum.Enum):
    """SOCKS5 address type."""
    IP4 = 1
    DOMAIN = 3
    IP6 = 4


class AuthMethod(enum.Enum):
    """SOCKS5 connection method."""
    NO_AUTH = 0
    GSSAPI = 1
    PASSWORD = 2


class Command(enum.Enum):
    """SOCKS5 request command."""
    CONNECT = 1
    BIND = 2
    UPD_ASSOCIATE = 3


class Reply(enum.Enum):
    """SOCKS5 reply status code."""
    SUCCEEDED = 0
    FAILURE = 1
    NOT_ALLOWED = 2
    NETWORK_UNREACHABLE = 3
    HOST_UNREACHABLE =  4
    REFUSED = 5
    TTL_EXPIRED = 6
    NOT_SUPPORTED = 7
    ADDRESS_NOT_SUPPORTED = 8
    UNASSIGNED = 9


def get_address(address: int | str) -> IPv4Address | IPv6Address | str:
    """Get address as a corresponding type.

    Args:
        address: `str` for domain name address, int for IPv4/6 type
            addresses.
    """
    return address if isinstance(address, str) else ip_address(address)


method_message = lambda method: struct.pack("!2B", VERSION, method.value)


class BaseSocksMessage:
    """Base class for SOCKS5 requests/messages"""

    version = VERSION


class SocksRequest(BaseSocksMessage):
    """SOCKS5 request class."""
    
    def __init__(self, cmd: int, atyp: int,
                 dst_addr: str | int, dst_port: int):
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
        self.dst_addr = get_address(dst_addr)
        self.dst_port = dst_port


class SocksReply(BaseSocksMessage):
    """SOCKS5 reply class."""

    def __init__(self, reply: int, atyp: int,
                 bnd_addr: str | int, bnd_port: int):
        """Constructor.
        
        Args:
            reply: Reply status code.
            atyp: SOCKS address type.
            bnd_addr: Server bound address.
            bnd_port: Server bound port.
        """
        self.reply = Reply(reply)
        self.atyp = AddressType(atyp)
        self.bnd_addr = get_address(bnd_addr)
        self.bnd_port = bnd_port


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


class SocksProtocol(asyncio.Protocol):
    """Proxy protocol class.

    This protocol is used to handle initial authentication and
        connection negotiation, as well as request processing.
    """

    def __init__(self, auth_method: AuthMethod = AuthMethod.NO_AUTH):
        self.auth_method = auth_method
        # TODO: Write a proper state machine.
        self.state = 0

    def connection_made(self, transport: asyncio.Transport):
        self.transport = transport
        self.peer = transport.get_extra_info("peername") # Client address.
        self.logger = logging.getLogger()
        self._log_connected()

    def connection_lost(self, error: Exception | None):
        self._log_disconnected()

        if error is not None:
            self.logger.exception(error)

    def data_received(self, data: bytes):
        self._log_data(data)

        if self.state == 0:
            self.handle_auth(data)

    def handle_auth(self, message: bytes):
        try:
            methods = get_methods_from_message(message)
        except IncorrectPacket:
            # Close the connection if packet was corrupted.
            return self.transport.close()

        if self.auth_method not in methods:
            self.logger.info(
                f"Auth negotiation failed for {self.peer[0]}:{self.peer[1]}. "
                "Closing connection.")
            self.transport.write(NO_METHOD)
            return self.transport.close()

        self.logger.info(
            f"Authenticated {self.peer[0]}:{self.peer[1]} "
            f"with {self.auth_method.name}")
        self.transport.write(method_message(self.auth_method))
        self.state = 1

    def _log_data(self, data):
        """Log received data. Debug only."""
        self.logger.debug(
            f"Got {len(data)} bytes: "
            f"{data if len(data) < 32 else data[:32] + b'...'}")

    def _log_connected(self):
        """Log client connection message."""
        self.logger.info(f"{self.peer[0]}:{self.peer[1]} connected")

    def _log_disconnected(self):
        """Log client disconnect message."""
        self.logger.info(f"{self.peer[0]}:{self.peer[1]} disconnected")
 
        
async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s -- %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S")

    loop = asyncio.get_running_loop()
    server = await loop.create_server(SocksProtocol, "0.0.0.0", 1080)

    logging.info("Starting the server...")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    finally:
        logging.getLogger().info("Stopping the server")
