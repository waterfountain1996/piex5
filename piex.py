#!/usr/bin/env python3

import asyncio
import enum
from ipaddress import IPv4Address, IPv6Address, ip_address
import struct


class AddressType(enum.Enum):
    """SOCKS5 address type."""
    IP4 = 1
    DOMAIN = 3
    IP6 = 4


class Command(enum.Enum):
    """SOCKS5 request command."""
    CONNECT = 1
    BIND = 2
    UPD_ASSOCIATE = 3


class Method(enum.Enum):
    """SOCKS5 connection method."""
    NO_AUTH = 0
    GSSAPI = 1
    PASSWORD = 2
    IANA = 3
    RESERVED = 4
    PRIVATE = 5
    NO_METHODS = 6


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


def get_method_as_enum(method: int) -> Method:
    """Get method as an enum."""
    match method:
        case 0 | 1 | 2:
            return Method(method)
        case 255:
            return Method.NO_METHODS
        case _:
            if method in range(3, int('7F', 16) + 1):
                return Method.IANA
            elif method in range(int('80', 16), 255):
                return Method.PRIVATE
            else:
                raise ValueError("Unknown method")


def get_methods_from_message(message: bytes) -> list[Method]:
    """Parse method selection message.

    Args:
        message: Raw message.

    Returns:
        List of client-proposed auth methods.
    """
    _, nmethods = struct.unpack_from("!2B", message)
    methods = struct.unpack_from(f"!{nmethods}B", message, 2)
    return list(get_method_as_enum(m) for m in sorted(set(methods)))


class BaseSocksMessage:
    """Base class for SOCKS5 requests/messages"""

    version = 5


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


class SocksProtocol(asyncio.Protocol):
    """SOCKS5 protocol handler."""

    # Server authentication method.
    auth_method = Method.NO_AUTH

    def __init__(self):
        """Constructor.
        
        Sets up state for the client.
        """
        self.ignore = False
        self.negotiating = False

    def connection_made(self, transport: asyncio.Transport):
        """Connection callback.

        Starts auth negotiation mode.
        """
        self.transport = transport
        self.negotiating = True

    def data_received(self, data: bytes):
        """SOCKS5 message handler."""
        if self.ignore:
            # Ignore packets from the client.
            return

        if self.negotiating:
            # Process method selection message.
            methods = get_methods_from_message(data)
            if self.auth_method not in methods:
                # We can not authenticate with any of client's methods,
                # so we end the negotiation and ignore further packets.
                self.transport.write(b"\x05\xff")
                self.negotiating = False
                self.ignore = True
                return

            # Write selection message and stop method negotiation.
            self.transport.write(struct.pack("!2B", 5, self.auth_method.value))
            self.negotiating = False
            return

        return data

        
async def main():
    loop = asyncio.get_running_loop()
    server = await loop.create_server(SocksProtocol, "0.0.0.0", 1080)

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
