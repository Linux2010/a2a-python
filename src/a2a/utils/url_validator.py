# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Composable URL validation utilities."""

import asyncio
import ipaddress
import socket

from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit


IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int | None], Sequence[IPAddress | str]]


class InvalidUrlError(ValueError):
    """Raised when URL validation rejects a URL."""


@dataclass(frozen=True)
class ResolvedUrl:
    """A parsed URL and the resolved addresses used for validation."""

    raw: str
    parsed: SplitResult
    addresses: tuple[IPAddress, ...]


class UrlValidationRule(ABC):
    """A composable URL validation rule."""

    @abstractmethod
    async def check(self, url: ResolvedUrl) -> None:
        """Raise InvalidUrlError to reject the URL."""


class RequireScheme(UrlValidationRule):
    """Require a URL scheme to be one of the configured schemes."""

    def __init__(self, allowed_schemes: Sequence[str]) -> None:
        if not allowed_schemes:
            raise ValueError('allowed_schemes must not be empty.')
        self._allowed_schemes = frozenset(
            scheme.lower() for scheme in allowed_schemes
        )

    async def check(self, url: ResolvedUrl) -> None:
        """Reject URLs whose scheme is not configured as allowed."""
        scheme = url.parsed.scheme.lower()
        if scheme not in self._allowed_schemes:
            allowed = ', '.join(sorted(self._allowed_schemes))
            raise InvalidUrlError(
                f'URL scheme {url.parsed.scheme!r} is not allowed. '
                f'Allowed schemes: {allowed}.'
            )


class BlockPrivateNetworks(UrlValidationRule):
    """Reject URLs resolving to non-public IP addresses.

    Hosts in ``allow_hosts`` and addresses covered by ``allow_cidrs`` are
    exempt from the non-public address check.
    """

    def __init__(
        self,
        *,
        allow_hosts: Sequence[str] = (),
        allow_cidrs: Sequence[str] = (),
    ) -> None:
        self._allow_hosts = frozenset(
            _normalize_host(host) for host in allow_hosts
        )
        self._allow_networks = tuple(
            ipaddress.ip_network(cidr, strict=False) for cidr in allow_cidrs
        )

    async def check(self, url: ResolvedUrl) -> None:
        """Reject URLs that resolve to non-public addresses."""
        host = url.parsed.hostname
        if host is not None and _normalize_host(host) in self._allow_hosts:
            return

        for address in url.addresses:
            if any(address in network for network in self._allow_networks):
                continue
            if not address.is_global:
                raise InvalidUrlError(
                    f'URL host {host!r} resolves to non-public address '
                    f'{address}.'
                )


class UrlValidator:
    """Validate URLs by parsing, resolving, then running rules in order."""

    def __init__(
        self,
        rules: Sequence[UrlValidationRule] = (),
        *,
        resolve: bool = True,
        resolver: Resolver | None = None,
    ) -> None:
        self._rules = tuple(rules)
        self._resolve = resolve
        self._resolver = resolver

    async def validate(self, url: str) -> ResolvedUrl:
        """Validate a URL and return the parsed URL plus resolved addresses."""
        resolved = await self._build(url)
        for rule in self._rules:
            await rule.check(resolved)
        return resolved

    async def _build(self, url: str) -> ResolvedUrl:
        try:
            parsed = urlsplit(url)
            host = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            raise InvalidUrlError(f'Invalid URL {url!r}: {exc}') from exc

        addresses: tuple[IPAddress, ...] = ()
        if self._resolve:
            if host is None:
                raise InvalidUrlError(f'URL {url!r} does not include a host.')
            addresses = await self._resolve_host(host, port)

        return ResolvedUrl(raw=url, parsed=parsed, addresses=addresses)

    async def _resolve_host(
        self, host: str, port: int | None
    ) -> tuple[IPAddress, ...]:
        try:
            return (ipaddress.ip_address(host),)
        except ValueError:
            pass

        try:
            if self._resolver is not None:
                resolved = self._resolver(host, port)
            else:
                loop = asyncio.get_running_loop()
                address_info = await loop.getaddrinfo(
                    host,
                    port,
                    type=socket.SOCK_STREAM,
                )
                resolved = [info[4][0] for info in address_info]
        except OSError as exc:
            raise InvalidUrlError(
                f'Could not resolve URL host {host!r}: {exc}'
            ) from exc

        addresses = tuple(
            dict.fromkeys(ipaddress.ip_address(address) for address in resolved)
        )
        if not addresses:
            raise InvalidUrlError(f'URL host {host!r} did not resolve.')
        return addresses


def _normalize_host(host: str) -> str:
    return host.rstrip('.').lower()
