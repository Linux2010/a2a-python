"""Tests for a2a.utils.url_validator."""

import ipaddress

import pytest

from a2a.utils.url_validator import (
    BlockPrivateNetworks,
    InvalidUrlError,
    RequireScheme,
    ResolvedUrl,
    UrlValidationRule,
    UrlValidator,
)


class RecordingRule(UrlValidationRule):
    """Records the resolved URL passed to the rule."""

    def __init__(self) -> None:
        self.seen: list[ResolvedUrl] = []

    async def check(self, url: ResolvedUrl) -> None:
        self.seen.append(url)


@pytest.mark.asyncio
async def test_validate_resolves_and_returns_pinned_addresses() -> None:
    """UrlValidator returns parsed URL details and resolved addresses."""

    def resolver(host: str, port: int | None) -> list[str]:
        assert host == 'example.com'
        assert port == 443
        return ['93.184.216.34', '93.184.216.34']

    rule = RecordingRule()
    validator = UrlValidator(
        [RequireScheme(['https']), rule],
        resolver=resolver,
    )

    result = await validator.validate('https://example.com:443/agent')

    assert result.raw == 'https://example.com:443/agent'
    assert result.parsed.scheme == 'https'
    assert result.parsed.hostname == 'example.com'
    assert result.addresses == (ipaddress.ip_address('93.184.216.34'),)
    assert rule.seen == [result]


@pytest.mark.asyncio
async def test_require_scheme_rejects_disallowed_scheme() -> None:
    """RequireScheme rejects URLs whose scheme is not allowed."""
    validator = UrlValidator(
        [RequireScheme(['https'])],
        resolve=False,
    )

    with pytest.raises(InvalidUrlError, match='not allowed'):
        await validator.validate('http://example.com')


def test_require_scheme_rejects_empty_allowed_schemes() -> None:
    """RequireScheme needs at least one allowed scheme."""
    with pytest.raises(ValueError, match='must not be empty'):
        RequireScheme([])


@pytest.mark.asyncio
async def test_validate_rejects_url_without_host_when_resolving() -> None:
    """URL resolution requires a host."""
    validator = UrlValidator([RequireScheme(['https'])])

    with pytest.raises(InvalidUrlError, match='does not include a host'):
        await validator.validate('https:///missing-host')


@pytest.mark.asyncio
async def test_validate_rejects_invalid_url() -> None:
    """Malformed URLs are reported as InvalidUrlError."""
    validator = UrlValidator(resolve=False)

    with pytest.raises(InvalidUrlError, match='Invalid URL'):
        await validator.validate('http://example.com:not-a-port')


@pytest.mark.asyncio
async def test_block_private_networks_rejects_loopback_address() -> None:
    """BlockPrivateNetworks rejects non-public resolved addresses."""
    validator = UrlValidator([BlockPrivateNetworks()])

    with pytest.raises(InvalidUrlError, match='non-public address 127.0.0.1'):
        await validator.validate('http://127.0.0.1/callback')


@pytest.mark.asyncio
async def test_block_private_networks_allows_configured_host() -> None:
    """BlockPrivateNetworks allows explicitly configured hosts."""

    def resolver(host: str, port: int | None) -> list[str]:
        return ['127.0.0.1']

    validator = UrlValidator(
        [BlockPrivateNetworks(allow_hosts=['internal.example.test'])],
        resolver=resolver,
    )

    result = await validator.validate('http://internal.example.test/callback')

    assert result.addresses == (ipaddress.ip_address('127.0.0.1'),)


@pytest.mark.asyncio
async def test_block_private_networks_allows_configured_cidr() -> None:
    """BlockPrivateNetworks allows addresses in configured CIDRs."""
    validator = UrlValidator([BlockPrivateNetworks(allow_cidrs=['10.0.0.0/8'])])

    result = await validator.validate('http://10.1.2.3/callback')

    assert result.addresses == (ipaddress.ip_address('10.1.2.3'),)


@pytest.mark.asyncio
async def test_block_private_networks_rejects_mixed_disallowed_address() -> (
    None
):
    """All resolved addresses must be public or explicitly allowed."""

    def resolver(host: str, port: int | None) -> list[str]:
        return ['93.184.216.34', '10.1.2.3']

    validator = UrlValidator([BlockPrivateNetworks()], resolver=resolver)

    with pytest.raises(InvalidUrlError, match='10.1.2.3'):
        await validator.validate('http://example.com/callback')


@pytest.mark.asyncio
async def test_validate_reports_resolution_failures() -> None:
    """Resolver failures are reported as InvalidUrlError."""

    def resolver(host: str, port: int | None) -> list[str]:
        raise OSError('name lookup failed')

    validator = UrlValidator(resolver=resolver)

    with pytest.raises(InvalidUrlError, match='Could not resolve URL host'):
        await validator.validate('http://example.com/callback')


@pytest.mark.asyncio
async def test_validate_rejects_empty_resolution_result() -> None:
    """Resolvers must return at least one address."""

    def resolver(host: str, port: int | None) -> list[str]:
        return []

    validator = UrlValidator(resolver=resolver)

    with pytest.raises(InvalidUrlError, match='did not resolve'):
        await validator.validate('http://example.com/callback')


@pytest.mark.asyncio
async def test_validate_without_resolution_runs_rules_with_empty_addresses() -> (
    None
):
    """UrlValidator can skip DNS resolution for parse-only validation."""
    rule = RecordingRule()
    validator = UrlValidator([rule], resolve=False)

    result = await validator.validate('custom://agent/path')

    assert result.parsed.scheme == 'custom'
    assert result.addresses == ()
    assert rule.seen == [result]
