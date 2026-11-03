"""Network scanner for live TLS endpoints.

Establishes TLS connections with SNI to retrieve server certificates,
and supports bulk target loading from inventory files or lists.
"""

from __future__ import annotations

import socket
import ssl
from pathlib import Path

from lh_ssl_tracker.certificate import parse_der_certificate
from lh_ssl_tracker.models import (
    ParsedCertificate,
)


def parse_target(target: str) -> tuple[str, int]:
    """Parse a target string into hostname and port number.

    Args:
        target: Target address (e.g., 'example.com', 'example.com:8443', '192.168.1.1:443').

    Returns:
        Tuple of (hostname, port).
    """
    clean = target.strip()
    if clean.startswith("https://"):
        clean = clean[8:]
    elif clean.startswith("http://"):
        clean = clean[7:]

    # Remove any trailing path
    clean = clean.split("/")[0]

    # Handle IPv6 [::1]:443
    if clean.startswith("[") and "]" in clean:
        parts = clean.split("]")
        host = parts[0][1:]
        port_part = parts[1].lstrip(":")
        port = int(port_part) if port_part else 443
        return host, port

    if ":" in clean:
        host, port_str = clean.rsplit(":", 1)
        try:
            return host, int(port_str)
        except ValueError:
            return host, 443

    return clean, 443


def load_targets(target_input: str) -> list[str]:
    """Load target list from a single target, comma-separated targets, or an inventory file path.

    Args:
        target_input: Target address or file path containing target entries.

    Returns:
        List of target strings.
    """
    path = Path(target_input)
    if path.is_file():
        targets: list[str] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
        return targets

    # Check comma-separated targets
    if "," in target_input:
        return [t.strip() for t in target_input.split(",") if t.strip()]

    return [target_input.strip()] if target_input.strip() else []


class EndpointScanner:
    """Performs TLS handshake with remote endpoints to fetch server certificates."""

    def __init__(self, timeout: float = 10.0) -> None:
        """Initialize EndpointScanner with network timeout.

        Args:
            timeout: Socket connection and handshake timeout in seconds.
        """
        self.timeout = timeout

    def fetch_certificate(self, host: str, port: int) -> ParsedCertificate:
        """Connect to host:port via TLS with SNI and retrieve the server certificate.

        Args:
            host: Hostname or IP address.
            port: Port number.

        Returns:
            ParsedCertificate extracted from the peer TLS connection.

        Raises:
            ConnectionError: If connection, DNS, or TLS handshake fails.
        """
        # Create SSLContext with standard settings
        context = ssl.create_default_context()
        # Allow checking expired/untrusted certs without rejecting handshake
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    der_bytes = tls_sock.getpeercert(binary_form=True)
                    if not der_bytes:
                        raise ConnectionError(
                            f"Server at {host}:{port} returned empty certificate payload"
                        )
                    return parse_der_certificate(der_bytes)
        except TimeoutError as exc:
            raise ConnectionError(
                f"Connection to {host}:{port} timed out after {self.timeout}s"
            ) from exc
        except socket.gaierror as exc:
            raise ConnectionError(f"DNS resolution failure for host '{host}': {exc}") from exc
        except Exception as exc:
            raise ConnectionError(f"TLS handshake failed with {host}:{port}: {exc}") from exc

    def scan_endpoint(self, target: str) -> tuple[ParsedCertificate | None, str | None]:
        """Scan a target and return parsed certificate or error message.

        Args:
            target: Endpoint address.

        Returns:
            Tuple of (ParsedCertificate or None, error_message or None).
        """
        try:
            host, port = parse_target(target)
            cert = self.fetch_certificate(host, port)
            return cert, None
        except Exception as exc:
            return None, str(exc)
