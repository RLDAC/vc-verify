"""
Command-line interface for VC Verifier.

Usage:
    vc-verify credential.json
    vc-verify --url https://example.com/credentials/123
    cat credential.json | vc-verify -
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click
import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vc_verifier.verifier import VCVerifier, VerificationStatus, VerificationResult
from vc_verifier.statuslist import CredentialStatus


console = Console()


def format_result(result: VerificationResult) -> None:
    """Format and print verification result."""
    # Status emoji and color
    if result.status == VerificationStatus.VALID and result.is_valid:
        status_icon = "[bold green]VALID[/]"
        panel_style = "green"
    elif result.status == VerificationStatus.INVALID:
        status_icon = "[bold red]INVALID[/]"
        panel_style = "red"
    else:
        status_icon = "[bold yellow]ERROR[/]"
        panel_style = "yellow"

    # Build summary table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="dim")
    table.add_column("Value")

    table.add_row("Status", status_icon)

    if result.credential_id:
        table.add_row("Credential ID", result.credential_id)

    if result.issuer:
        table.add_row("Issuer", result.issuer)

    # Proof details
    if result.proof:
        proof_status = "[green]Valid[/]" if result.proof.valid else "[red]Invalid[/]"
        table.add_row("Proof", proof_status)
        table.add_row("Cryptosuite", result.proof.cryptosuite)
        table.add_row("Verification Method", result.proof.verification_method)
        if result.proof.error:
            table.add_row("Proof Error", f"[red]{result.proof.error}[/]")

    # Credential status
    if result.credential_status:
        cs = result.credential_status
        if cs.status == CredentialStatus.VALID:
            status_str = "[green]Valid[/]"
        elif cs.status == CredentialStatus.REVOKED:
            status_str = "[red]Revoked[/]"
        elif cs.status == CredentialStatus.SUSPENDED:
            status_str = "[yellow]Suspended[/]"
        else:
            status_str = "[dim]Unknown[/]"
        table.add_row("Credential Status", status_str)
        table.add_row("Status Purpose", cs.purpose)
        table.add_row("Status Index", str(cs.index))

    console.print(Panel(table, title="Verification Result", border_style=panel_style))

    # Errors
    if result.errors:
        console.print("\n[bold red]Errors:[/]")
        for error in result.errors:
            console.print(f"  [red]x[/] {error}")

    # Warnings
    if result.warnings:
        console.print("\n[bold yellow]Warnings:[/]")
        for warning in result.warnings:
            console.print(f"  [yellow]![/] {warning}")


def load_credential(source: str) -> dict[str, Any]:
    """Load credential from file, URL, or stdin.

    Args:
        source: File path, URL, or "-" for stdin.

    Returns:
        Parsed credential JSON.
    """
    if source == "-":
        # Read from stdin
        content = sys.stdin.read()
        return json.loads(content)

    if source.startswith("http://") or source.startswith("https://"):
        # Fetch from URL
        with httpx.Client(timeout=30.0) as client:
            response = client.get(
                source,
                headers={"Accept": "application/vc+ld+json, application/json"},
            )
            response.raise_for_status()
            return response.json()

    # Read from file
    path = Path(source)
    if not path.exists():
        raise click.ClickException(f"File not found: {source}")

    with path.open() as f:
        return json.load(f)


@click.command()
@click.argument("source", required=True)
@click.option(
    "--no-status",
    is_flag=True,
    help="Skip credential status (revocation) check",
)
@click.option(
    "--no-ssl-verify",
    is_flag=True,
    help="Disable SSL certificate verification",
)
@click.option(
    "--json-output",
    is_flag=True,
    help="Output result as JSON",
)
@click.option(
    "--timeout",
    type=float,
    default=30.0,
    help="HTTP request timeout in seconds",
)
@click.version_option()
def main(
    source: str,
    no_status: bool,
    no_ssl_verify: bool,
    json_output: bool,
    timeout: float,
) -> None:
    """Verify a W3C Verifiable Credential.

    SOURCE can be:
    - A file path (e.g., credential.json)
    - A URL (e.g., https://example.com/credentials/123)
    - "-" to read from stdin

    Examples:

        vc-verify credential.json

        vc-verify https://example.com/credentials/123

        cat credential.json | vc-verify -

        curl -s https://api.example.com/vc/123 | vc-verify -
    """
    try:
        # Load credential
        credential = load_credential(source)

        # Create verifier with options
        from vc_verifier.did_resolver import DIDResolver
        from vc_verifier.statuslist import StatusListChecker

        did_resolver = DIDResolver(timeout=timeout, verify_ssl=not no_ssl_verify)
        statuslist_checker = StatusListChecker(timeout=timeout, verify_ssl=not no_ssl_verify)

        verifier = VCVerifier(
            did_resolver=did_resolver,
            statuslist_checker=statuslist_checker,
            verify_status=not no_status,
        )

        # Verify
        result = verifier.verify(credential)

        # Output
        if json_output:
            output = {
                "status": result.status.value,
                "valid": result.is_valid,
                "credential_id": result.credential_id,
                "issuer": result.issuer,
                "proof": {
                    "valid": result.proof.valid if result.proof else None,
                    "cryptosuite": result.proof.cryptosuite if result.proof else None,
                    "verification_method": result.proof.verification_method if result.proof else None,
                    "error": result.proof.error if result.proof else None,
                } if result.proof else None,
                "credential_status": {
                    "status": result.credential_status.status.value if result.credential_status else None,
                    "purpose": result.credential_status.purpose if result.credential_status else None,
                    "index": result.credential_status.index if result.credential_status else None,
                } if result.credential_status else None,
                "errors": result.errors,
                "warnings": result.warnings,
            }
            console.print_json(data=output)
        else:
            format_result(result)

        # Exit with appropriate code
        sys.exit(0 if result.is_valid else 1)

    except json.JSONDecodeError as e:
        if json_output:
            console.print_json(data={"error": f"Invalid JSON: {e}"})
        else:
            console.print(f"[red]Error:[/] Invalid JSON: {e}")
        sys.exit(2)

    except httpx.HTTPError as e:
        if json_output:
            console.print_json(data={"error": f"HTTP error: {e}"})
        else:
            console.print(f"[red]Error:[/] HTTP error: {e}")
        sys.exit(2)

    except Exception as e:
        if json_output:
            console.print_json(data={"error": str(e)})
        else:
            console.print(f"[red]Error:[/] {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()
