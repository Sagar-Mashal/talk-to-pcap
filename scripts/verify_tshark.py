"""Verify tshark installation and version."""

import subprocess
import sys
from typing import Tuple


def check_tshark() -> Tuple[bool, str]:
    """
    Check if tshark is installed and meets version requirements.

    Returns:
        Tuple of (is_valid, message)
    """
    try:
        # Run tshark --version
        result = subprocess.run(
            ["tshark", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            return False, f"tshark command failed: {result.stderr}"

        # Parse version from output (e.g., "TShark (Wireshark) 4.0.6")
        version_line = result.stdout.split("\\n")[0]
        if "TShark" not in version_line:
            return False, f"Unexpected tshark output: {version_line}"

        # Extract version number
        version_str = version_line.split()[-1]
        major_version = int(version_str.split(".")[0])

        if major_version < 4:
            return (
                False,
                f"tshark version {version_str} is too old. Version 4.0+ required for 3GPP support.",
            )

        return True, f"tshark version {version_str} OK"

    except FileNotFoundError:
        return False, "tshark not found in PATH. Install Wireshark from https://www.wireshark.org/"
    except subprocess.TimeoutExpired:
        return False, "tshark command timed out"
    except Exception as e:
        return False, f"Error checking tshark: {e}"


def main() -> int:
    """Main entry point."""
    print("Checking tshark installation...")
    is_valid, message = check_tshark()

    if is_valid:
        print(f"✓ {message}")
        return 0
    else:
        print(f"✗ {message}")
        print("\\nInstallation instructions:")
        print("  Linux:   sudo apt install tshark (or yum/dnf)")
        print("  macOS:   brew install wireshark")
        print("  Windows: Download from https://www.wireshark.org/download.html")
        return 1


if __name__ == "__main__":
    sys.exit(main())
