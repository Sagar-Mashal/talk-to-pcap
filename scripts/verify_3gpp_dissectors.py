"""Verify 3GPP protocol dissectors are available in tshark."""

import subprocess
import sys
from typing import List, Tuple


REQUIRED_DISSECTORS = [
    "rrc",  # LTE/5G Radio Resource Control
    "nas-5gs",  # 5G NAS
    "s1ap",  # LTE S1 Application Protocol
    "x2ap",  # LTE X2 Application Protocol
    "ngap",  # 5G NG Application Protocol
    "gtp",  # GPRS Tunneling Protocol
    "diameter",  # Diameter (LTE core)
]


def check_dissectors() -> Tuple[bool, List[str], List[str]]:
    """
    Check if required 3GPP dissectors are available.

    Returns:
        Tuple of (all_available, available_list, missing_list)
    """
    try:
        # Run tshark -G protocols to list all available dissectors
        result = subprocess.run(
            ["tshark", "-G", "protocols"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            return False, [], REQUIRED_DISSECTORS

        # Parse protocol list
        available = set()
        for line in result.stdout.split("\\n"):
            if "\\t" in line:
                # Format: "Protocol Name\\tShort Name\\tFilter Name"
                parts = line.split("\\t")
                if len(parts) >= 3:
                    filter_name = parts[2].lower()
                    available.add(filter_name)

        # Check which required dissectors are present
        available_dissectors = []
        missing_dissectors = []

        for dissector in REQUIRED_DISSECTORS:
            if dissector.lower() in available:
                available_dissectors.append(dissector)
            else:
                missing_dissectors.append(dissector)

        return len(missing_dissectors) == 0, available_dissectors, missing_dissectors

    except FileNotFoundError:
        return False, [], REQUIRED_DISSECTORS
    except subprocess.TimeoutExpired:
        return False, [], REQUIRED_DISSECTORS
    except Exception:
        return False, [], REQUIRED_DISSECTORS


def main() -> int:
    """Main entry point."""
    print("Checking 3GPP protocol dissectors...")
    all_available, available, missing = check_dissectors()

    if all_available:
        print(f"✓ All {len(REQUIRED_DISSECTORS)} required dissectors available:")
        for dissector in available:
            print(f"  - {dissector}")
        return 0
    else:
        print(f"✗ Missing {len(missing)} dissector(s):")
        for dissector in missing:
            print(f"  - {dissector}")

        if available:
            print(f"\\n✓ Available dissectors ({len(available)}):")
            for dissector in available:
                print(f"  - {dissector}")

        print("\\nNote: Ensure you have Wireshark 4.0+ installed with full dissector set.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
