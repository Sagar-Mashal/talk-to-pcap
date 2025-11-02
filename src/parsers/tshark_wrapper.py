"""Wrapper for tshark command-line tool."""

import subprocess
from pathlib import Path
from typing import Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


class TsharkNotFoundError(Exception):
    """Raised when tshark is not found in PATH."""

    pass


class PcapCorruptedError(Exception):
    """Raised when PCAP file is corrupted or invalid."""

    pass


def run_tshark(
    pcap_path: str,
    display_filter: str,
    tshark_path: Optional[str] = None,
) -> subprocess.Popen:
    """
    Run tshark to convert PCAP to a stream of PDML XML.

    Args:
        pcap_path: Path to input PCAP file.
        display_filter: TShark display filter to apply.
        tshark_path: Optional custom path to tshark executable.

    Returns:
        A Popen object for the running tshark process.

    Raises:
        TsharkNotFoundError: If tshark not found.
        PcapCorruptedError: If PCAP file is invalid.
        FileNotFoundError: If pcap_path is not found.
    """
    pcap_file = Path(pcap_path)
    if not pcap_file.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    tshark_cmd = tshark_path or "tshark"
    command = [
        tshark_cmd,
        "-r",
        str(pcap_file),
        "-T",
        "pdml",
    ]
    if display_filter:
        command.extend(["-Y", display_filter])

    logger.info(f"Running tshark: {' '.join(command)}")

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        return process

    except FileNotFoundError:
        raise TsharkNotFoundError(
            f"tshark command not found: {tshark_cmd}. "
            "Install Wireshark from https://www.wireshark.org/"
        )
    except Exception as e:
        logger.error(f"Failed to start tshark process: {e}")
        raise



def verify_tshark_installation(tshark_path: Optional[str] = None) -> bool:
    """
    Verify tshark is installed and accessible.

    Args:
        tshark_path: Optional custom path to tshark executable

    Returns:
        True if tshark is available

    Raises:
        TsharkNotFoundError: If tshark not found
    """
    tshark_cmd = tshark_path or "tshark"

    try:
        result = subprocess.run(
            [tshark_cmd, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode == 0:
            version_line = result.stdout.split("\\n")[0]
            logger.info(f"tshark found: {version_line}")
            return True
        else:
            raise TsharkNotFoundError(f"tshark returned error: {result.stderr}")

    except FileNotFoundError:
        raise TsharkNotFoundError(
            f"tshark not found: {tshark_cmd}. "
            "Install Wireshark from https://www.wireshark.org/"
        )
    except subprocess.TimeoutExpired:
        raise TsharkNotFoundError("tshark version check timed out")
