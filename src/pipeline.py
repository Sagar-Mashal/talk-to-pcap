"""Main parsing pipeline orchestrator."""

import time
from pathlib import Path
from typing import Optional

from src.config import config
from src.parsers import tshark_wrapper
from src.transformers import json_to_parquet, xml_to_json
from src.utils.logger import get_logger

logger = get_logger(__name__)


class PipelineError(Exception):
    """Base exception for pipeline errors."""

    pass


def parse_pcap_to_parquet(
    pcap_path: str,
    output_dir: Optional[str] = None,
    keep_intermediates: bool = False,
    save_pdml: bool = False,
    tshark_path: Optional[str] = None,
    tshark_filter: Optional[str] = None,
    chunk_size: int = 10000,
) -> str:
    """
    Parse PCAP file through full pipeline: PCAP → PDML Stream → JSON → Parquet.

    Args:
        pcap_path: Path to input PCAP file.
        output_dir: Output directory (defaults to config.PARQUET_DIR).
        keep_intermediates: Keep JSON file after conversion.
        save_pdml: Save PDML intermediate file (memory intensive for large files).
        tshark_path: Optional custom path to tshark executable.
        tshark_filter: TShark display filter to apply.
        chunk_size: Number of packets to process per chunk.

    Returns:
        Path to generated Parquet file.

    Raises:
        FileNotFoundError: If PCAP file doesn't exist.
        PipelineError: If any pipeline stage fails.
    """
    # Validate input
    pcap_file = Path(pcap_path)
    if not pcap_file.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    # Setup output paths
    output_base_dir = Path(output_dir) if output_dir else config.PARQUET_DIR
    pcap_basename = pcap_file.stem

    pdml_path = config.PDML_DIR / f"{pcap_basename}.pdml"
    json_path = config.JSON_DIR / f"{pcap_basename}.jsonl"
    parquet_path = output_base_dir / f"{pcap_basename}.parquet"

    # Ensure parent directories exist
    if save_pdml:
        pdml_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    parquet_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info(f"=" * 80)
    logger.info(f"Starting pipeline for: {pcap_file.name}")
    logger.info(f"Input PCAP: {pcap_file.absolute()}")
    if save_pdml:
        logger.info(f"Output PDML: {pdml_path.absolute()}")
    logger.info(f"Output JSON: {json_path.absolute()}")
    logger.info(f"Output Parquet: {parquet_path.absolute()}")
    logger.info(f"Keep intermediates: {keep_intermediates}")
    logger.info(f"Save PDML: {save_pdml}")
    logger.info(f"TShark filter: {tshark_filter or config.TSHARK_DISPLAY_FILTER}")
    logger.info(f"=" * 80)

    total_start = time.time()
    tshark_process = None

    try:
        # Stage 1 & 2: PCAP → PDML Stream → JSON
        logger.info("Stage 1/3: Streaming PCAP to PDML...")
        stage_start = time.time()

        display_filter = tshark_filter or config.TSHARK_DISPLAY_FILTER
        tshark_process = tshark_wrapper.run_tshark(
            str(pcap_file),
            display_filter=display_filter,
            tshark_path=tshark_path,
        )

        # If saving PDML, buffer the entire output first
        if save_pdml:
            logger.info("Saving PDML to file (may take extra time for large files)...")
            pdml_content = tshark_process.stdout.read()
            tshark_process.wait()
            
            # Save PDML file
            with open(pdml_path, 'w', encoding='utf-8') as f:
                f.write(pdml_content)
            
            pdml_size_mb = pdml_path.stat().st_size / (1024 * 1024)
            logger.info(f"✓ PDML saved: {pdml_path.absolute()} ({pdml_size_mb:.2f} MB)")
            
            # Now convert from saved PDML to JSON
            logger.info("Stage 2/3: Converting PDML to JSON...")
            from io import StringIO
            pdml_stream = StringIO(pdml_content)
            packet_count = xml_to_json.pdml_to_json(
                pdml_stream,
                str(json_path),
                chunk_size=chunk_size,
            )
        else:
            logger.info("Stage 2/3: Converting PDML stream to JSON...")
            # The stream from tshark is passed directly to the JSON converter
            packet_count = xml_to_json.pdml_to_json(
                tshark_process.stdout,
                str(json_path),
                chunk_size=chunk_size,
            )

        # Check for tshark errors after processing the stream
        stdout, stderr = tshark_process.communicate()
        if tshark_process.returncode != 0:
            error_msg = stderr.strip()
            # Special case: "cut short" is often a non-fatal warning with valid partial output
            if "cut short" in error_msg and packet_count > 0:
                logger.warning(f"tshark reported a potentially incomplete file but packets were extracted: {error_msg}")
            else:
                logger.error(f"tshark failed with exit code {tshark_process.returncode}: {error_msg}")
                if "command not found" in error_msg.lower() or "not recognized" in error_msg.lower():
                    raise tshark_wrapper.TsharkNotFoundError("tshark not found in PATH.")
                elif "invalid" in error_msg.lower() or "corrupt" in error_msg.lower():
                    raise tshark_wrapper.PcapCorruptedError(f"PCAP file appears to be corrupted: {error_msg}")
                else:
                    raise PipelineError(f"tshark execution failed: {error_msg}")

        stage_duration = time.time() - stage_start
        logger.info(f"✓ Stages 1 & 2 completed in {stage_duration:.2f}s")

        if packet_count == 0:
            logger.warning("No packets matched the filter. Pipeline finished early.")
            return ""

        # Stage 3: JSON → Parquet
        logger.info("Stage 3/3: Converting JSON to Parquet...")
        stage_start = time.time()

        json_to_parquet.json_to_parquet(
            str(json_path),
            str(parquet_path),
            chunk_size=chunk_size,
        )

        stage_duration = time.time() - stage_start
        logger.info(f"✓ Stage 3 completed in {stage_duration:.2f}s")

        # Report summary
        total_duration = time.time() - total_start
        parquet_size_mb = parquet_path.stat().st_size / (1024 * 1024)

        logger.info(f"=" * 80)
        logger.info(f"✓ Pipeline completed in {total_duration:.2f}s")
        logger.info(f"✓ Output Parquet: {parquet_path.absolute()}")
        logger.info(f"✓ Parquet Size: {parquet_size_mb:.2f} MB")
        if keep_intermediates and json_path.exists():
            json_size_mb = json_path.stat().st_size / (1024 * 1024)
            logger.info(f"✓ Intermediate JSON: {json_path.absolute()} ({json_size_mb:.2f} MB)")
        logger.info(f"=" * 80)

        # Cleanup intermediate JSON file if not keeping
        if not keep_intermediates and json_path.exists():
            try:
                json_path.unlink()
                logger.debug(f"Deleted intermediate file: {json_path.name}")
            except OSError as e:
                logger.warning(f"Could not delete intermediate file {json_path.name}: {e}")

        return str(parquet_path)

    except tshark_wrapper.TsharkNotFoundError as e:
        logger.error(f"tshark not found: {e}")
        raise PipelineError(f"tshark not found: {e}") from e

    except tshark_wrapper.PcapCorruptedError as e:
        logger.error(f"PCAP file corrupted: {e}")
        raise PipelineError(f"PCAP file corrupted: {e}") from e

    except MemoryError as e:
        logger.error(f"Out of memory: {e}")
        logger.error(
            "Try reducing chunk_size or processing a smaller PCAP file. "
            "Large files may require 16GB+ RAM."
        )
        raise PipelineError(f"Out of memory: {e}") from e

    except Exception as e:
        logger.error(f"Pipeline error: {e}", exc_info=True)
        raise PipelineError(f"Pipeline failed: {e}") from e

    finally:
        # Ensure tshark process is terminated
        if tshark_process and tshark_process.poll() is None:
            tshark_process.terminate()
            logger.warning("Terminated hanging tshark process.")
