"""Command-line interface for Talk-to-PCAP."""

import sys
from pathlib import Path

import click

from src import __version__
from src.agents import gemini_client, query_executor
from src.config import config
from src.pipeline import PipelineError, parse_pcap_to_parquet
from src.query import duckdb_loader, formatters, sql_executor
from src.utils.logger import get_logger, setup_logger

logger = get_logger(__name__)


@click.group()
@click.version_option(version=__version__)
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose logging")
@click.option("-q", "--quiet", is_flag=True, help="Suppress non-error output")
def cli(verbose: bool, quiet: bool):
    """Talk-to-PCAP: Natural language query interface for 3GPP LTE/5G PCAP files."""
    if verbose:
        setup_logger(level="DEBUG")
    elif quiet:
        setup_logger(level="ERROR")


@cli.command()
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option(
    "--output-dir",
    type=click.Path(),
    help="Output directory for Parquet file (default: data/parquet)",
)
@click.option("--keep-intermediates", is_flag=True, help="Keep JSON intermediate files")
@click.option("--save-pdml", is_flag=True, help="Save PDML intermediate file (memory intensive for large files)")
@click.option("--chunk-size", type=int, default=10000, help="Packets per processing chunk")
@click.option("--tshark-path", type=str, help="Custom path to tshark executable")
@click.option("--tshark-filter", type=str, help="TShark display filter override")
def parse(
    pcap_file: str,
    output_dir: str,
    keep_intermediates: bool,
    save_pdml: bool,
    chunk_size: int,
    tshark_path: str,
    tshark_filter: str,
):
    """Parse PCAP file to Parquet format.

    Example:
        talk-to-pcap parse pcapLog.pcap
        talk-to-pcap parse large_capture.pcap --keep-intermediates --chunk-size 5000
    """
    try:
        # Ensure data directories exist
        config.ensure_data_dirs()

        click.echo(f"Parsing PCAP file: {pcap_file}")

        # Run pipeline
        parquet_path = parse_pcap_to_parquet(
            pcap_path=pcap_file,
            output_dir=output_dir,
            keep_intermediates=keep_intermediates,
            save_pdml=save_pdml,
            tshark_path=tshark_path,
            tshark_filter=tshark_filter,
            chunk_size=chunk_size,
        )

        if not parquet_path:
            click.echo("\\n✓ Pipeline finished. No packets matched the filter, so no output was created.")
            sys.exit(0)

        click.echo(f"\\n✓ Success! Parquet file created: {parquet_path}")
        click.echo(f"\\nNext steps:")
        click.echo(f"  - Query with: talk-to-pcap query {parquet_path} 'your question'")
        click.echo(f"  - Inspect with: talk-to-pcap inspect {parquet_path}")

        sys.exit(0)

    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except PipelineError as e:
        click.echo(f"Pipeline error: {e}", err=True)
        sys.exit(3)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        logger.error(f"Parse command failed", exc_info=True)
        sys.exit(4)


@cli.command()
@click.argument("parquet_file", type=click.Path(exists=True))
@click.argument("query_text", type=str)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json", "csv", "sql"], case_sensitive=False),
    default="table",
    help="Output format",
)
@click.option("--show-sql", is_flag=True, help="Show generated SQL query")
@click.option("--no-llm", is_flag=True, help="Execute as direct SQL (no LLM)")
@click.option("--limit", type=int, default=100, help="Maximum rows to return")
@click.option("--gemini-key", type=str, help="Gemini API key (overrides environment)")
@click.option("--use-ue-correlation", is_flag=True, help="Enable UE correlation across protocol layers")
@click.option(
    "--output-mode",
    type=click.Choice(["full", "answer-only", "debug"], case_sensitive=False),
    default="full",
    help="Output mode: 'full' (default), 'answer-only' (only show extracted answer), 'debug' (show everything)"
)
@click.option("--4g", "mode_4g", is_flag=True, help="Force 4G LTE mode (S1AP, X2AP, RRC)")
@click.option("--5g", "mode_5g", is_flag=True, help="Force 5G NR mode (NGAP, F1AP, NR-RRC)")
def query(
    parquet_file: str,
    query_text: str,
    output_format: str,
    show_sql: bool,
    no_llm: bool,
    limit: int,
    gemini_key: str,
    use_ue_correlation: bool,
    output_mode: str,
    mode_4g: bool,
    mode_5g: bool,
):
    """Query Parquet file using natural language or SQL.

    Examples:
        talk-to-pcap query data.parquet "List all RRC messages"
        talk-to-pcap query data.parquet "How many UEs attached?" --format json
        talk-to-pcap query data.parquet "SELECT * FROM packets LIMIT 10" --no-llm
        talk-to-pcap query 5g-sa.parquet "Trace call flow for UE 77" --5g
        talk-to-pcap query lte.parquet "Show handover for UE 2" --4g
    """
    try:
        # Validate mode flags
        if mode_4g and mode_5g:
            click.echo("Error: Cannot specify both --4g and --5g. Choose one or let the system auto-detect.", err=True)
            sys.exit(1)
        
        # Determine network mode
        network_mode = None  # Auto-detect
        if mode_4g:
            network_mode = "4g"
            click.echo("📡 Network Mode: 4G LTE (S1AP, X2AP, RRC)")
        elif mode_5g:
            network_mode = "5g"
            click.echo("📡 Network Mode: 5G NR (NGAP, F1AP, NR-RRC)")
        
        # Load Parquet into DuckDB
        click.echo(f"Loading Parquet file: {parquet_file}")
        conn = duckdb_loader.load_parquet_to_duckdb(parquet_file)

        # Build UE correlation table if requested
        correlation_table = None
        if use_ue_correlation:
            click.echo("Building UE correlation table...")
            from src.analysis.ue_correlation import build_correlation_table
            import pyarrow.parquet as pq
            
            # Load all packets for correlation
            table = pq.read_table(parquet_file)
            df = table.to_pandas()
            packets = df[['packet_number', 'protocol_fields_json']].to_dict('records')
            correlation_table = build_correlation_table(packets)
            
            stats = correlation_table.get_stats()
            click.echo(f"✓ Found {stats['total_groups']} UE groups with {stats['total_identifiers']} unique IDs")

        # Execute query
        if no_llm:
            # If user supplied a natural language measurement style query, translate it
            lowered = query_text.lower()
            import re as _re
            is_select = lowered.strip().startswith('select')
            measurement_intent = (('rsrp' in lowered or 'rsrq' in lowered) and 'ue' in lowered)
            if measurement_intent and not is_select:
                ue_match = _re.search(r"ue\s*(?:id)?\s*(\d+)", lowered)
                if ue_match:
                    target_ue = ue_match.group(1)
                    from src.query.query_helpers import resolve_rlc_ids_for_logical_ue
                    rlc_ids = resolve_rlc_ids_for_logical_ue(target_ue, correlation_table, conn) if use_ue_correlation else {target_ue}
                    if rlc_ids:
                        clauses = []
                        for rid in sorted(rlc_ids):
                            clauses.append(f"protocol_fields_json LIKE '%\"rlc_lte.rlc-lte.ueid\": \"{rid}\",%'")
                            # Double closing brace for literal match inside f-string
                            clauses.append(f"protocol_fields_json LIKE '%\"rlc_lte.rlc-lte.ueid\": \"{rid}\"}}%'")
                        or_clause = " OR ".join(clauses)
                        query_text = (
                            "SELECT packet_number, timestamp_iso, protocol_fields_json FROM packets WHERE "
                            "protocol_fields_json LIKE '%rsrpResult%' AND protocol_fields_json LIKE '%rsrqResult%' AND (" + or_clause + ") ORDER BY packet_number"
                        )
                        click.echo(f"\nTranslated NL measurement query to deterministic SQL for UE {target_ue}")
                    else:
                        click.echo(f"\nCould not resolve UE '{target_ue}' to any RLC IDs; proceeding without translation")

            # Direct (translated or original) SQL execution
            query_request, result = query_executor.execute_direct_sql(
                conn=conn,
                sql=query_text,
                dataset_path=parquet_file,
                limit=limit,
                correlation_table=correlation_table
            )
        else:
            # Natural language query with Gemini
            config.validate_gemini_key()

            click.echo("Initializing Gemini API...")
            model = gemini_client.initialize_gemini(api_key=gemini_key)

            click.echo(f"Processing query: {query_text}")
            query_request, result = query_executor.execute_natural_language_query(
                model=model,
                conn=conn,
                query_text=query_text,
                dataset_path=parquet_file,
                limit=limit,
                correlation_table=correlation_table,
                network_mode=network_mode
            )

        # Show generated SQL if requested
        if show_sql and query_request.generated_sql:
            click.echo("\\n" + "=" * 80)
            click.echo("Generated SQL:")
            click.echo(query_request.generated_sql)
            click.echo("=" * 80 + "\\n")

        # Try to extract specific field value if it's a "what is" type query
        # NOTE: query_executor already does extraction for LLM queries, so skip for those
        specific_answer = None
        if result.data and no_llm and ('what is' in query_text.lower() or 'show me the' in query_text.lower()):
            from src.query.query_helpers import extract_specific_field_value
            specific_answer = extract_specific_field_value(result.data, query_text)
        
        # Handle different output modes
        if output_mode == "answer-only":
            # ANSWER-ONLY MODE: Only show extracted answer
            if specific_answer:
                field_name, field_value = specific_answer
                click.echo(f"✓ {field_name} = {field_value}")
            else:
                click.echo("No specific answer could be extracted. Try --output-mode full to see all results.")
        
        elif output_mode == "debug":
            # DEBUG MODE: Show everything including answer and full results
            if specific_answer:
                field_name, field_value = specific_answer
                click.echo("\n" + "=" * 80)
                click.echo("EXTRACTED ANSWER:")
                click.echo("=" * 80)
                click.echo(f"✓ {field_name} = {field_value}")
                click.echo("=" * 80 + "\n")
            
            click.echo("FULL QUERY RESULTS:")
            click.echo("=" * 80)
            # Format output
            if output_format == "table":
                output = formatters.format_as_table(result)
            elif output_format == "json":
                output = formatters.format_as_json(result)
            elif output_format == "csv":
                output = formatters.format_as_csv(result)
            elif output_format == "sql":
                output = formatters.format_as_sql(query_request)
            else:
                output = str(result.data)
            click.echo(output)
            click.echo("=" * 80)
        
        else:
            # FULL MODE (default): Show answer prominently, then abbreviated results
            if specific_answer:
                field_name, field_value = specific_answer
                click.echo("\n" + "=" * 80)
                click.echo(f"✓ ANSWER: {field_name} = {field_value}")
                click.echo("=" * 80 + "\n")
            
            # Show first few lines of results for context
            if output_format == "table":
                # Debug logging
                import logging
                logger = logging.getLogger(__name__)
                logger.info(f"CLI - About to format table: result.data length={len(result.data) if result.data else 0}")
                logger.info(f"CLI - First item: {result.data[0] if result.data else 'no data'}")
                output = formatters.format_as_table(result)
            elif output_format == "json":
                output = formatters.format_as_json(result)
            elif output_format == "csv":
                output = formatters.format_as_csv(result)
            elif output_format == "sql":
                output = formatters.format_as_sql(query_request)
            else:
                output = str(result.data)
            
            # Show abbreviated output in full mode
            lines = output.split('\n')
            if len(lines) > 20:
                click.echo('\n'.join(lines[:10]))
                click.echo(f"\n... ({len(lines) - 20} more lines) ...\n")
                click.echo('\n'.join(lines[-10:]))
                click.echo("\n(Use --output-mode debug to see full results)")
            else:
                click.echo(output)

        # Show execution time
        if query_request.execution_time_ms:
            click.echo(f"\\n✓ Query completed in {query_request.execution_time_ms}ms")

        conn.close()
        sys.exit(0)

    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except ValueError as e:
        click.echo(f"API key error: {e}", err=True)
        sys.exit(2)
    except Exception as e:
        click.echo(f"Query error: {e}", err=True)
        logger.error(f"Query command failed", exc_info=True)
        sys.exit(4)


@cli.command()
@click.argument("parquet_file", type=click.Path(exists=True))
@click.option("--head", type=int, default=10, help="Show first N rows")
@click.option("--schema", is_flag=True, help="Show Parquet schema")
@click.option("--stats", is_flag=True, help="Show file statistics")
def inspect(parquet_file: str, head: int, schema: bool, stats: bool):
    """Inspect Parquet file contents.

    Examples:
        talk-to-pcap inspect data.parquet --schema
        talk-to-pcap inspect data.parquet --stats
        talk-to-pcap inspect data.parquet --head 20
    """
    try:
        from src.transformers import json_to_parquet

        # Show schema
        if schema:
            click.echo("Parquet Schema:")
            click.echo("=" * 80)
            schema_obj = json_to_parquet.get_parquet_schema(parquet_file)
            click.echo(schema_obj.to_string())
            click.echo()

        # Show stats
        if stats:
            click.echo("Parquet Statistics:")
            click.echo("=" * 80)
            stats_dict = json_to_parquet.get_parquet_stats(parquet_file)
            for key, value in stats_dict.items():
                if key != "schema":
                    click.echo(f"{key}: {value}")
            click.echo()

        # Show sample data
        if head > 0:
            click.echo(f"Sample Data (first {head} rows):")
            click.echo("=" * 80)

            conn = duckdb_loader.load_parquet_to_duckdb(parquet_file)
            result = sql_executor.execute_sql(
                conn,
                f"SELECT packet_number, timestamp_iso, protocol, message_type FROM packets LIMIT {head}",
                limit=head,
            )

            output = formatters.format_as_table(result)
            click.echo(output)

            conn.close()

        sys.exit(0)

    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Inspect error: {e}", err=True)
        logger.error(f"Inspect command failed", exc_info=True)
        sys.exit(4)


@cli.command()
def examples():
    """Show example queries."""
    click.echo("Example Queries:\\n")

    sample_queries = sql_executor.get_sample_queries()
    for i, query in enumerate(sample_queries, 1):
        click.echo(f"{i}. {query['description']}")
        click.echo(f"   SQL: {query['sql']}")
        click.echo()


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
