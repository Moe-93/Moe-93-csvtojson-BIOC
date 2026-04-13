#!/usr/bin/env python3
"""
CSV to Cortex XDR BIOC JSON Converter
Converts CSV files to Cortex XDR BIOC format for easy import.

Supports two BIOC types:
  1. XQL-based BIOCs (is_xql=true) - Uses XQL queries
  2. Indicator-based BIOCs (is_xql=false) - Uses investigation filters

Usage:
    python csv_to_bioc.py --file biocs.csv --output biocs.json
    python csv_to_bioc.py --file biocs.csv --output biocs.json --type xql
    python csv_to_bioc.py --file biocs.csv --output biocs.json --type indicator
    python csv_to_bioc.py --file biocs.csv --output biocs.json --auto-detect
    python csv_to_bioc.py --template  # Generate CSV template

CSV Format (XQL-based):
    name,description,severity,status,is_xql,xql_query,comment,mitre_technique_id,mitre_tactic_id,category

CSV Format (Indicator-based):
    name,description,severity,status,is_xql,investigation_type,search_field,search_type,search_value,comment,mitre_technique_id,mitre_tactic_id,category

Example CSV (XQL-based):
    name,description,severity,status,is_xql,xql_query,comment,mitre_technique_id,mitre_tactic_id,category
    Suspicious PowerShell,Detects suspicious PowerShell execution,high,enabled,true,"dataset = xdr_data | filter action_process_image_name contains ""powershell.exe"" | filter action_process_image_command_line contains ""-enc"" | limit 100",Encoded PowerShell execution,T1059.001,TA0002,EXECUTION
    Admin File Execution,Administrator executing files,medium,enabled,true,"dataset = xdr_data | filter action_process_username =~ ""Administrator"" | limit 100",Admin file execution,T1078.001,TA0004,PRIVILEGE_ESCALATION

Example CSV (Indicator-based):
    name,description,severity,status,is_xql,investigation_type,search_field,search_type,search_value,comment,mitre_technique_id,mitre_tactic_id,category
    PowerShell Execution,Detect PowerShell execution,high,enabled,false,PROCESS_EXECUTION_EVENT,action_process_image_name,CONTAINS,powershell.exe,PowerShell detection,T1059.001,TA0002,EXECUTION
    Suspicious Domain,Detect connection to suspicious domain,critical,enabled,false,NETWORK_EVENT,action_remote_ip_domain,CONTAINS,malware.com,Malware domain detection,T1071,TA0011,COMMAND_AND_CONTROL
"""

import csv
import json
import os
import sys
import argparse
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants
SEVERITY_MAP = {
    'informational': 'SEV_010_INFORMATIONAL',
    'low': 'SEV_020_LOW',
    'medium': 'SEV_030_MEDIUM',
    'high': 'SEV_040_HIGH',
    'critical': 'SEV_050_CRITICAL',
    'info': 'SEV_010_INFORMATIONAL',
    'SEV_010_INFORMATIONAL': 'SEV_010_INFORMATIONAL',
    'SEV_020_LOW': 'SEV_020_LOW',
    'SEV_030_MEDIUM': 'SEV_030_MEDIUM',
    'SEV_040_HIGH': 'SEV_040_HIGH',
    'SEV_050_CRITICAL': 'SEV_050_CRITICAL'
}

INVESTIGATION_TYPE_MAPPING = {
    'process': 'PROCESS_EXECUTION_EVENT',
    'process_execution': 'PROCESS_EXECUTION_EVENT',
    'process_execution_event': 'PROCESS_EXECUTION_EVENT',
    'file': 'FILE_EVENT',
    'file_event': 'FILE_EVENT',
    'network': 'NETWORK_EVENT',
    'network_event': 'NETWORK_EVENT',
    'registry': 'REGISTRY_EVENT',
    'registry_event': 'REGISTRY_EVENT',
    'dns': 'DNS_EVENT',
    'dns_event': 'DNS_EVENT',
    'ip': 'IP_ADDRESS_EVENT',
    'ip_address': 'IP_ADDRESS_EVENT',
    'ip_address_event': 'IP_ADDRESS_EVENT',
    'url': 'URL_EVENT',
    'url_event': 'URL_EVENT'
}

SEARCH_TYPE_MAPPING = {
    'eq': 'EQ',
    'equal': 'EQ',
    'equals': 'EQ',
    'contains': 'CONTAINS',
    'contain': 'CONTAINS',
    'regex': 'REGEX',
    'regexp': 'REGEX',
    'starts_with': 'STARTS_WITH',
    'startswith': 'STARTS_WITH',
    'ends_with': 'ENDS_WITH',
    'endswith': 'ENDS_WITH',
    'neq': 'NEQ',
    'not_equal': 'NEQ',
    'notequals': 'NEQ'
}


def normalize_severity(severity: str) -> str:
    """Normalize severity to XDR format."""
    if not severity:
        return 'SEV_030_MEDIUM'
    severity_lower = severity.strip().lower()
    return SEVERITY_MAP.get(severity_lower, 'SEV_030_MEDIUM')


def normalize_investigation_type(inv_type: str) -> str:
    """Normalize investigation type to XDR format."""
    if not inv_type:
        return 'PROCESS_EXECUTION_EVENT'
    inv_type_lower = inv_type.strip().lower().replace(' ', '_')
    return INVESTIGATION_TYPE_MAPPING.get(inv_type_lower, 'PROCESS_EXECUTION_EVENT')


def normalize_search_type(search_type: str) -> str:
    """Normalize search type to XDR format."""
    if not search_type:
        return 'CONTAINS'
    search_type_lower = search_type.strip().lower()
    return SEARCH_TYPE_MAPPING.get(search_type_lower, 'CONTAINS')


def normalize_status(status: str) -> str:
    """Normalize status to ENABLED/DISABLED."""
    if not status:
        return 'ENABLED'
    status_upper = status.strip().upper()
    if status_upper in ['ENABLED', 'ENABLE', 'TRUE', 'YES', 'ACTIVE', 'ON']:
        return 'ENABLED'
    elif status_upper in ['DISABLED', 'DISABLE', 'FALSE', 'NO', 'INACTIVE', 'OFF']:
        return 'DISABLED'
    return 'ENABLED'


def clean_csv_value(value: str) -> str:
    """Clean and normalize CSV field values."""
    if value is None:
        return ''
    return value.strip()


def create_xql_bioc(row: Dict[str, str]) -> Dict[str, Any]:
    """Create an XQL-based BIOC from CSV row."""
    name = clean_csv_value(row.get('name', ''))
    if not name:
        raise ValueError("Missing required field: name")

    description = clean_csv_value(row.get('description', '')) or name
    severity = normalize_severity(row.get('severity', 'medium'))
    status = normalize_status(row.get('status', 'enabled'))
    xql_query = clean_csv_value(row.get('xql_query', row.get('xql', row.get('query', ''))))
    if not xql_query:
        raise ValueError(f"XQL-based BIOC '{name}' missing xql_query field")
    
    comment = clean_csv_value(row.get('comment', description))
    mitre_technique = clean_csv_value(row.get('mitre_technique_id', row.get('mitre_technique', '')))
    mitre_tactic = clean_csv_value(row.get('mitre_tactic_id', row.get('mitre_tactic', '')))
    category = clean_csv_value(row.get('category', ''))

    # Build MITRE technique string
    mitre_technique_id_and_name = ''
    if mitre_technique:
        # Try to parse "T1059.001 - PowerShell" format
        if ' - ' in mitre_technique:
            mitre_technique_id_and_name = mitre_technique
        else:
            mitre_technique_id_and_name = f"{mitre_technique} - Unknown"

    # Build MITRE tactic string
    mitre_tactic_id_and_name = ''
    if mitre_tactic:
        if ' - ' in mitre_tactic:
            mitre_tactic_id_and_name = mitre_tactic
        else:
            tactic_names = {
                'TA0001': 'Initial Access',
                'TA0002': 'Execution',
                'TA0003': 'Persistence',
                'TA0004': 'Privilege Escalation',
                'TA0005': 'Defense Evasion',
                'TA0006': 'Credential Access',
                'TA0007': 'Discovery',
                'TA0008': 'Lateral Movement',
                'TA0009': 'Collection',
                'TA0010': 'Exfiltration',
                'TA0011': 'Command and Control',
                'TA0040': 'Impact'
            }
            tactic_name = tactic_names.get(mitre_tactic, 'Unknown')
            mitre_tactic_id_and_name = f"{mitre_tactic} - {tactic_name}"

    # Create indicator text from XQL query (abbreviated)
    indicator_text = xql_query[:200] if len(xql_query) > 200 else xql_query

    bioc = {
        "name": name,
        "comment": comment,
        "description": description,
        "severity": severity,
        "status": status,
        "is_xql": True,
        "category": category if category else "EXECUTION",
        "xql": xql_query,
        "indicator_text": indicator_text,
        "indicator": {
            "runOnCGO": True,
            "investigationType": "PROCESS_EXECUTION_EVENT",
            "investigation": {}
        }
    }

    if mitre_technique_id_and_name:
        bioc["mitre_technique_id_and_name"] = mitre_technique_id_and_name
        # Extract technique ID
        if ' - ' in mitre_technique_id_and_name:
            bioc["mitre_technique_id"] = mitre_technique_id_and_name.split(' - ')[0]
    
    if mitre_tactic_id_and_name:
        bioc["mitre_tactic_id_and_name"] = mitre_tactic_id_and_name
        # Extract tactic ID
        if ' - ' in mitre_tactic_id_and_name:
            bioc["mitre_tactic_id"] = mitre_tactic_id_and_name.split(' - ')[0]

    return bioc


def create_indicator_bioc(row: Dict[str, str]) -> Dict[str, Any]:
    """Create an indicator-based BIOC from CSV row."""
    name = clean_csv_value(row.get('name', ''))
    if not name:
        raise ValueError("Missing required field: name")

    description = clean_csv_value(row.get('description', '')) or name
    severity = normalize_severity(row.get('severity', 'medium'))
    status = normalize_status(row.get('status', 'enabled'))
    investigation_type = normalize_investigation_type(
        row.get('investigation_type', row.get('investigationType', 'process'))
    )
    search_field = clean_csv_value(row.get('search_field', ''))
    if not search_field:
        raise ValueError(f"Indicator-based BIOC '{name}' missing search_field")
    
    search_type = normalize_search_type(row.get('search_type', 'CONTAINS'))
    search_value = clean_csv_value(row.get('search_value', ''))
    if not search_value:
        raise ValueError(f"Indicator-based BIOC '{name}' missing search_value")

    comment = clean_csv_value(row.get('comment', description))
    mitre_technique = clean_csv_value(row.get('mitre_technique_id', row.get('mitre_technique', '')))
    mitre_tactic = clean_csv_value(row.get('mitre_tactic_id', row.get('mitre_tactic', '')))
    category = clean_csv_value(row.get('category', ''))

    # Build indicator filter
    filter_condition = {
        "SEARCH_FIELD": search_field,
        "SEARCH_TYPE": search_type,
        "SEARCH_VALUE": search_value,
        "EXTRA_FIELDS": [],
        "isExtended": False,
        "node": "attributes"
    }

    # Create indicator structure
    indicator = {
        "runOnCGO": True,
        "investigationType": investigation_type,
        "investigation": {
            investigation_type: {
                "filter": {
                    "AND": [filter_condition]
                }
            }
        }
    }

    # Create indicator text
    indicator_text = f"{search_field} {search_type.lower()} {search_value}"

    # Build MITRE strings (same as XQL)
    mitre_technique_id_and_name = ''
    if mitre_technique:
        if ' - ' in mitre_technique:
            mitre_technique_id_and_name = mitre_technique
        else:
            mitre_technique_id_and_name = f"{mitre_technique} - Unknown"

    mitre_tactic_id_and_name = ''
    if mitre_tactic:
        if ' - ' in mitre_tactic:
            mitre_tactic_id_and_name = mitre_tactic
        else:
            tactic_names = {
                'TA0001': 'Initial Access',
                'TA0002': 'Execution',
                'TA0003': 'Persistence',
                'TA0004': 'Privilege Escalation',
                'TA0005': 'Defense Evasion',
                'TA0006': 'Credential Access',
                'TA0007': 'Discovery',
                'TA0008': 'Lateral Movement',
                'TA0009': 'Collection',
                'TA0010': 'Exfiltration',
                'TA0011': 'Command and Control',
                'TA0040': 'Impact'
            }
            tactic_name = tactic_names.get(mitre_tactic, 'Unknown')
            mitre_tactic_id_and_name = f"{mitre_tactic} - {tactic_name}"

    bioc = {
        "name": name,
        "comment": comment,
        "description": description,
        "severity": severity,
        "status": status,
        "is_xql": False,
        "category": category if category else "EXECUTION",
        "indicator": indicator,
        "indicator_text": indicator_text
    }

    if mitre_technique_id_and_name:
        bioc["mitre_technique_id_and_name"] = mitre_technique_id_and_name
        if ' - ' in mitre_technique_id_and_name:
            bioc["mitre_technique_id"] = mitre_technique_id_and_name.split(' - ')[0]
    
    if mitre_tactic_id_and_name:
        bioc["mitre_tactic_id_and_name"] = mitre_tactic_id_and_name
        if ' - ' in mitre_tactic_id_and_name:
            bioc["mitre_tactic_id"] = mitre_tactic_id_and_name.split(' - ')[0]

    return bioc


def detect_bioc_type(row: Dict[str, str]) -> str:
    """Auto-detect whether row is XQL-based or indicator-based."""
    # Check is_xql field first (most reliable)
    is_xql = clean_csv_value(row.get('is_xql', ''))
    if is_xql:
        return 'xql' if is_xql.lower() in ['true', 'yes', '1'] else 'indicator'
    
    # Check for XQL query fields with actual content
    xql_value = clean_csv_value(row.get('xql_query', row.get('xql', row.get('query', ''))))
    if xql_value:
        return 'xql'
    
    # Check for indicator fields with actual content
    search_field = clean_csv_value(row.get('search_field', ''))
    search_value = clean_csv_value(row.get('search_value', ''))
    investigation_type = clean_csv_value(row.get('investigation_type', row.get('investigationType', '')))
    
    if search_field and search_value:
        return 'indicator'
    
    # Default to XQL if no clear indicator
    return 'xql'


def convert_csv_to_bioc(csv_file: str, bioc_type: str = 'auto', auto_detect: bool = False) -> List[Dict[str, Any]]:
    """
    Convert CSV file to Cortex XDR BIOC format.
    
    Args:
        csv_file: Path to CSV file
        bioc_type: 'xql', 'indicator', or 'auto' (auto-detect per row)
        auto_detect: If True, auto-detect type for each row
    
    Returns:
        List of BIOC dictionaries
    """
    biocs = []
    errors = []
    
    logger.info(f"Reading CSV file: {csv_file}")
    
    with open(csv_file, 'r', encoding='utf-8-sig') as f:
        # Try to detect encoding issues
        reader = csv.DictReader(f)
        
        logger.info(f"CSV columns: {reader.fieldnames}")
        
        for row_num, row in enumerate(reader, start=2):  # Start at 2 (row 1 is header)
            try:
                # Skip empty rows
                if not any(row.values()):
                    continue
                
                # Determine BIOC type
                if auto_detect or bioc_type == 'auto':
                    row_type = detect_bioc_type(row)
                else:
                    row_type = bioc_type
                
                # Create BIOC
                if row_type == 'xql':
                    bioc = create_xql_bioc(row)
                else:
                    bioc = create_indicator_bioc(row)
                
                biocs.append(bioc)
                logger.debug(f"✓ Row {row_num}: Created BIOC '{bioc['name']}'")
                
            except ValueError as e:
                errors.append(f"Row {row_num}: {str(e)}")
                logger.warning(f"Skipping row {row_num}: {e}")
            except Exception as e:
                errors.append(f"Row {row_num}: Unexpected error - {str(e)}")
                logger.error(f"Unexpected error on row {row_num}: {e}")
    
    if errors:
        logger.warning(f"\nEncountered {len(errors)} error(s) during conversion:")
        for error in errors:
            logger.warning(f"  - {error}")
    
    return biocs


def generate_template(output_file: str = 'bioc_template.csv', template_type: str = 'both'):
    """Generate CSV template file with sample data."""
    
    templates = {
        'xql': {
            'filename': 'bioc_template_xql.csv',
            'headers': [
                'name', 'description', 'severity', 'status', 'is_xql',
                'xql_query', 'comment', 'mitre_technique_id', 'mitre_tactic_id', 'category'
            ],
            'sample_data': [
                {
                    'name': 'Suspicious PowerShell Execution',
                    'description': 'Detects suspicious PowerShell encoded command execution',
                    'severity': 'high',
                    'status': 'enabled',
                    'is_xql': 'true',
                    'xql_query': 'dataset = xdr_data | filter action_process_image_name contains "powershell.exe" | filter action_process_image_command_line contains "-enc" | limit 100',
                    'comment': 'PowerShell encoded command detection',
                    'mitre_technique_id': 'T1059.001 - PowerShell',
                    'mitre_tactic_id': 'TA0002',
                    'category': 'EXECUTION'
                },
                {
                    'name': 'Admin File Execution',
                    'description': 'Administrator account executing files',
                    'severity': 'medium',
                    'status': 'enabled',
                    'is_xql': 'true',
                    'xql_query': 'dataset = xdr_data | filter action_process_username =~ "Administrator" | limit 100',
                    'comment': 'Administrator file execution',
                    'mitre_technique_id': 'T1078.001 - Valid Accounts: Default Accounts',
                    'mitre_tactic_id': 'TA0004',
                    'category': 'PRIVILEGE_ESCALATION'
                }
            ]
        },
        'indicator': {
            'filename': 'bioc_template_indicator.csv',
            'headers': [
                'name', 'description', 'severity', 'status', 'is_xql',
                'investigation_type', 'search_field', 'search_type', 'search_value',
                'comment', 'mitre_technique_id', 'mitre_tactic_id', 'category'
            ],
            'sample_data': [
                {
                    'name': 'PowerShell Process Execution',
                    'description': 'Detect PowerShell process creation',
                    'severity': 'high',
                    'status': 'enabled',
                    'is_xql': 'false',
                    'investigation_type': 'process_execution_event',
                    'search_field': 'action_process_image_name',
                    'search_type': 'contains',
                    'search_value': 'powershell.exe',
                    'comment': 'PowerShell detection',
                    'mitre_technique_id': 'T1059.001',
                    'mitre_tactic_id': 'TA0002',
                    'category': 'EXECUTION'
                },
                {
                    'name': 'Suspicious Domain Connection',
                    'description': 'Detect connection to known malicious domain',
                    'severity': 'critical',
                    'status': 'enabled',
                    'is_xql': 'false',
                    'investigation_type': 'network_event',
                    'search_field': 'action_remote_ip_domain',
                    'search_type': 'contains',
                    'search_value': 'malware.com',
                    'comment': 'Malicious domain detection',
                    'mitre_technique_id': 'T1071',
                    'mitre_tactic_id': 'TA0011',
                    'category': 'COMMAND_AND_CONTROL'
                }
            ]
        }
    }
    
    if template_type == 'both':
        # Generate both templates
        for tmpl_type in ['xql', 'indicator']:
            tmpl = templates[tmpl_type]
            filename = tmpl['filename']
            generate_single_template(tmpl['headers'], tmpl['sample_data'], filename)
        logger.info(f"✓ Generated both templates: {templates['xql']['filename']}, {templates['indicator']['filename']}")
    else:
        if template_type not in templates:
            logger.error(f"Invalid template type: {template_type}. Use 'xql', 'indicator', or 'both'")
            sys.exit(1)
        tmpl = templates[template_type]
        generate_single_template(tmpl['headers'], tmpl['sample_data'], tmpl['filename'])
        logger.info(f"✓ Generated template: {tmpl['filename']}")


def generate_single_template(headers: List[str], sample_data: List[Dict], filename: str):
    """Generate a single CSV template file."""
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(sample_data)
    logger.info(f"  - {filename}")


def save_biocs_to_json(biocs: List[Dict], output_file: str, pretty: bool = True):
    """Save BIOCs to JSON file."""
    logger.info(f"Saving {len(biocs)} BIOC(s) to: {output_file}")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        if pretty:
            json.dump(biocs, f, indent=2, ensure_ascii=False)
        else:
            json.dump(biocs, f, ensure_ascii=False)
    
    logger.info(f"✓ Successfully saved to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="CSV to Cortex XDR BIOC JSON Converter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate CSV templates
  python csv_to_bioc.py --template
  python csv_to_bioc.py --template xql
  python csv_to_bioc.py --template indicator

  # Convert CSV to BIOC JSON (auto-detect type)
  python csv_to_bioc.py --file biocs.csv --output biocs.json

  # Convert CSV with specific type
  python csv_to_bioc.py --file biocs.csv --output biocs.json --type xql
  python csv_to_bioc.py --file biocs.csv --output biocs.json --type indicator

  # Convert with auto-detection per row
  python csv_to_bioc.py --file biocs.csv --output biocs.json --auto-detect

  # Convert with verbose output
  python csv_to_bioc.py --file biocs.csv --output biocs.json -v

CSV Format (Unified - supports both types):
  name,description,severity,status,is_xql,xql_query,investigation_type,search_field,search_type,search_value,comment,mitre_technique_id,mitre_tactic_id,category

For XQL-based BIOCs: Fill xql_query, leave indicator fields empty
For Indicator-based BIOCs: Fill investigation_type, search_field, search_type, search_value, leave xql_query empty

Field Descriptions:
  name                - BIOC rule name (required)
  description         - Rule description (defaults to name if empty)
  severity            - informational, low, medium, high, critical (default: medium)
  status              - enabled or disabled (default: enabled)
  is_xql              - true for XQL-based, false for indicator-based
  xql_query           - XQL query string (for XQL-based BIOCs only)
  investigation_type  - process_execution_event, file_event, network_event, etc. (for indicator-based)
  search_field        - XDR field name to search (e.g., action_process_image_name)
  search_type         - contains, eq, regex, starts_with, ends_with
  search_value        - Value to search for
  comment             - Rule comment/notes
  mitre_technique_id  - MITRE technique (e.g., T1059.001 or "T1059.001 - PowerShell")
  mitre_tactic_id     - MITRE tactic ID (e.g., TA0002 or "TA0002 - Execution")
  category            - BIOC category (EXECUTION, PERSISTENCE, PRIVILEGE_ESCALATION, etc.)
        """
    )
    
    parser.add_argument('--file', '-f', help='Input CSV file path')
    parser.add_argument('--output', '-o', help='Output JSON file path (default: <input_filename>.json)')
    parser.add_argument('--type', '-t', 
                       choices=['xql', 'indicator', 'auto'],
                       default='auto',
                       help='BIOC type: xql, indicator, or auto (default: auto)')
    parser.add_argument('--auto-detect', action='store_true',
                       help='Auto-detect BIOC type for each CSV row')
    parser.add_argument('--template', nargs='?', const='both',
                       choices=['xql', 'indicator', 'both'],
                       help='Generate CSV template file(s)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose/debug output')
    
    args = parser.parse_args()
    
    # Setup logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Generate template if requested
    if args.template:
        generate_template(template_type=args.template)
        return
    
    # Validate file argument
    if not args.file:
        parser.error("--file is required (use --template to generate CSV templates)")
    
    if not os.path.exists(args.file):
        logger.error(f"File not found: {args.file}")
        sys.exit(1)
    
    # Set default output filename
    if not args.output:
        base_name = os.path.splitext(args.file)[0]
        args.output = f"{base_name}_biocs.json"
    
    try:
        # Convert CSV to BIOCs
        auto_detect = args.auto_detect or args.type == 'auto'
        biocs = convert_csv_to_bioc(args.file, args.type, auto_detect)
        
        if not biocs:
            logger.error("No valid BIOCs found in CSV file")
            sys.exit(1)
        
        # Save to JSON
        save_biocs_to_json(biocs, args.output)
        
        # Summary
        logger.info(f"\n{'='*60}")
        logger.info("CONVERSION COMPLETE")
        logger.info(f"{'='*60}")
        logger.info(f"Total BIOCs converted: {len(biocs)}")
        logger.info(f"XQL-based BIOCs: {sum(1 for b in biocs if b.get('is_xql'))}")
        logger.info(f"Indicator-based BIOCs: {sum(1 for b in biocs if not b.get('is_xql'))}")
        logger.info(f"Output file: {args.output}")
        logger.info(f"\nNext step: Import using xdr_xql_inserter.py")
        logger.info(f"  python xdr_xql_inserter.py --file {args.output}")
        
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
