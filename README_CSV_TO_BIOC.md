# CSV to Cortex XDR BIOC Converter

Convert CSV files to Cortex XDR BIOC (Behavioral Indicators of Compromise) JSON format for easy import.

## Features

✅ **Two BIOC Types Supported:**
- **XQL-based BIOCs** - Uses XQL queries for detection
- **Indicator-based BIOCs** - Uses investigation filters (process, file, network, registry events)

✅ **Auto-Detection:** Automatically detects BIOC type per row based on CSV content

✅ **MITRE ATT&CK Mapping:** Automatic MITRE technique and tactic ID expansion

✅ **Severity Normalization:** Converts simple severity labels to XDR format

✅ **Template Generation:** Generate ready-to-use CSV templates with sample data

✅ **Validation:** Validates required fields and provides detailed error reporting

## Installation

No additional dependencies required! Uses only Python standard library modules.

```bash
# Works with Python 3.6+
python3 csv_to_bioc.py --help
```

## Quick Start

### 1. Generate CSV Templates

```bash
# Generate both XQL and indicator templates
python3 csv_to_bioc.py --template both

# Generate only XQL template
python3 csv_to_bioc.py --template xql

# Generate only indicator template  
python3 csv_to_bioc.py --template indicator
```

### 2. Fill in Your CSV

Edit the generated CSV templates with your BIOC rules.

**XQL-based CSV columns:**
```
name, description, severity, status, is_xql, xql_query, comment, mitre_technique_id, mitre_tactic_id, category
```

**Indicator-based CSV columns:**
```
name, description, severity, status, is_xql, investigation_type, search_field, search_type, search_value, comment, mitre_technique_id, mitre_tactic_id, category
```

### 3. Convert CSV to BIOC JSON

```bash
# Convert XQL-based BIOCs
python3 csv_to_bioc.py --file my_xql_biocs.csv --output xql_biocs.json --type xql

# Convert indicator-based BIOCs
python3 csv_to_bioc.py --file my_indicator_biocs.csv --output indicator_biocs.json --type indicator

# Auto-detect type for each row (mixed CSV)
python3 csv_to_bioc.py --file mixed_biocs.csv --output all_biocs.json --auto-detect
```

### 4. Import to Cortex XDR

```bash
# Using the bulk importer
python3 xdr_xql_inserter.py --file xql_biocs.json

# Or using the simple importer
python3 xdr_bioc_importer.py
```

## CSV Format Examples

### XQL-based BIOC CSV

```csv
name,description,severity,status,is_xql,xql_query,comment,mitre_technique_id,mitre_tactic_id,category
Suspicious PowerShell,Detect PowerShell encoded commands,high,enabled,true,"dataset = xdr_data | filter action_process_image_name contains ""powershell.exe"" | filter action_process_image_command_line contains ""-enc"" | limit 100",Encoded PowerShell detection,T1059.001 - PowerShell,TA0002,EXECUTION
Admin File Execution,Administrator executing files,medium,enabled,true,"dataset = xdr_data | filter action_process_username =~ ""Administrator"" | limit 100",Admin execution detection,T1078.001 - Valid Accounts,TA0004,PRIVILEGE_ESCALATION
```

### Indicator-based BIOC CSV

```csv
name,description,severity,status,is_xql,investigation_type,search_field,search_type,search_value,comment,mitre_technique_id,mitre_tactic_id,category
Malicious Domain,Detect malicious domain connections,critical,enabled,false,network_event,action_remote_ip_domain,contains,malware.com,Malware domain detection,T1071 - Application Layer Protocol,TA0011,COMMAND_AND_CONTROL
Suspicious Process,Detect execution from temp directory,high,enabled,false,process_execution_event,action_process_image_path,contains,C:\Users\Public\,Temp directory execution,T1059 - Command and Scripting Interpreter,TA0002,EXECUTION
```

## Field Reference

### Common Fields (Both Types)

| Field | Required | Description | Example Values |
|-------|----------|-------------|----------------|
| `name` | ✅ | BIOC rule name | `Suspicious PowerShell Execution` |
| `description` | ❌ | Rule description (defaults to name) | `Detects suspicious PowerShell activity` |
| `severity` | ❌ | Severity level (default: medium) | `informational`, `low`, `medium`, `high`, `critical` |
| `status` | ❌ | Rule status (default: enabled) | `enabled`, `disabled` |
| `is_xql` | ❌ | BIOC type flag | `true` for XQL, `false` for indicator |
| `comment` | ❌ | Additional notes | `Internal rule #123` |
| `mitre_technique_id` | ❌ | MITRE technique | `T1059.001` or `T1059.001 - PowerShell` |
| `mitre_tactic_id` | ❌ | MITRE tactic | `TA0002` or `TA0002 - Execution` |
| `category` | ❌ | BIOC category | `EXECUTION`, `PERSISTENCE`, `PRIVILEGE_ESCALATION`, etc. |

### XQL-based Specific Fields

| Field | Required | Description | Example |
|-------|----------|-------------|---------|
| `xql_query` | ✅ | XQL query string | `dataset = xdr_data \| filter ... \| limit 100` |

### Indicator-based Specific Fields

| Field | Required | Description | Example Values |
|-------|----------|-------------|----------------|
| `investigation_type` | ✅ | Event type | `process_execution_event`, `file_event`, `network_event`, `registry_event`, `dns_event`, `ip_address_event`, `url_event` |
| `search_field` | ✅ | XDR field to search | `action_process_image_name`, `action_remote_ip_domain`, `registry_key_name` |
| `search_type` | ✅ | Comparison operator | `contains`, `eq`, `regex`, `starts_with`, `ends_with`, `not_equal` |
| `search_value` | ✅ | Value to search for | `powershell.exe`, `malware.com`, `*.exe` |

## Supported Values

### Severity Mapping

| CSV Value | XDR Format |
|-----------|------------|
| `informational`, `info` | `SEV_010_INFORMATIONAL` |
| `low` | `SEV_020_LOW` |
| `medium` | `SEV_030_MEDIUM` |
| `high` | `SEV_040_HIGH` |
| `critical` | `SEV_050_CRITICAL` |

### Status Mapping

| CSV Value | XDR Format |
|-----------|------------|
| `enabled`, `enable`, `true`, `yes`, `active`, `on` | `ENABLED` |
| `disabled`, `disable`, `false`, `no`, `inactive`, `off` | `DISABLED` |

### Investigation Type Mapping

| CSV Value | XDR Format |
|-----------|------------|
| `process`, `process_execution`, `process_execution_event` | `PROCESS_EXECUTION_EVENT` |
| `file`, `file_event` | `FILE_EVENT` |
| `network`, `network_event` | `NETWORK_EVENT` |
| `registry`, `registry_event` | `REGISTRY_EVENT` |
| `dns`, `dns_event` | `DNS_EVENT` |
| `ip`, `ip_address`, `ip_address_event` | `IP_ADDRESS_EVENT` |
| `url`, `url_event` | `URL_EVENT` |

### MITRE Tactic ID Mapping

| Tactic ID | Tactic Name |
|-----------|-------------|
| `TA0001` | Initial Access |
| `TA0002` | Execution |
| `TA0003` | Persistence |
| `TA0004` | Privilege Escalation |
| `TA0005` | Defense Evasion |
| `TA0006` | Credential Access |
| `TA0007` | Discovery |
| `TA0008` | Lateral Movement |
| `TA0009` | Collection |
| `TA0010` | Exfiltration |
| `TA0011` | Command and Control |
| `TA0040` | Impact |

### BIOC Categories

Common categories used in Cortex XDR:
- `EXECUTION`
- `PERSISTENCE`
- `PRIVILEGE_ESCALATION`
- `DEFENSE_EVASION`
- `CREDENTIAL_ACCESS`
- `DISCOVERY`
- `LATERAL_MOVEMENT`
- `COLLECTION`
- `EXFILTRATION`
- `COMMAND_AND_CONTROL`
- `IMPACT`

## Command Line Options

```
usage: csv_to_bioc.py [-h] [--file FILE] [--output OUTPUT] [--type {xql,indicator,auto}]
                      [--auto-detect] [--template [{xql,indicator,both}]] [--verbose]

CSV to Cortex XDR BIOC JSON Converter

options:
  -h, --help            Show this help message and exit
  --file, -f FILE       Input CSV file path
  --output, -o OUTPUT   Output JSON file path (default: <input_filename>.json)
  --type, -t {xql,indicator,auto}
                        BIOC type: xql, indicator, or auto (default: auto)
  --auto-detect         Auto-detect BIOC type for each CSV row
  --template [{xql,indicator,both}]
                        Generate CSV template file(s)
  --verbose, -v         Enable verbose/debug output
```

## Troubleshooting

### Issue: CSV parsing errors

**Solution:** Ensure your CSV file:
- Uses UTF-8 encoding (or UTF-8 with BOM)
- Has proper quoting for fields containing commas
- Escapes double quotes by doubling them (`""`)

### Issue: Missing required fields

**Solution:** Check that:
- XQL-based BIOCs have `xql_query` field
- Indicator-based BIOCs have `search_field` and `search_value` fields
- All BIOCs have `name` field

### Issue: Invalid severity or status

**Solution:** Use supported values from the mapping tables above. The script normalizes common variations automatically.

## Integration with Other Scripts

This converter is designed to work seamlessly with the other BIOC management scripts in this project:

1. **csv_to_bioc.py** - Convert CSV to BIOC JSON ✅ (this script)
2. **xdr_xql_inserter.py** - Bulk import BIOCs to XDR
3. **xdr_bioc_importer.py** - Simple BIOC importer
4. **validation.py** - Validate XQL queries
5. **jsonconvert.py** - Clean and normalize XQL queries

### Example Workflow

```bash
# Step 1: Create CSV
cat > my_biocs.csv << EOF
name,description,severity,status,is_xql,xql_query,comment,mitre_technique_id,mitre_tactic_id,category
Test Rule,Test detection,low,enabled,true,"dataset = xdr_data | limit 100",Test rule,T1059.001,TA0002,EXECUTION
EOF

# Step 2: Convert to JSON
python3 csv_to_bioc.py --file my_biocs.csv --output my_biocs.json

# Step 3: Validate XQL (optional)
python3 validation.py --file my_biocs.json

# Step 4: Import to XDR
export XDR_API_URL="api.xdr.sa.paloaltonetworks.com"
export XDR_API_KEY_ID="5"
export XDR_API_KEY="your_api_key_here"
python3 xdr_xql_inserter.py --file my_biocs.json
```

## Best Practices

1. **Test First:** Use `--verbose` flag to review conversion details
2. **Start Small:** Test with 2-3 BIOCs before bulk conversion
3. **Use Templates:** Generate templates with `--template` for correct format
4. **Validate XQL:** Run XQL queries through `validation.py` before importing
5. **Backup JSON:** Keep original CSV files for easy updates
6. **Naming Convention:** Use consistent, descriptive BIOC names
7. **MITRE Mapping:** Include MITRE technique and tactic IDs for better reporting

## License

This script is provided as-is for use with Cortex XDR. Modify and distribute as needed.

## Support

For issues or questions:
1. Check this README
2. Run with `--verbose` flag for detailed output
3. Review sample CSV files in this directory
4. Check Cortex XDR API documentation for endpoint details
