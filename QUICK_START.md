# Quick Start Guide - CSV to BIOC Converter

## 🚀 3-Step Process

### Step 1: Generate Template
```bash
python3 csv_to_bioc.py --template both
```

### Step 2: Fill CSV with Your BIOCs
Edit `bioc_template_xql.csv` or `bioc_template_indicator.csv`

### Step 3: Convert & Import
```bash
python3 csv_to_bioc.py --file bioc_template_xql.csv --output biocs.json
python3 xdr_xql_inserter.py --file biocs.json
```

---

## 📋 CSV Format Examples

### XQL-based (is_xql = true)

```csv
name,description,severity,status,is_xql,xql_query,comment,mitre_technique_id,mitre_tactic_id,category
PowerShell Encoded Command,Detect encoded PowerShell,high,enabled,true,"dataset = xdr_data | filter action_process_image_name contains ""powershell.exe"" | filter action_process_image_command_line contains ""-enc"" | limit 100",Detection of encoded commands,T1059.001 - PowerShell,TA0002,EXECUTION
```

**Key points:**
- Wrap XQL queries in double quotes
- Escape internal quotes by doubling them: `""powershell.exe""`
- Set `is_xql` to `true`
- Leave indicator columns empty

### Indicator-based (is_xql = false)

```csv
name,description,severity,status,is_xql,investigation_type,search_field,search_type,search_value,comment,mitre_technique_id,mitre_tactic_id,category
Malicious Domain,Detect bad domains,critical,enabled,false,network_event,action_remote_ip_domain,contains,malware.com,Malicious domain detection,T1071,TA0011,COMMAND_AND_CONTROL
```

**Key points:**
- Set `is_xql` to `false`
- Fill `investigation_type`: process_execution_event, network_event, file_event, registry_event
- Fill `search_field`: XDR field name
- Fill `search_type`: contains, eq, regex
- Fill `search_value`: What to search for
- Leave `xql_query` empty

---

## 🎯 Common Use Cases

### 1. Process Execution Detection (Indicator-based)

```csv
name,description,severity,status,is_xql,investigation_type,search_field,search_type,search_value,comment,mitre_technique_id,mitre_tactic_id,category
Suspicious Executable,Detect cmd.exe execution,high,enabled,false,process_execution_event,action_process_image_name,equals,cmd.exe,cmd.exe execution detection,T1059.001,TA0002,EXECUTION
```

### 2. File Creation Detection (Indicator-based)

```csv
name,description,severity,status,is_xql,investigation_type,search_field,search_type,search_value,comment,mitre_technique_id,mitre_tactic_id,category
Ransom File Creation,Detect ransom note creation,critical,enabled,false,file_event,action_file_name,contains,ransom_note,Ransomware detection,T1486,TA0040,IMPACT
```

### 3. Network Connection Detection (Indicator-based)

```csv
name,description,severity,status,is_xql,investigation_type,search_field,search_type,search_value,comment,mitre_technique_id,mitre_tactic_id,category
C2 Beacon,Detect C2 beacon to evil.com,high,enabled,false,network_event,action_remote_ip_domain,equals,evil.com,C2 communication detection,T1071,TA0011,COMMAND_AND_CONTROL
```

### 4. Complex XQL Query (XQL-based)

```csv
name,description,severity,status,is_xql,xql_query,comment,mitre_technique_id,mitre_tactic_id,category
PowerShell with Hidden Window,Detect hidden PowerShell execution,high,enabled,true,"dataset = xdr_data | filter action_process_image_name contains ""powershell.exe"" | filter action_process_image_command_line contains ""-w hidden"" | filter action_process_image_command_line contains ""-nop"" | limit 100",Hidden PowerShell detection,T1059.001 - PowerShell,TA0002,EXECUTION
```

---

## 🔧 Field Values Reference

### Severity
- `informational` or `info` → Low impact
- `low` → Minor concern
- `medium` → Moderate risk (default)
- `high` → Significant threat
- `critical` → Immediate action required

### Status
- `enabled`, `true`, `yes`, `active` → Rule is active
- `disabled`, `false`, `no`, `inactive` → Rule is disabled

### Investigation Types
- `process_execution_event` or `process` → Process creation
- `file_event` or `file` → File operations
- `network_event` or `network` → Network connections
- `registry_event` or `registry` → Registry modifications
- `dns_event` or `dns` → DNS queries
- `ip_address_event` or `ip` → IP address events
- `url_event` or `url` → URL access

### Search Types
- `contains` → Partial match (most common)
- `equals` or `eq` → Exact match
- `regex` → Regular expression
- `starts_with` → Prefix match
- `ends_with` → Suffix match
- `not_equal` → Exclusion

### Categories
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

---

## ⚡ Pro Tips

1. **Test First**: Always test with 2-3 rules before bulk import
2. **Use Templates**: `python3 csv_to_bioc.py --template both`
3. **Verbose Mode**: Add `-v` flag for detailed output
4. **Auto-Detect**: Use `--auto-detect` for mixed CSV files
5. **Validate XQL**: Run XQL queries through `validation.py` first
6. **Escape Quotes**: Double any quotes in XQL queries: `""value""`
7. **UTF-8**: Save CSV files with UTF-8 encoding

---

## 🐛 Troubleshooting

### Problem: CSV parsing errors
**Solution**: Check UTF-8 encoding and proper quote escaping

### Problem: Missing fields error
**Solution**: Ensure required fields are filled:
- XQL: `name`, `xql_query`
- Indicator: `name`, `investigation_type`, `search_field`, `search_value`

### Problem: Invalid severity
**Solution**: Use: informational, low, medium, high, critical

### Problem: Import fails
**Solution**: 
1. Verify API credentials
2. Check XQL query syntax with `validation.py`
3. Ensure BIOC names are unique

---

## 📞 Need Help?

```bash
# Show all options
python3 csv_to_bioc.py --help

# Verbose output for debugging
python3 csv_to_bioc.py --file test.csv --output test.json -v

# Generate templates
python3 csv_to_bioc.py --template both
```

---

## 🔄 Complete Workflow

```bash
# 1. Generate template
python3 csv_to_bioc.py --template xql

# 2. Edit bioc_template_xql.csv with your rules (use Excel, LibreOffice, etc.)

# 3. Convert to JSON
python3 csv_to_bioc.py --file bioc_template_xql.csv --output my_biocs.json

# 4. Set XDR credentials
export XDR_API_URL="api.xdr.sa.paloaltonetworks.com"
export XDR_API_KEY_ID="5"
export XDR_API_KEY="your_key_here"

# 5. Import to XDR (dry run first)
python3 xdr_xql_inserter.py --file my_biocs.json --dry-run

# 6. Import for real
python3 xdr_xql_inserter.py --file my_biocs.json
```

That's it! Your BIOCs are now in Cortex XDR! 🎉
