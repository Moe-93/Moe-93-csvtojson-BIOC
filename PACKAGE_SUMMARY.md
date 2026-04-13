# 📦 CSV to Cortex XDR BIOC Converter - Complete Package

## ✅ What's Been Created

### Main Script
- **`csv_to_bioc.py`** - Production-ready CSV to BIOC converter

### Documentation
- **`README`** - Comprehensive reference guide
- **`QUICK_START.md`** - Quick start guide with examples

### Sample Files
- **`sample_xql_biocs.csv`** - XQL-based BIOC examples (3 rules)
- **`sample_indicator_biocs.csv`** - Indicator-based BIOC examples (5 rules)
- **`sample_xql_biocs.json`** - Converted XQL JSON output
- **`sample_indicator_biocs.json`** - Converted indicator JSON output
- **`bioc_template_xql.csv`** - XQL template with sample data
- **`bioc_template_indicator.csv`** - Indicator template with sample data

---

## 🎯 Features

### ✨ Core Capabilities
1. **Dual Format Support**
   - XQL-based BIOCs (query-driven detection)
   - Indicator-based BIOCs (field-based detection)

2. **Smart Auto-Detection**
   - Automatically detects BIOC type per row
   - Handles mixed CSV files seamlessly

3. **Intelligent Normalization**
   - Severity labels: `low` → `SEV_020_LOW`
   - Status values: `enabled/true/yes` → `ENABLED`
   - Investigation types: `process` → `PROCESS_EXECUTION_EVENT`
   - MITRE ATT&CK ID expansion

4. **Template Generation**
   - Ready-to-use CSV templates
   - Pre-filled with working examples

5. **Comprehensive Validation**
   - Required field checking
   - Detailed error reporting
   - Skip invalid rows gracefully

### 🛡️ DevSecOps Best Practices
- ✅ No external dependencies (stdlib only)
- ✅ UTF-8 encoding support
- ✅ Proper CSV escaping
- ✅ Verbose logging for debugging
- ✅ Error recovery and reporting
- ✅ Compatible with existing XDR tools

---

## 🚀 Usage Examples

### Basic Conversion

```bash
# Convert XQL-based BIOCs
python3 csv_to_bioc.py -f my_rules.csv -o my_rules.json --type xql

# Convert indicator-based BIOCs
python3 csv_to_bioc.py -f indicators.csv -o indicators.json --type indicator

# Auto-detect mixed file
python3 csv_to_bioc.py -f mixed.csv -o all.json --auto-detect
```

### Template Generation

```bash
# Generate both templates
python3 csv_to_bioc.py --template both

# Generate specific template
python3 csv_to_bioc.py --template xql
python3 csv_to_bioc.py --template indicator
```

### Advanced Usage

```bash
# Verbose output for debugging
python3 csv_to_bioc.py -f biocs.csv -o biocs.json -v

# Use with existing XDR tools
python3 csv_to_bioc.py -f biocs.csv -o biocs.json && \
python3 xdr_xql_inserter.py -f biocs.json
```

---

## 📊 CSV Format

### Unified Header (supports both types)

```csv
name,description,severity,status,is_xql,xql_query,investigation_type,search_field,search_type,search_value,comment,mitre_technique_id,mitre_tactic_id,category
```

### For XQL-based BIOCs (is_xql=true)
- **Fill**: `xql_query`
- **Leave empty**: `investigation_type`, `search_field`, `search_type`, `search_value`

**Example:**
```csv
PowerShell Detection,Detect PowerShell,high,enabled,true,"dataset = xdr_data | filter ...",,,,PowerShell detection,T1059.001,TA0002,EXECUTION
```

### For Indicator-based BIOCs (is_xql=false)
- **Fill**: `investigation_type`, `search_field`, `search_type`, `search_value`
- **Leave empty**: `xql_query`

**Example:**
```csv
Malicious Domain,Detect bad domains,critical,enabled,false,,network_event,action_remote_ip_domain,contains,malware.com,Domain detection,T1071,TA0011,COMMAND_AND_CONTROL
```

---

## 🔗 Integration with Existing Tools

### Workflow

```
CSV File
    ↓
csv_to_bioc.py (converts to JSON)
    ↓
BIOC JSON File
    ↓
xdr_xql_inserter.py (imports to XDR)
    ↓
Cortex XDR Console
```

### Complete Command Chain

```bash
# Step 1: Convert
python3 csv_to_bioc.py -f my_biocs.csv -o my_biocs.json

# Step 2: Validate (optional)
python3 validation.py --file my_biocs.json

# Step 3: Import
export XDR_API_URL="api.xdr.sa.paloaltonetworks.com"
export XDR_API_KEY_ID="5"
export XDR_API_KEY="your_api_key"
python3 xdr_xql_inserter.py -f my_biocs.json
```

---

## 📖 Field Reference

### Required Fields

| Type | Required Fields |
|------|----------------|
| **XQL-based** | `name`, `xql_query` |
| **Indicator-based** | `name`, `investigation_type`, `search_field`, `search_value` |

### Optional Fields (Both Types)
- `description` - Defaults to name if empty
- `severity` - Default: medium
- `status` - Default: enabled
- `comment` - Additional notes
- `mitre_technique_id` - MITRE technique
- `mitre_tactic_id` - MITRE tactic
- `category` - BIOC category

---

## 🎨 Supported Values

### Severity Mapping
```
informational → SEV_010_INFORMATIONAL
low           → SEV_020_LOW
medium        → SEV_030_MEDIUM
high          → SEV_040_HIGH
critical      → SEV_050_CRITICAL
```

### Investigation Types
```
process        → PROCESS_EXECUTION_EVENT
file           → FILE_EVENT
network        → NETWORK_EVENT
registry       → REGISTRY_EVENT
dns            → DNS_EVENT
ip             → IP_ADDRESS_EVENT
url            → URL_EVENT
```

### Search Types
```
contains    → CONTAINS
equals/eq   → EQ
regex       → REGEX
starts_with → STARTS_WITH
ends_with   → ENDS_WITH
not_equal   → NEQ
```

---

## 🧪 Testing

All tests passed successfully:

```bash
✅ XQL-based conversion (3 rules)
✅ Indicator-based conversion (5 rules)
✅ Auto-detection with mixed CSV (8 rules)
✅ Template generation (both types)
✅ Help command
✅ Verbose mode
```

---

## 📚 Documentation Files

1. **README_CSV_TO_BIOC.md** - Full reference (250+ lines)
   - Complete field descriptions
   - All supported values
   - Troubleshooting guide
   - Integration examples

2. **QUICK_START.md** - Quick reference (150+ lines)
   - 3-step process
   - Common use cases
   - Pro tips
   - Complete workflow example

---

## 🎓 Key Benefits

### For Security Analysts
- ✅ No coding required - just fill CSV
- ✅ Excel-compatible templates
- ✅ Bulk import capability
- ✅ MITRE ATT&CK integration

### For DevSecOps Engineers
- ✅ Scriptable and automatable
- ✅ CI/CD pipeline ready
- ✅ Version control friendly
- ✅ No external dependencies

### For SOC Teams
- ✅ Standardized format
- ✅ Easy to review and audit
- ✅ Reusable templates
- ✅ Consistent imports

---

## 🔧 Technical Details

- **Python Version**: 3.6+
- **Dependencies**: None (stdlib only: csv, json, argparse, logging)
- **License**: Free to modify and distribute
- **Compatible With**: Cortex XDR API v1
- **Tested On**: macOS, Linux compatible

---

## 📞 Support & Troubleshooting

### Common Issues

**Q: CSV parsing fails**
A: Ensure UTF-8 encoding and proper quote escaping

**Q: Import fails**
A: Verify API credentials and BIOC name uniqueness

**Q: Need help with XQL syntax**
A: Use `validation.py` to test queries before importing

### Getting Help

```bash
# Show all options
python3 csv_to_bioc.py --help

# Verbose debugging
python3 csv_to_bioc.py -f test.csv -o test.json -v

# Review documentation
cat README_CSV_TO_BIOC.md
cat QUICK_START.md
```

---

## 🎉 Ready to Use!

Your CSV to BIOC converter is production-ready and fully integrated with your existing XDR toolkit.

**Start with:**
```bash
python3 csv_to_bioc.py --template both
```

Then edit the templates and convert!
