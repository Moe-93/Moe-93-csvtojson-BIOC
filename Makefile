# CSV to Cortex XDR BIOC Converter - Makefile
# Quick commands for common operations

.PHONY: help templates convert-xql convert-indicator convert-mixed test clean

# Default target
help:
	@echo "CSV to Cortex XDR BIOC Converter"
	@echo "================================="
	@echo ""
	@echo "Available commands:"
	@echo "  make templates              - Generate CSV templates"
	@echo "  make convert-xql            - Convert XQL-based CSV to JSON"
	@echo "  make convert-indicator      - Convert indicator-based CSV to JSON"
	@echo "  make convert-mixed          - Convert mixed CSV with auto-detect"
	@echo "  make test                   - Run test conversions"
	@echo "  make clean                  - Remove generated files"
	@echo "  make help                   - Show this help"
	@echo ""
	@echo "Usage examples:"
	@echo "  make convert-xql FILE=my_rules.csv"
	@echo "  make convert-indicator FILE=my_indicators.csv"
	@echo ""

# Generate CSV templates
templates:
	python3 csv_to_bioc.py --template both

# Convert XQL-based CSV to JSON
convert-xql:
ifndef FILE
	$(error FILE is required. Usage: make convert-xql FILE=my_rules.csv)
endif
	python3 csv_to_bioc.py --file $(FILE) --output $(FILE:.csv=.json) --type xql

# Convert indicator-based CSV to JSON
convert-indicator:
ifndef FILE
	$(error FILE is required. Usage: make convert-indicator FILE=my_indicators.csv)
endif
	python3 csv_to_bioc.py --file $(FILE) --output $(FILE:.csv=.json) --type indicator

# Convert mixed CSV with auto-detection
convert-mixed:
ifndef FILE
	$(error FILE is required. Usage: make convert-mixed FILE=my_biocs.csv)
endif
	python3 csv_to_bioc.py --file $(FILE) --output $(FILE:.csv=.json) --auto-detect

# Run tests
test:
	@echo "Running test conversions..."
	@echo ""
	@echo "Test 1: XQL-based conversion"
	python3 csv_to_bioc.py --file sample_xql_biocs.csv --output test_xql.json --type xql
	@echo ""
	@echo "Test 2: Indicator-based conversion"
	python3 csv_to_bioc.py --file sample_indicator_biocs.csv --output test_indicator.json --type indicator
	@echo ""
	@echo "Test 3: Auto-detection with mixed CSV"
	python3 csv_to_bioc.py --file sample_biocs.csv --output test_mixed.json --auto-detect
	@echo ""
	@echo "✅ All tests completed!"
	@echo ""
	@echo "Generated test files:"
	@ls -lh test_*.json 2>/dev/null || echo "No test files found"

# Clean generated test files
clean:
	rm -f test_*.json
	rm -f bioc_template_*.csv
	@echo "Cleaned generated files"
