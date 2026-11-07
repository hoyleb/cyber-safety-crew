.PHONY: test demo
test:
	PYTHONPATH=src python3 -m unittest discover -s tests -v
demo:
	PYTHONPATH=src python3 -m cyber_safety_crew assess --scope examples/scope.json --zeek examples/conn.jsonl --nuclei examples/nuclei.jsonl --manual examples/manual.jsonl --inventory examples/inventory.jsonl --output demo-output
