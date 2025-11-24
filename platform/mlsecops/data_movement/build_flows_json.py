import yaml, json, pathlib

ROOT = pathlib.Path(__file__).parent
flows_yaml = ROOT / "flows.yaml"
flows_json = ROOT / "flows.json"

data = yaml.safe_load(flows_yaml.read_text())
flows = data.get("flows", [])

flows_json.write_text(json.dumps({"flows": flows}, indent=2))
print("wrote", flows_json)
