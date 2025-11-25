# Pulls CI artifacts + hashes + zips. Zero drama for auditors.
import json, hashlib, zipfile
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "artifacts"
EVIDENCE = ROOT / "evidence"

FILES_TO_COLLECT = [
    ARTIFACTS / "pytest.xml",
    ARTIFACTS / "opa.json",
    ARTIFACTS / "checkov.json",
    ARTIFACTS / "tfplan.json",
    ARTIFACTS / "conftest.json",
    EVIDENCE / "controls_mapping.json",
]

def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    bundle_dir = EVIDENCE / ts
    bundle_dir.mkdir(parents=True, exist_ok=True)

    manifest = {"generated_at": ts, "files": []}

    for f in FILES_TO_COLLECT:
        if f.exists():
            dest = bundle_dir / f.name
            dest.write_bytes(f.read_bytes())
            manifest["files"].append({
                "name": f.name,
                "sha256": sha256_file(dest),
                "source": str(f)
            })
        else:
            manifest["files"].append({
                "name": f.name,
                "missing": True,
                "source": str(f)
            })

    manifest_path = bundle_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))

    # zip it
    zip_path = EVIDENCE / f"evidence_bundle_{ts}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for p in bundle_dir.rglob("*"):
            z.write(p, p.relative_to(bundle_dir))

    print(f"[OK] Evidence bundle created: {zip_path}")

if __name__ == "__main__":
    main()
