import json
import os
from collections import Counter

import boto3

s3 = boto3.client("s3")

EVIDENCE_BUCKET = os.environ.get("EVIDENCE_BUCKET_NAME")


def list_decisions(prefix: str):
    paginator = s3.get_paginator("list_objects_v2")
    page_iterator = paginator.paginate(Bucket=EVIDENCE_BUCKET, Prefix=prefix)

    keys = []
    for page in page_iterator:
        for obj in page.get("Contents", []):
            keys.append(obj["Key"])
    return keys


def load_json(key: str):
    resp = s3.get_object(Bucket=EVIDENCE_BUCKET, Key=key)
    body = resp["Body"].read()
    return json.loads(body)


def main():
    if not EVIDENCE_BUCKET:
        raise SystemExit("EVIDENCE_BUCKET_NAME env var is required")

    prefixes = ["dlp-decisions/request/", "dlp-decisions/response/"]

    decisions = []
    for p in prefixes:
        for key in list_decisions(p):
            try:
                record = load_json(key)
                decisions.append(record)
            except Exception:
                # Skip corrupt records in a lab setting
                continue

    total = len(decisions)
    decision_counter = Counter(d.get("decision", "unknown") for d in decisions)
    stage_counter = Counter(d.get("stage", "unknown") for d in decisions)

    summary = {
        "total_records": total,
        "by_decision": dict(decision_counter),
        "by_stage": dict(stage_counter),
    }

    os.makedirs("evidence", exist_ok=True)

    with open("evidence/dlp_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    with open("evidence/dlp_summary.md", "w", encoding="utf-8") as f:
        f.write("# DLP Evidence Summary\n\n")
        f.write(f"- Total records: **{total}**\n")
        f.write("## By Decision\n")
        for k, v in decision_counter.items():
            f.write(f"- {k}: {v}\n")
        f.write("\n## By Stage\n")
        for k, v in stage_counter.items():
            f.write(f"- {k}: {v}\n")

    print("Evidence summary written to evidence/dlp_summary.json and .md")


if __name__ == "__main__":
    main()
