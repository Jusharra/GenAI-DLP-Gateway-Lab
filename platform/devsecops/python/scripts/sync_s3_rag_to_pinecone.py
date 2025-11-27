import os
import json
from typing import List, Tuple, Dict

import boto3
from pinecone import Pinecone
from openai import OpenAI
from dotenv import load_dotenv  # ✅ add this

load_dotenv()  

DEMO_BUCKET = os.getenv("DEMO_BUCKET", "vhc-dlp-demo-data-dev")

# Support multiple prefixes: e.g. "clean/,sensitive/"
RAG_PREFIXES = [
    p.strip()
    for p in os.getenv("RAG_S3_PREFIXES", "clean/,sensitive/").split(",")
    if p.strip()
]

PINECONE_ENV = os.getenv("PINECONE_ENV") or os.getenv("PINECONE_ENVIRONMENT")
PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
PINECONE_INDEX_NAME = (
    os.getenv("PINECONE_INDEX_NAME")
    or os.getenv("PINECONE_INDEX")
    or "vhc-rag-index"
)
PINECONE_NAMESPACE = os.getenv("PINECONE_NAMESPACE", "default")

OPENAI_MODEL = os.getenv("OPENAI_EMBED_MODEL", "text-embedding-3-small")


def embed_texts(texts: List[str]) -> List[List[float]]:
    """
    Simple embedding helper. Uses OpenAI for now.
    Swap this out if you prefer another provider.
    """
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY must be set to embed texts")

    client = OpenAI(api_key=api_key)

    resp = client.embeddings.create(
        model=OPENAI_MODEL,
        input=texts,
    )
    # ordered list of embeddings
    return [item.embedding for item in resp.data]


def load_rag_docs_from_s3() -> List[Tuple[str, str, Dict]]:
    """
    Read RAG JSON docs from S3:DEMO_BUCKET/{prefixes}.
    Each object is expected to be JSON; we are tolerant about the text key:
      - "text"
      - "content"
      - "body"
      - "prompt"/"question"/"answer" (joined)
    """
    s3 = boto3.client("s3")

    docs: List[Tuple[str, str, Dict]] = []

    for prefix in RAG_PREFIXES:
        prefix = prefix.strip()
        if not prefix:
            continue

        print(f"[RAG] Listing S3 objects from {DEMO_BUCKET}/{prefix}")
        resp = s3.list_objects_v2(Bucket=DEMO_BUCKET, Prefix=prefix)

        contents = resp.get("Contents", [])
        if not contents:
            continue

        for obj in contents:
            key = obj["Key"]
            # ignore folder “keys”
            if key.endswith("/") or not key.endswith(".json"):
                continue

            body = s3.get_object(Bucket=DEMO_BUCKET, Key=key)["Body"].read()
            try:
                record = json.loads(body)
            except json.JSONDecodeError:
                print(f"[RAG] Skipping non-JSON object: {key}")
                continue

            # ---- tolerant text extraction ----
            text = None

            # primary candidates
            for field in ("text", "content", "body"):
                v = record.get(field)
                if isinstance(v, str) and v.strip():
                    text = v.strip()
                    break

            # fallback: join Q/A style fields if no single text field exists
            if text is None:
                q = record.get("question") or record.get("prompt")
                a = record.get("answer") or record.get("response")
                pieces = [p for p in [q, a] if isinstance(p, str) and p.strip()]
                if pieces:
                    text = "\n\n".join(pieces)

            if not text:
                # keep this log but do NOT treat it as fatal
                print(f"[RAG] Skipping {key}, no usable text field.")
                continue

            doc_id = record.get("id") or key
            metadata = record.get("metadata", {})
            metadata.setdefault("s3_key", key)

            docs.append((doc_id, text, metadata))

    if not docs:
        print(f"[RAG] No RAG docs found across all prefixes; nothing to sync.")
    else:
        print(f"[RAG] Loaded {len(docs)} docs from S3 across prefixes {RAG_PREFIXES}")

    return docs


def upsert_docs_to_pinecone(docs: List[Tuple[str, str, Dict]]):
    """
    Embed docs and upsert into Pinecone.
    """
    if not docs:
        print("[PINECONE] No docs to upsert; exiting.")
        return

    if not PINECONE_API_KEY:
        raise RuntimeError("PINECONE_API_KEY must be set")

    # New Pinecone client (no global init)
    pc = Pinecone(api_key=PINECONE_API_KEY)
    index = pc.Index(PINECONE_INDEX_NAME)

    batch_size = 32
    for i in range(0, len(docs), batch_size):
        batch = docs[i:i + batch_size]
        ids = [d[0] for d in batch]
        texts = [d[1] for d in batch]
        metas = [d[2] for d in batch]

        print(f"[PINECONE] Embedding batch {i}–{i+len(batch)-1}")
        vectors = embed_texts(texts)

        payload = [
            (ids[j], vectors[j], metas[j])
            for j in range(len(batch))
        ]

        print(
            f"[PINECONE] Upserting {len(payload)} vectors into "
            f"index '{PINECONE_INDEX_NAME}' namespace '{PINECONE_NAMESPACE}'"
        )
        index.upsert(
            vectors=payload,
            namespace=PINECONE_NAMESPACE,
        )


def main():
    docs = load_rag_docs_from_s3()
    upsert_docs_to_pinecone(docs)
    print("[RAG] Sync complete ✅")


if __name__ == "__main__":
    main()
