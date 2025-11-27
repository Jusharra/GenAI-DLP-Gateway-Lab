import os
from pinecone import Pinecone, ServerlessSpec
from dotenv import load_dotenv  # ✅ add this

load_dotenv()  


def main():
    api_key = os.getenv("PINECONE_API_KEY")
    if not api_key:
        raise RuntimeError("PINECONE_API_KEY must be set in the environment")

    index_name = os.getenv("PINECONE_INDEX_NAME", "vhc-rag-index")
    region = os.getenv("PINECONE_REGION", "us-east-1")

    pc = Pinecone(api_key=api_key)

    # List existing indexes
    existing = [idx["name"] for idx in pc.list_indexes()]
    print(f"[PINECONE] Existing indexes: {existing}")

    # Delete if it already exists with wrong dim
    if index_name in existing:
        print(f"[PINECONE] Deleting existing index '{index_name}'...")
        pc.delete_index(index_name)

    # Create new index with 1536-dim vectors (OpenAI text-embedding-3-small)
    print(f"[PINECONE] Creating index '{index_name}' with dimension 1536...")
    pc.create_index(
        name=index_name,
        dimension=1536,
        metric="cosine",
        spec=ServerlessSpec(
            cloud="aws",
            region=region,
        ),
    )

    print("[PINECONE] Index recreated ✅")


if __name__ == "__main__":
    main()
