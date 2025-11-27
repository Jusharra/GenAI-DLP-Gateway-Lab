import os
from dotenv import load_dotenv
from pinecone import Pinecone, ServerlessSpec

load_dotenv()


def main():
    api_key = os.getenv("PINECONE_API_KEY")
    # Support both names: PINECONE_ENV (old) and PINECONE_ENVIRONMENT (your .env)
    env = os.getenv("PINECONE_ENV") or os.getenv("PINECONE_ENVIRONMENT")

    if not api_key or not env:
        raise RuntimeError(
            "PINECONE_API_KEY and PINECONE_ENV (or PINECONE_ENVIRONMENT) must be set in your environment"
        )

    pc = Pinecone(api_key=api_key)

    index_name = os.getenv("PINECONE_INDEX", "vhc-rag-index")
    namespace = os.getenv("PINECONE_NAMESPACE", "vhc-default")

    # Create index if it doesn't exist (serverless)
    if index_name not in [idx["name"] for idx in pc.list_indexes()]:
        pc.create_index(
            name=index_name,
            dimension=384,  # all-MiniLM-L6-v2 embedding size
            metric="cosine",
            spec=ServerlessSpec(cloud="aws", region=env),
        )

    index = pc.Index(index_name)
    print(f"[PINECONE] Index '{index_name}' ready, namespace '{namespace}'")


if __name__ == "__main__":
    main()