import os
from pinecone import Pinecone, ServerlessSpec

pc = Pinecone(api_key=os.getenv("PINECONE_API_KEY"))

def get_index():
    index_name = os.getenv("PINECONE_INDEX_NAME", "vhc-rag-index")
    ns = os.getenv("PINECONE_NAMESPACE", "vhc-default")
    index = pc.Index(index_name)
    return index, ns

def upsert_embedding(vec_id: str, embedding: list, metadata: dict):
    index, ns = get_index()
    index.upsert(
        vectors=[{
            "id": vec_id,
            "values": embedding,
            "metadata": metadata
        }],
        namespace=ns
    )

def query_embeddings(embedding: list, top_k=5):
    index, ns = get_index()
    res = index.query(
        vector=embedding,
        top_k=top_k,
        namespace=ns,
        include_metadata=True
    )
    return res
