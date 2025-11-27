import os
import sys
from pathlib import Path
from typing import List, Dict, Any

import streamlit as st
from dotenv import load_dotenv
from openai import OpenAI
from dotenv import load_dotenv
from pinecone import Pinecone, ServerlessSpec

load_dotenv()

# ----------------------------------------------------
# Bootstrap Python path so we can import dlp_utils
# ----------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent
PYTHON_DIR = REPO_ROOT / "platform" / "devsecops" / "python"
if str(PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_DIR))

from dlp_utils import classify_text, detect_entities, check_data_movement  # type: ignore

# ----------------------------------------------------
# Env + clients
# ----------------------------------------------------
load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_EMBED_MODEL = os.getenv("OPENAI_EMBED_MODEL", "text-embedding-3-small")

PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
PINECONE_INDEX_NAME = os.getenv("PINECONE_INDEX_NAME", "vhc-rag-index")
PINECONE_NAMESPACE = os.getenv("PINECONE_NAMESPACE", "vhc-default")

if not OPENAI_API_KEY:
    st.warning(
        "OPENAI_API_KEY is not set in your environment. "
        "The RAG query will be disabled until you set it."
    )

if not PINECONE_API_KEY:
    st.warning(
        "PINECONE_API_KEY is not set in your environment. "
        "The RAG query will be disabled until you set it."
    )

openai_client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None
pc = Pinecone(api_key=PINECONE_API_KEY) if PINECONE_API_KEY else None
pinecone_index = pc.Index(PINECONE_INDEX_NAME) if pc else None


# ----------------------------------------------------
# Helpers
# ----------------------------------------------------
def embed_text(text: str) -> List[float]:
    if not openai_client:
        raise RuntimeError("OPENAI_API_KEY not configured")

    resp = openai_client.embeddings.create(
        model=OPENAI_EMBED_MODEL,
        input=[text],
    )
    return resp.data[0].embedding


def query_rag(prompt: str, top_k: int = 5) -> List[Dict[str, Any]]:
    if not pinecone_index:
        raise RuntimeError("Pinecone is not configured")

    vec = embed_text(prompt)
    result = pinecone_index.query(
        namespace=PINECONE_NAMESPACE,
        vector=vec,
        top_k=top_k,
        include_metadata=True,
    )
    matches = []
    for m in result.matches:
        matches.append(
            {
                "id": m.id,
                "score": m.score,
                "metadata": getattr(m, "metadata", {}) or {},
            }
        )
    return matches


def simulate_flow(
    src: str, dst: str, classification_label: str
) -> Dict[str, Any]:
    """
    Use your existing dlp_utils.check_data_movement to evaluate hops.
    """
    state = {
        "classification_label": classification_label,
        "policy_decision": {"action": "allow"},
        "redaction_applied": False,
    }
    try:
        decision = check_data_movement(src, dst, state)
    except Exception as e:
        return {"allow": False, "reason": f"OPA error: {e}"}

    return decision


# ----------------------------------------------------
# Streamlit UI
# ----------------------------------------------------
st.set_page_config(
    page_title="GenAI DLP Gateway – RAG Demo",
    layout="wide",
)

st.title("🔐 GenAI DLP Gateway – RAG Visibility Demo")
st.caption(
    "End-to-end view of: user prompt → DLP classification → data-movement policies "
    "→ RAG (Pinecone) retrieval."
)

with st.sidebar:
    st.header("⚙️ Runtime context")
    st.markdown(f"- **Pinecone index**: `{PINECONE_INDEX_NAME}`")
    st.markdown(f"- **Namespace**: `{PINECONE_NAMESPACE}`")
    st.markdown(f"- **Embed model**: `{OPENAI_EMBED_MODEL}`")
    st.markdown(
        "- **DLP engine**: `dlp_utils.classify_text / detect_entities / check_data_movement`"
    )

st.subheader("1️⃣ Enter a prompt")

default_prompt = "Schedule a limo in LA tomorrow for 4 people at 7pm."
user_prompt = st.text_area(
    "Prompt (this will go through the DLP gateway before any RAG access)",
    value=default_prompt,
    height=140,
)

run_demo = st.button("Run DLP + RAG flow")

if run_demo:
    if not user_prompt.strip():
        st.error("Prompt cannot be empty.")
        st.stop()

    with st.spinner("Running DLP classification and policy checks..."):
        # ---------------- DLP classification ----------------
        classification_label = classify_text(user_prompt)
        entities = detect_entities(user_prompt)

        # ---------------- Data movement hops ----------------
        hops = [
            ("user", "dlp_gateway", "User → DLP Gateway"),
            ("dlp_gateway", "rag_orchestrator", "DLP → RAG orchestrator"),
            ("rag_orchestrator", "pinecone", "RAG orchestrator → Pinecone"),
        ]

        hop_results = []
        all_to_pinecone_allowed = True

        for src, dst, label in hops:
            decision = simulate_flow(src, dst, classification_label)
            allow = bool(decision.get("allow", False))
            if not allow:
                all_to_pinecone_allowed = False
            hop_results.append(
                {
                    "src": src,
                    "dst": dst,
                    "label": label,
                    "allow": allow,
                    "reason": decision.get("reason", "no reason provided"),
                }
            )

    # ---------------- UI: DLP results ----------------
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 🧬 DLP classification")
        st.write(f"**Label:** `{classification_label}`")
        if entities:
            st.write("**Detected entities:**")
            st.json(entities)
        else:
            st.write("_No entities detected by classifier._")

    with col2:
        st.markdown("### 🔀 Data movement decisions")

        for hop in hop_results:
            color = "✅" if hop["allow"] else "⛔"
            st.markdown(f"**{color} {hop['label']}**")
            st.write(f"- allow: `{hop['allow']}`")
            st.write(f"- reason: `{hop['reason']}`")
            st.markdown("---")

    # ---------------- UI: RAG retrieval ----------------
    st.markdown("### 2️⃣ RAG retrieval (Pinecone)")

    if not all_to_pinecone_allowed:
        st.warning(
            "Policy blocked at least one hop in the chain to Pinecone. "
            "RAG query is **not** executed for this prompt."
        )
    elif not (openai_client and pinecone_index):
        st.warning(
            "OpenAI and/or Pinecone are not fully configured. "
            "Set `OPENAI_API_KEY` and `PINECONE_API_KEY` to enable RAG."
        )
    else:
        with st.spinner("Querying Pinecone with DLP-approved prompt..."):
            try:
                matches = query_rag(user_prompt, top_k=5)
            except Exception as e:
                st.error(f"Error querying Pinecone: {e}")
                matches = []

        if not matches:
            st.info("No RAG matches returned from Pinecone.")
        else:
            st.success(f"Retrieved {len(matches)} RAG matches from Pinecone.")
            for m in matches:
                st.markdown(f"**Vector ID:** `{m['id']}` · Score: `{m['score']:.4f}`")
                meta = m.get("metadata") or {}
                if meta:
                    st.json(meta)
                else:
                    st.write("_No metadata on this vector._")
                st.markdown("---")
