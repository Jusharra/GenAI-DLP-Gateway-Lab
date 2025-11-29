import json
import os
import sys
from pathlib import Path
from typing import List, Dict, Any

# --- Force Python to use the repo's dlp_utils.py ---
ROOT = Path(__file__).resolve().parent
DLP_PATH = ROOT / "platform" / "devsecops" / "python"

# Put our path at the front so it's searched first
sys.path.insert(0, str(DLP_PATH))

# If dlp_utils was already imported from somewhere else, drop it
if "dlp_utils" in sys.modules:
    del sys.modules["dlp_utils"]

import dlp_utils  # now guaranteed to come from DLP_PATH
print("dlp_utils loaded from:", dlp_utils.__file__)  # sanity check in terminal

from dlp_utils import classify_text, detect_entities, check_data_movement

import streamlit as st
from dotenv import load_dotenv
from openai import OpenAI
from pinecone import Pinecone, ServerlessSpec

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
    Adapter between the friendly labels from classify_text()
    and the strict labels expected by the OPA policy.
    """

    # Normalize what the classifier gives us into what Rego expects
    norm = (classification_label or "").strip().lower()

    if norm in ("phi", "restricted_phi"):
        opa_label = "RESTRICTED_PHI"
    elif norm in ("restricted_pii", "pii"):
        opa_label = "RESTRICTED_PII"
    elif norm in ("internal",):
        opa_label = "INTERNAL"
    else:
        # Failsafe – treat unknown labels as INTERNAL
        opa_label = "INTERNAL"

    state = {
        "classification_label": opa_label,
        "policy_decision": {"action": "allow"},
        "redaction_applied": False,
    }

    try:
        decision = check_data_movement(src, dst, state)
    except Exception as e:
        return {"allow": False, "reason": f"OPA error: {e}"}

    return decision


def summarize_rag_results(prompt: str, matches: List[Dict[str, Any]]) -> str:
    """
    Use the retrieved RAG context (ideally ATLAS techniques) to generate a short
    human-readable explanation of *why* these results are relevant.

    If OPENAI_API_KEY is missing, we just fall back to a static message.
    """
    if not matches:
        return "No RAG context retrieved for this prompt."

    if not openai_client:
        return (
            "RAG context was retrieved, but LLM summarization is disabled because "
            "OPENAI_API_KEY is not configured."
        )

    # Build a compact context from the top few matches
    context_chunks = []
    for m in matches[:5]:
        meta = m.get("metadata") or {}
        title = (
            meta.get("title")
            or meta.get("name")
            or meta.get("technique")
            or meta.get("technique_name")
            or meta.get("id")
            or m["id"]
        )
        tactic = meta.get("tactic") or meta.get("tactic_name")
        desc = meta.get("description") or meta.get("summary") or ""

        block = f"ID: {m['id']}\nScore: {m['score']:.3f}\nTitle: {title}\n"
        if tactic:
            block += f"Tactic: {tactic}\n"
        if desc:
            block += f"Description: {desc}\n"
        context_chunks.append(block)

    context_text = "\n\n".join(context_chunks)

    completion = openai_client.chat.completions.create(
        model=os.getenv("OPENAI_CHAT_MODEL", "gpt-4o-mini"),
        messages=[
            {
                "role": "system",
                "content": (
                    "You are an AI security and compliance risk assistant explaining how retrieved "
                    "AI attack / ATLAS Matrix techniques relate to a user's prompt. "
                    "Summarize in 3–4 bullet points, focusing on why these "
                    "techniques are relevant and what they show about risk."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"User prompt:\n{prompt}\n\n"
                    f"Retrieved context (ATLAS/AI attack metadata):\n{context_text}"
                ),
            },
        ],
        temperature=0.2,
    )
    return completion.choices[0].message.content.strip()
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
        # classify_text now returns a dict: {"label": ..., "entities": [...]}
        classification = classify_text(user_prompt)
        classification_label = classification.get("label", "INTERNAL")
        entities = classification.get("entities") or detect_entities(user_prompt)

        # ---------------- Data movement via dlp_utils ----------------
        # Use the same engine you used in your sanity check
        movement = check_data_movement(user_prompt)

        hop_results = []
        all_to_pinecone_allowed = True

        # movement["hops"] is expected to be a list of:
        # { "from": ..., "to": ..., "allow": bool, "reason": "human readable" }
        for hop in movement.get("hops", []):
            allow = bool(hop.get("allow", False))
            if not allow:
                all_to_pinecone_allowed = False

            hop_results.append(
                {
                    "src": hop.get("from"),
                    "dst": hop.get("to"),
                    "label": f"{hop.get('from')} → {hop.get('to')}",
                    "allow": allow,
                    "reason": hop.get("reason", "no reason provided"),
                }
            )

    # ---------------- UI: DLP results ----------------
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 🧬 DLP classification")
        # Show ONLY the label, not the whole dict
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
            # This is now the human-readable reason from OPA / dlp_utils
            st.write(f"- reason: {hop['reason']}")
            st.markdown("---")

    # ---------------- UI: RAG retrieval ----------------
    st.markdown("### 2️⃣ RAG retrieval (Pinecone)")

    if not all_to_pinecone_allowed:
        st.warning(
            f"Policy blocked at least one hop in the chain to Pinecone "
            f"for classification label `{classification_label}`. "
            "RAG query is **not** executed for this prompt. "
            "See data-movement reasons above."
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

            # 🔎 New: AI-generated explanation of *why* these results matter
            st.markdown("**RAG assistant explanation**")
            summary = summarize_rag_results(user_prompt, matches)
            st.write(summary)
            st.markdown("---")

        # Raw matches for auditors
        for m in matches:
            st.markdown(f"**Vector ID:** `{m['id']}` · Score: `{m['score']:.4f}`")
            meta = m.get("metadata") or {}
            if meta:
                st.json(meta)
            else:
                st.write("_No metadata on this vector._")
            st.markdown("---")

            # 3️⃣ AI assistant answer using RAG context
            if openai_client:
                st.markdown("### 3️⃣ AI assistant response")

                # Collect some text from the retrieved vectors
                context_chunks = []
                for m in matches:
                    meta = m.get("metadata") or {}
                    text = (
                        meta.get("content")
                        or meta.get("text")
                        or meta.get("chunk")
                    )
                    if text:
                        context_chunks.append(text)

                context = "\n\n---\n\n".join(context_chunks[:3])  # keep it short

                try:
                    from openai import OpenAI  # already imported at top, but harmless
                    model_name = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

                    system_msg = (
                        "You are a DLP-aware RAG assistant. "
                        "Answer the user's question using ONLY the provided context and ISO/IEC 42001:2023 and ISO 27001. "
                        "If the context is not relevant, say you have insufficient "
                        "information instead of guessing."
                    )

                    user_msg = (
                        f"User prompt:\n{user_prompt}\n\n"
                        f"Relevant context from vector store:\n{context or '[no context available]'}"
                    )

                    resp = openai_client.chat.completions.create(
                        model=model_name,
                        messages=[
                            {"role": "system", "content": system_msg},
                            {"role": "user", "content": user_msg},
                        ],
                        temperature=0.2,
                    )
                    answer = resp.choices[0].message.content
                    st.write(answer)
                except Exception as e:
                    st.error(f"Error generating AI answer: {e}")
           # ---------------- UI: Evidence snapshot (optional) ----------------
                evidence_path = ROOT / "platform" / "evidence" / "evidence_unified.json"
                if evidence_path.exists():
                    st.markdown("### 3️⃣ Evidence snapshot for GRC")
                    st.caption(
                        "Mapped unified controls with OPA policies and Checkov checks "
                        "(showing a small subset for demo)."
                    )

                    # Resolve path relative to this file, not the working directory
                    APP_ROOT = Path(__file__).resolve().parent
                    EVIDENCE_PATH = APP_ROOT / "platform" / "evidence" / "evidence_unified.json"

                    evidence = None
                    try:
                        if EVIDENCE_PATH.exists():
                            with EVIDENCE_PATH.open("r", encoding="utf-8") as f:
                                evidence = json.load(f)
                    except Exception:
                        # If anything goes wrong reading/parsing, we'll fall back to the info banner
                        evidence = None

                    controls = (evidence or {}).get("controls") or []

                    if not controls:
                        st.info(
                            "Run the CI pipeline to generate unified evidence before demoing this section."
                        )
                    else:
                        # If you only want to show a subset, slice here
                        st.json(controls[:10])
