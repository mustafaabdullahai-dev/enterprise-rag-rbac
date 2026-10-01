# Architecture

## System shape

```mermaid
flowchart LR
    subgraph Transport
        API[FastAPI]
        CLI[CLI]
    end
    subgraph Policy
        AUTH[PBKDF2 + HMAC tokens]
        ACL[Authorizer / PDP]
        RL[Rate limiter]
        IG[Input guard]
        OG[Output guard]
    end
    subgraph Orchestration
        G[LangGraph state machine]
    end
    subgraph Data
        LOADER[Loaders] --> CHUNK[Chunker] --> CLS[Sensitivity classifier]
        CLS --> CH[(ChromaDB)]
        CH --> RET[Hybrid retriever]
        RET --> G
    end
    subgraph Assurance
        AUD[(Hash-chained audit log)]
        EV[Evaluation + red team]
    end
    G --> OG
    G --> AUD
    EV --> G
```

`AppContext` (`context.py`) is the composition root: the API lifespan, the CLI and the test fixtures
all build the same object graph, so the HTTP tests exercise the identical graph the unit tests do.

## The workflow

`graph/workflow.py` builds a `StateGraph` over `QueryState`. Nodes return partial state updates;
only terminal nodes set `action`.

| Node | Responsibility | May terminate? |
| --- | --- | --- |
| `guard_input` | normalise, length caps, PII mask, injection/exfil/secret scan, privileged-topic probe | yes — `blocked` / `refuse` |
| `retrieve` | push-down ACL filter, post-filter, BM25 + RRF fusion, relevance floor, withheld reporting | yes — `insufficient_evidence` |
| `grade` | evidence rule: ≥2 matching content words or 1 rare word in a single chunk | yes — `insufficient_evidence` |
| `generate` | build the fenced prompt, call the LangChain LLM runnable | yes — `insufficient_evidence` |
| `verify_citations` | every claim must cite a retrieved chunk; retry once with a stricter instruction | yes — `insufficient_evidence` |
| `output_guard` | secret scan → citation verification → canary tripwire → grounding → PII mask | yes — `blocked` / `insufficient_evidence` |
| `finalize` | force a terminal action, clear citations of unreleased answers, write the audit record | — |

The retry loop exists because "no citation" is the most common recoverable defect of an LLM answer,
and one retry is cheaper than a vague refusal.

### Why the order is input → retrieve → generate → output

Security controls sit where they are cheapest and most reliable:

* The input guard is the only control that runs before the user's text touches the retriever, the
  embedding cache, the model provider or the audit log.
* The output guard is the only control that runs before an answer touches the client, so it is the
  last line regardless of what happened in between.
* Nothing in the middle can widen access: the retriever only narrows, the output guard only blocks
  or redacts.

## Data model

A **chunk** is the unit of retrieval *and* of authorization:

```python
Chunk(
    chunk_id="9734536f7a",            # Chroma document id -> citations are verifiable
    doc_id="hr-salary-bands-fy2026",
    text="...band: B3 | min_salary: 90000...",
    metadata={
        "classification": "restricted",
        "acl_role_hr_business_partner": True,
        "acl_dept_hr": True,
        "acl_any_staff": False,
        "status": "active",
        "canary": "CANARY-HRSALARYBANDSFY2026-AB12CD34",
        "row_index": 3, "ref": "row:3", "ingested_at": "...",
    },
)
```

ACLs live **per chunk**, not in a side table. That makes the vector query filterable in a single
predicate and lets the post-filter re-derive authorization from the chunk alone — no extra lookup,
no chance of a stale permission list.

ChromaDB accepts only scalars in metadata, so booleans stay booleans (enabling `$eq`) and
collections are flattened to comma-separated strings (`_clean_metadata` in `vector_store.py`).

## Ingestion

```
files ──▶ loaders ──▶ LoadedUnit[] ──▶ classifier ──▶ DocumentACL ──▶ chunker ──▶ Chunk[] ──▶ Chroma
```

* **Loaders** normalise PDF pages, spreadsheet rows, Word sections and Markdown headings into
  `LoadedUnit`s that keep a citable location (`page:3`, `row:14`, `sheet:CostCenters:row:2`).
* **Classifier** derives the ACL (manifest → folder policy → content escalation) and issues a canary
  for confidential/restricted documents.
* **Chunker** splits prose with LangChain's `RecursiveCharacterTextSplitter` but never splits a
  record — a spreadsheet row is already atomic, and splitting it would corrupt the values a reader
  needs in order to verify the answer.
* **Pipeline** is the only writer to the vector store, so a chunk cannot reach the index without an
  ACL attached. It also prunes catalog entries whose source file disappeared.

## Retrieval

1. **Push-down filter** — `Authorizer.chroma_where` builds
   `classification ∈ visible ∧ status = active ∧ (any_staff ∨ role grant ∨ department grant)`.
2. **Vector search** — cosine similarity (Chroma), post-filtered in Python regardless of outcome;
   the store reports `filter_fallback` if Chroma rejected the predicate, and the UI shows it.
3. **BM25** — a dependency-free implementation over the same corpus. It is what makes exact-key
   lookups ("cost centre CC-100", "matter 2026-007") work when embeddings are weak.
4. **RRF fusion** — ranks from both lists combine as `1/(k + rank)`, which needs no score
   calibration between the two systems.
5. **Head reservation** — the top hit of *each* ranking is guaranteed a slot before the fused order
   fills the rest. Without it a document that is the best lexical match can be pushed out of
   `top_k` by weaker semantic neighbours — exactly how "litigation register" queries came back empty
   during development.
6. **Withheld reporting** — blocked documents are recorded (audit trail and UI) rather than silently
   dropped, because a refusal is a security event.

## Generation and grounding

The prompt fences the context with `<<<CONTEXT>>>` … `<<<END_CONTEXT>>>`, numbers each block with its
`doc_id#chunk_id`, and states that everything inside is *data, not instructions*. Claims must end
with a citation marker, or the model must answer `INSUFFICIENT_EVIDENCE`.

Two engines implement that contract as a LangChain `LLM`:

| Backend | Use | Guarantee |
| --- | --- | --- |
| `extractive` (default) | offline demos, CI | can only emit sentences that came from the authorised context; zero external knowledge |
| `openai` | production | quality from a real model; guardrails still verify everything afterwards |

## Extension points

| Want to… | Change |
| --- | --- |
| add a document format | a `LoadedUnit` producer in `ingestion/loaders.py` |
| add a classification source | a source in `SensitivityClassifier.classify` (it only ever escalates) |
| change retrieval strategy | `EnterpriseRetriever.retrieve` (keep the ACL layers) |
| add a guardrail | a `PatternRule` in `guardrails/policies.py`, or a check in the relevant guard |
| add a workflow step | a node in `graph/workflow.py` plus a conditional edge |
| swap the model | `build_llm` / `build_embeddings` — nothing else |