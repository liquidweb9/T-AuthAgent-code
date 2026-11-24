"""T-AuthAgent cryptographic approval layer above Progent.

Modules:
    canon         CBOR canonical encoding + H(canon(Req))
    req           Req v2 model (outline.tex def:req)
    cert          Cert dataclass
    threshold_sig Mode B Ed25519 multi-signature
    committee     n-approver simulation with risk-aware (t,n)
    catalog       ApprovalCatalog of (apid, cid, t, n, pk_group)
    gateway       9 pi_j gateway acceptance predicate
    replay_store  consumed-nonce set
    context       per-task ContextVar carrying the pending Cert
    hook_update   tool.py:464 hook -- build Req, call committee, attach Cert
    hook_gateway  tool.py:573 hook -- try gateway acceptance with pending Cert
    fake_llm      SECAGENT_FAKE_LLM offline replacement for api_request
"""
