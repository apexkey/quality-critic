"""
APEX KEY — SYSTEM A | QA CRITIC — qa_agent.py
--------------------------------------------------------------------
ROLE: validation / inspection. NO approval authority. Produces `validation_status`.
Tasks:
  1. Score the artifact with LLM-as-a-Judge (weighted F/C/L minus hallucination).
  2. Compute Δ variance (expected vs actual from sandbox).
  3. Static red-team check (secret/danger pattern scan on the actual code).
  4. Pass -> route to CEO governance (ready-for-approval); fail -> feedback to CTO.
"""
import os
import json
import hashlib
import requests

SUPA_URL = os.environ["SUPABASE_URL"]
SUPA_KEY = os.environ["SUPABASE_SERVICE_KEY"]
GROQ = os.environ.get("GROQ_API_KEY")
CEREBRAS = os.environ.get("CEREBRAS_API_KEY")
OPENROUTER = os.environ.get("OPENROUTER_API_KEY")
TRACE_ID = os.environ["TRACE_ID"]
WORKSPACE_ID = os.environ["WORKSPACE_ID"]
TENANT = os.environ.get("TENANT", "kernel")
SHA256 = os.environ["SHA256"]
EXIT_CODE = int(os.environ.get("EXIT_CODE", "-1"))
STDOUT = os.environ.get("STDOUT", "")
STDERR = os.environ.get("STDERR", "")
STEP = os.environ.get("STEP", "qa")

HEADERS = {
    "apikey": SUPA_KEY,
    "authorization": f"Bearer {SUPA_KEY}",
    "content-type": "application/json",
}

# Weighted quality model   Q = (Wf*F)+(Wc*C)+(Wl*L) - P_hallucination
WF, WC, WL, PENALTY = 0.45, 0.35, 0.20, 0.15


def llm(system, user, max_tokens=400):
    providers = []
    if GROQ:
        providers.append(("groq", GROQ, "https://api.groq.com/openai/v1/chat/completions", "llama-3.3-70b-versatile"))
    if CEREBRAS:
        providers.append(("cerebras", CEREBRAS, "https://api.cerebras.ai/v1/chat/completions", "llama-3.3-70b"))
    if OPENROUTER:
        providers.append(("openrouter", OPENROUTER, "https://openrouter.ai/api/v1/chat/completions", "deepseek/deepseek-chat"))
    last = None
    for name, key, url, model in providers:
        r = requests.post(url, headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                          json={"model": model, "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                                "max_tokens": max_tokens, "temperature": 0.0}, timeout=90)
        if r.ok:
            return r.json()["choices"][0]["message"]["content"], name
        last = f"{name}:{r.status_code}"
    raise RuntimeError(f"all providers failed: {last}")


def fetch_artifact():
    r = requests.get(f"{SUPA_URL}/rest/v1/build_artifacts", params={"sha256": f"eq.{SHA256}", "select": "*", "limit": "1"}, headers=HEADERS, timeout=30)
    return r.json()[0] if r.ok and r.json() else None


def static_scan(code):
    """Deterministic (Law: decisions must be deterministic, not from memory)."""
    secrets = ["api_key", "BEGIN PRIVATE KEY", "AKIA", "password=", "secret="]
    danger = ["os.system", "subprocess", "eval(", "exec(", "base64.b64decode", "__import__"]
    s_hits = [w for w in secrets if w.lower() in code.lower()]
    d_hits = [w for w in danger if w in code.lower()]
    return {"secrets": s_hits, "danger": d_hits}


def judge(artifact, run_meta):
    system = (
        "You are the QA Critic (pessimist) for Apex Key System A. You score "
        "generated code objectively. Return strict JSON: {\"F\":0-1,\"C\":0-1,\"L\":0-1,\"P\":0-1}"
        " where F=factuality/correctness, C=business-logic compliance, L=format/structure, "
        "P=hallucination penalty (0=none ... 1=severe). Be adversarial & conservative."
    )
    user = (
        f"CODE:\n{artifact['code'][:3000]}\n\n"
        f"RUN stdout:\n{run_meta['stdout'][:1500]}\n"
        f"RUN stderr:\n{run_meta['stderr'][:1500]}\n"
        f"RUN exit_code: {EXIT_CODE}\n"
        f"Score strictly as JSON."
    )
    txt, provider = llm(system, user)
    # Robust parse (may include prose around JSON)
    s = txt.find("{"); e = txt.rfind("}")
    return json.loads(txt[s:e+1]) if s >= 0 and e >= s else {"F": 0, "C": 0, "L": 0, "P": 1}, provider


def main():
    print(json.dumps({"qa": "boot", "trace": TRACE_ID, "sha": SHA256}))
    art = fetch_artifact()
    if not art:
        print(json.dumps({"qa": "error", "detail": "artifact missing"}))
        return
    run_meta = {"stdout": STDOUT, "stderr": STDERR, "exit_code": EXIT_CODE}

    # 1) Static deterministic scan first (cheap gate)
    scan = static_scan(art["code"])

    # 2) LLM-as-a-judge (F/C/L/P)
    scores, provider = judge(art, run_meta)
    Q = (WF * scores["F"]) + (WC * scores["C"]) + (WL * scores["L"]) - (PENALTY * scores["P"])
    Q = round(max(0.0, min(1.0, Q)), 3)

    # 3) Δ variance engine (expected success: exit 0, no danger)
    delta = 1.0 if EXIT_CODE == 0 else -1.0

    passed = (EXIT_CODE == 0) and (Q >= 0.60) and (not scan["secrets"]) and (not scan["danger"])
    status = "qa_passed" if passed else "qa_failed"

    # Write validation result
    requests.post(
        f"{SUPA_URL}/rest/v1/agent_executions",
        json={"trace_id": TRACE_ID, "workspace_id": WORKSPACE_ID, "tenant_key": TENANT,
              "agent_id": "qa", "action": "validate", "status": status,
              "output": {"Q": Q, "F": scores["F"], "C": scores["C"], "L": scores["L"], "P": scores["P"],
                         "delta": delta, "scan": scan, "provider": provider},
              "error": STDERR[:200] if not passed else None},
        headers=HEADERS, timeout=30,
    )

    # Update the job status on the pipeline (parent job if linked)
    # Route: pass -> CEO/governance (ready-for-approval); fail -> CTO feedback.
    # For MVK self-test, we surface the verdict and, if approved-ready, log an
    # approval request for the CEO/Founder (Four-Way Separation is honoured here).
    if passed:
        requests.post(
            f"{SUPA_URL}/rest/v1/governance_approval_queue",
            json={"tenant_key": TENANT, "action_ref": f"artifact:{SHA256}", "action_type": "deploy",
                  "validation_ref": None, "subject": f"self-test artifact {SHA256}",
                  "proposed_delta": {"deploy": True}, "reason": "QA passed, Q=%.3f" % Q,
                  "status": "approval_requested", "requested_by": "qa"},
            headers=HEADERS, timeout=30,
        )

    print(json.dumps({
        "qa": status, "Q": Q, "F": scores["F"], "C": scores["C"], "L": scores["L"],
        "P": scores["P"], "delta": delta, "provider": provider,
        "exec_ok": EXIT_CODE == 0, "scan": scan,
    }))


if __name__ == "__main__":
    main()
