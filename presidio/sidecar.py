# SPDX-License-Identifier: Apache-2.0
"""
memory-guard Presidio sidecar — the out-of-process half of the Presidio-backed Detector
(task 007, ADR-009).

This script is the THIRD-PARTY surface kept entirely OUT of the Go binary: it loads the
Presidio AnalyzerEngine (spaCy NER + Presidio's pattern recognizers) ONCE at startup
(a warm process — model load is a one-time cold-start cost, NOT a per-call cost), then
serves newline-delimited JSON requests over stdin/stdout. The Go side (detector_presidio.go)
spawns it, keeps it warm, and speaks the protocol below behind the unchanged Detector seam.

Protocol (newline-delimited JSON, one request per line, one response per line):

  request : {"op":"analyze","text":"<text>"}
  response: {"entities":[{"type":"<PRESIDIO_ENTITY>","start":<int>,"end":<int>,"score":<float>}], ...}
  request : {"op":"ping"}
  response: {"ok":true}

On a malformed request the sidecar replies {"error":"<reason>"} and keeps serving.
The sidecar performs NO outbound network I/O at runtime (the spaCy model is local, pinned,
and installed offline). Only the BASE presidio-analyzer/anonymizer packages are required —
NO azure/openai/transformers/gliner/stanza extras (those carry the credential-reading code
this deployment deliberately never installs; see ADR-009 / docs/spec/configuration.md).

Pinned (recorded in ADR-009 + docs/spec/configuration.md):
  presidio-analyzer == 2.2.362
  presidio-anonymizer == 2.2.362
  spacy             == 3.8.14
  en_core_web_lg    == 3.8.0
"""
import json
import sys


def main() -> int:
    # Import inside main so a --selftest of argv parsing is cheap and import errors are
    # reported on the protocol channel (stdout) rather than crashing silently.
    try:
        from presidio_analyzer import AnalyzerEngine
    except Exception as exc:  # pragma: no cover - exercised only when deps are absent
        sys.stdout.write(json.dumps({"error": f"presidio import failed: {exc}"}) + "\n")
        sys.stdout.flush()
        return 1

    # Warm the engine ONCE: this is the cold-start cost (spaCy model load), paid here at
    # startup and never again on the per-call hot path.
    analyzer = AnalyzerEngine()

    # Signal readiness so the Go client can block until the model is loaded before timing
    # steady-state latency (cold-start is excluded from the measurement, per TC-003).
    sys.stdout.write(json.dumps({"ready": True}) + "\n")
    sys.stdout.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as exc:
            _reply({"error": f"bad json: {exc}"})
            continue

        op = req.get("op")
        if op == "ping":
            _reply({"ok": True})
            continue
        if op != "analyze":
            _reply({"error": f"unknown op: {op!r}"})
            continue

        text = req.get("text", "")
        if not isinstance(text, str):
            _reply({"error": "text must be a string"})
            continue

        try:
            results = analyzer.analyze(text=text, language="en")
        except Exception as exc:  # keep the process alive on a single bad input
            _reply({"error": f"analyze failed: {exc}"})
            continue

        entities = [
            {
                "type": r.entity_type,
                "start": r.start,
                "end": r.end,
                "score": round(float(r.score), 4),
            }
            for r in results
        ]
        _reply({"entities": entities})

    return 0


def _reply(obj) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    raise SystemExit(main())
