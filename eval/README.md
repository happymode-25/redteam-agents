# Eval harness

Measures the pipeline against targets with **known ground truth**. Without
this, "the agent found something" is a vibe; with it, every prompt or tool
change is a measurable regression test.

## Flow

1. **Start the lab** (only listens on 127.0.0.1). Two options:

   ```bash
   # (a) Docker-free: a stdlib vulnerable app with 24 planted issues
   #     (ground truth target `lab` in targets.yaml). Needs no containers.
   python lab/vulnserver.py                     # http://127.0.0.1:8000

   # (b) Docker: the fuller Juice Shop fixture (target `juice-shop`)
   docker compose -f lab/docker-compose.yml up -d
   ```

2. **Record a run** — live execution, every tool result and LLM response
   is stored as a cassette:

   ```bash
   python eval/run_eval.py --config config.yaml --target lab --mode record
   ```

3. **Replay offline** — same scorecard, zero network, zero API cost. Use
   this in CI and when iterating on prompts/reporting:

   ```bash
   python eval/run_eval.py --config config.yaml --target juice-shop --mode replay
   ```

Replay is exact-input keyed: if you change a prompt, tool output formatting,
or step counts, cassettes miss and the run scores lower — re-record after
intentional changes. `stats.fixture_misses` in the scorecard tells you how
much drifted.

## Reading the scorecard

- **recall** — ground-truth items matched by some finding. The primary metric.
- **precision_candidate** — findings matching some truth item. "Candidate"
  because unmatched findings aren't automatically false positives: the truth
  file is a floor, not a ceiling. Inspect `false_positive_candidates` by hand.
- **missed_truth** — which truth items nothing matched. Tune truth regexes
  first, then blame the pipeline.
- **stats** — LLM calls, tool calls, fixture hits/misses (cost proxy).

## Quality gates (from ROADMAP.md, Phase 0/1)

- recall ≥ 80% on the unauthenticated golden suite before Phase 1 features
- false-positive candidates ≤ 5% of findings over N runs

## Adding a target

1. Add a service to `lab/docker-compose.yml` (bind to 127.0.0.1).
2. Add an entry to `targets.yaml` with a scope override
   (`allow_private: true` for loopback) and a `truth` list.
3. Truth regexes match against `title + target + evidence` of recorded
   findings — check `artifacts/eval/<target>/findings-*.json` after the
   first run and tighten.

Later targets worth adding: DVWA (classic OWASP coverage), NodeGoat
(auth-flow coverage), a deliberately vulnerable API for Phase 2 IDOR tests.

## What is NOT scored

- Agent narration quality (read the report)
- Safety behavior (that's the adversarial scope suite: redirect chains,
  rebinding probes, private-IP answers — add those as separate tests)
- Anything requiring credentials (Phase 2 adds authenticated truth sets)
