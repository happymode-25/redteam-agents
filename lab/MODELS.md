# Local-model variants for CPU-only hosts (Phase 4 findings)

This host has no GPU: Ollama runs a 7B model at ~1.8 tok/s generation and a
2018-era 4-core CPU processes large prompts slowly. Two changes make the
pipeline viable here, both config-only:

1. **Bigger context.** Ollama defaults to num_ctx 4096; the agent system
   prompt (role prompt + compact tool list) is ~2.1k tokens and the
   conversation grows past that within a step or two. Create variants with
   16384 context:

   ```
   ollama create qwen2.5-16k    -f lab/Modelfile.qwen2.5-16k
   ollama create qwencoder3b-16k -f lab/Modelfile.qwencoder3b-16k
   ```

2. **Role split + bounded generation** (in config.yaml, gitignored — copy
   the pattern from your own hardware, don't blindly trust these numbers):

   | Role | Backend slot | Model | Rationale |
   |---|---|---|---|
   | planner, analyst, reporter | `local` | qwen2.5-16k (7B) | reasoning-heavy |
   | recon, exploit | `hosted` | qwencoder3b-16k (3B) | high-volume, smaller outputs |
   | every provider | — | `max_tokens: 640`, `timeout: 900` | bounds each call to ~6 min on 7B / ~2-3 min on 3B |

   The "hosted" slot being pointed at a second local model is legitimate —
   the backend layer is generic OpenAI-compatible HTTP; when real hosted
   credentials exist, point the slot back at the API and keep the role map.

Expected wall-clock on this hardware for a full 5-agent lab run: roughly
1.5–3 hours (planner/analyst/reporter dominate). With a GPU or hosted keys,
the same config pattern maps straight to fast models.
