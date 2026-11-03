# SentinelAI - AI SOC Assistant

An AI-assisted SOC investigation platform: ingests security logs, normalizes them,
runs deterministic detections, correlates alerts into incidents, and uses an LLM
(with RAG over playbooks) to produce evidence-grounded summaries.
The analyst always makes the final decision.

**Status:** work in progress. Uses synthetic log data only.

## Progress
- [x] Normalized event model
- [x] Linux auth log parser + tests
- [ ] Detection engine
- [ ] Incident correlation
- [ ] RAG + AI analysis
- [ ] Dashboard
