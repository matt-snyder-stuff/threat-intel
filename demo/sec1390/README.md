# SEC1390 End-to-End Detection Demo

Replayable demo block for **The AI Detection Engineer: From Threat Intel to Splunk Detections in Minutes, Not Days**.

This is the demo referenced in the talk slides.

## Files

- `run_agent_demo.py` parses the CyberAv3ngers and TeamPCP source intel, extracts IOCs, writes normalized intel, builds SPL, and creates lookup/seed artifacts.
- `seed_splunk_demo.sh` loads the generated artifacts into a local Splunk Docker container, seeds demo events, and runs validation searches.
- `inputs/` contains the sample advisory inputs used by the demo.
- `spl/` contains generated and proof SPL used in the live walkthrough.

## Quick Replay

```bash
cd demo/sec1390
python3 -m pip install -r requirements.txt
python3 run_agent_demo.py
./seed_splunk_demo.sh
```

The seed script assumes a local Splunk container named `splunk`.

Defaults:

- Splunk auth: `admin:Ch@ngeMe123!`
- HEC token: `security-lab-hec-token`
- Demo index: `demo_threat`
- HEC URL: `https://localhost:8088/services/collector/event`

Override with environment variables:

```bash
export SPLUNK_CONTAINER=splunk
export SPLUNK_AUTH='admin:Ch@ngeMe123!'
export SPLUNK_HEC_TOKEN='security-lab-hec-token'
export SPLUNK_HEC_URL='https://localhost:8088/services/collector/event'
```

## What The Demo Shows

1. Extract IOCs from CyberAv3ngers/Iran PLC activity and TeamPCP CI/CD supply-chain intel.
2. Generate starter and behavior-based SPL.
3. Create lookup/KV payload artifacts.
4. Seed Splunk with deterministic demo events.
5. Validate telemetry readiness before trusting zero-result searches.
6. Attach confidence and review decisions to candidate detections.

## Local Lab Caveat

The demo generates a KV Store payload, but some Apple Silicon Docker setups running Splunk's amd64 image may fail to start KV Store because the embedded `mongod` process exits under emulation. The demo also uses CSV lookups so the replay still works and demonstrates a safe fallback path.
