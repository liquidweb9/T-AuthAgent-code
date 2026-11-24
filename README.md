# T-AuthAgent research prototype

T-AuthAgent verifies a single-use approval certificate at the tool gateway after Progent identifies a policy expansion. This directory contains the v3 research implementation, local evaluation modules, and the recorded CSV data used in the paper. Progent is described in [Securing AI Agents with Privilege Control](https://arxiv.org/abs/2504.11703).

The paper analyzes threshold BLS. The recorded implementation uses a research Schnorr/secp256k1 backend with a public-message-derived signing nonce. Its measurements characterize workflow behavior and implementation cost. This backend does not meet the unforgeability assumption of the formal construction.

## Local setup

Run from the repository root with Python 3.11 in a fresh virtual environment.

```shell
python -m pip install -r requirements.txt
python -m pytest progent/secagent/auth/tests
python -m experiments.risk_validation --out-dir runs/risk
python -m experiments.latency --t 3 --n 5 --out-dir runs/latency
```

The local evaluation modules operate on deterministic fixtures. Use the module's `--help` for thresholds, sample counts and output options. Write new runs outside the historical data directory.

## Contents

- `progent/secagent/` contains the Progent policy runtime and proxy integration. The installable package is defined by `progent/pyproject.toml`. The optional MCP proxy has additional service dependencies.
- `progent/secagent/auth/` contains the certificate format, threshold backend, committee, catalog, gateway, replay store, and unit tests.
- `experiments/` contains local evaluations of threshold behavior, timing, risk selection, replay storage, retries, and approval workflow.
- `experiments/out/` contains the recorded v3 evaluation inputs for analysis, including per-trial outcomes, summary CSVs, and platform metadata. The main conformance matrix and real-model sensitivity run are supplied as recorded data. The latter is in `real_llm/`.

The aggregate and per-trial values belong to the recorded backend. No BLS measurements are included.
