# Third-party notices

This project (Apache-2.0) builds on the following third-party software and data.
Keep this file in sync with `requirements.txt` — adding a dependency without a row
here fails review.

## Dataset

| Resource | Source | Licence / terms | Use |
|---|---|---|---|
| CSE-CIC-IDS2018 | Canadian Institute for Cybersecurity, University of New Brunswick — `s3://cse-cic-ids2018` (AWS Open Data) | Free for research with citation: Sharafaldin, Lashkari, Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization", ICISSP 2018 | Training/evaluation data; a 1,000-row excerpt is committed as `tests/fixtures/mini.csv` |

## Python dependencies

Exact pinned versions live in `requirements.txt` / `environment.lock.yml`.

| Package | Licence | Use |
|---|---|---|
| numpy | BSD-3-Clause | Numeric arrays |
| pandas | BSD-3-Clause | Flow CSV handling |
| scipy | BSD-3-Clause | scikit-learn dependency |
| scikit-learn | BSD-3-Clause | Logistic-regression baseline, scalers, metrics |
| torch | BSD-3-Clause | Deep models (TGN, GRAFT, RSSM) |
| torch-geometric | MIT | Temporal graph network |
| xgboost | Apache-2.0 | Baseline model |
| captum | BSD-3-Clause | Pinned but not currently imported — the shipped explainer is TreeSHAP (shap); kept as an alternative gradient-based explainer |
| shap | MIT | TreeSHAP named-feature attributions on the deployed model (`engine/explain.py`) |
| streamlit | Apache-2.0 | Offline demo app |
| plotly | MIT | Interactive 3D network-graph panel (rendered by st.plotly_chart, which serves plotly.js from Streamlit's bundled assets — no CDN) |
| altair | BSD-3-Clause | Transitive Streamlit dependency; the app renders charts with matplotlib (server-side, no CDN), not altair |
| matplotlib | PSF-based (matplotlib licence) | Evaluation plots |
| PyYAML | MIT | Config files |
| jsonschema | MIT | Prediction-object validation |
| scapy | GPL-2.0-only¹ | Packet parsing + the inline retransmission heuristic (default backend) |
| pyshark | MIT | Pinned but not currently imported — see ² |
| pyarrow | Apache-2.0 | Columnar interim storage |
| tqdm | MPL-2.0 + MIT | Transitive dependency; not imported by project code |
| pytest | MIT | Test harness |

## External tools (not Python packages)

| Tool | Licence | Use |
|---|---|---|
| tshark (Wireshark CLI) | GPL-2.0 | Ground-truth retransmission backend (M2.2), invoked as an unmodified external subprocess by `data/packet_features.py` when `retransmission_backend: tshark` and Wireshark is installed. Not bundled. |
| AWS CLI (awscli) | Apache-2.0 | `data/download_cic.sh` uses it (via `awscli.clidriver`) to list/sync the public CSE-CIC-IDS2018 bucket at data-prep time. Not required at inference/demo time. |

¹ scapy is GPL-2.0. It parses pcap bytes at data-preparation time as an
unmodified, dynamically imported tool; it is not linked into or distributed with
the Apache-2.0 source. If distribution requirements change, drop the scapy path
and require tshark.

² pyshark is retained as a pinned option but no module imports it — the tshark
backend is a direct subprocess call to the Wireshark CLI (see the table above),
not the pyshark wrapper. Kept for now as a drop-in alternative; remove if it
stays unused through M12.
