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
| captum | BSD-3-Clause | Integrated Gradients explanations |
| shap | MIT | TreeSHAP on the flow-level pre-filter |
| streamlit | Apache-2.0 | Offline demo app |
| altair | BSD-3-Clause | Charts in the app (no CDN at runtime) |
| matplotlib | PSF-based (matplotlib licence) | Evaluation plots |
| PyYAML | MIT | Config files |
| jsonschema | MIT | Prediction-object validation |
| scapy | GPL-2.0-only¹ | Packet-level feature extraction (fallback path) |
| pyshark | MIT | Packet-level feature extraction (tshark path; requires a local Wireshark/tshark install) |
| pyarrow | Apache-2.0 | Columnar interim storage |
| tqdm | MPL-2.0 + MIT | Progress bars |
| pytest | MIT | Test harness |

¹ scapy is GPL-2.0. It is used as an optional, unmodified, dynamically imported
tool invoked at data-preparation time; it is not linked into or distributed with
the Apache-2.0 source. If distribution requirements change, drop the scapy
fallback and require tshark.
