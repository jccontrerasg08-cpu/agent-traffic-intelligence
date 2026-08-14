# Evaluation and Dataset Plan

## Labels

Maintain both `label` and `label_confidence`/`label_source`.

Strong labels can come from controlled traffic generation or verifiable provider identity. User-Agent-only labels are weak because they are spoofable.

## Controlled generators

Generate authorized lab traffic from:

- browsers used manually;
- curl/wget;
- Python `requests`, `httpx`, and `aiohttp`;
- Scrapy;
- Playwright, Selenium, and Puppeteer;
- known provider crawlers observed on owned infrastructure when identity can be validated.

## Leakage controls

Do not randomly split requests from the same session/client across train and test. Minimum evaluation suites should include:

1. grouped session/client split;
2. temporal holdout;
3. unseen automation-family holdout;
4. provider/UA ablation to test whether the model learned behavior instead of memorizing names.

## Metrics

Primary metrics:

- bot precision and recall;
- PR-AUC;
- false-positive rate on human traffic;
- false-negative rate;
- calibration error / reliability plots;
- latency and memory at the chosen operating threshold.

Accuracy alone is not a useful headline metric on imbalanced traffic.
