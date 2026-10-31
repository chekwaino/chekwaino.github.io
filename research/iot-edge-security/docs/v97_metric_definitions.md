# v97 dashboard metrics — exact definitions and evidential boundaries

Raised by the external audit of the v97 patch: the dashboard tiles FDSS / DFDI / FLS /
ASCS / AIS are **simplified in-script proxies**, and renaming them (patch V5) is not
enough — their definitions and limits must be stated in the preprocessing report and
the thesis. This document is that statement.

## What each tile actually computes (per the v97 source)

| Tile | Definition in the script | What it can evidence | What it cannot evidence |
|------|--------------------------|----------------------|-------------------------|
| **FDSS** | Maximum Jensen–Shannon divergence of the label distribution between validation and test shards (train↔shard comparisons included in the reported max) | Gross distributional shift between splits (a leak *alarm*, not proof) | That no feature leakage occurred — JS over labels says nothing about feature-level leakage; a leak can exist with identical label distributions |
| **DFDI** | Constant `0` when `SCIENTIFIC_LEAKAGE_SAFE=True` | Only that the flag was on — it is a *configuration echo*, not a measurement | Any independent evidence of leakage absence |
| **FLS** | Constant `0` when `SCIENTIFIC_LEAKAGE_SAFE=True` | Same as DFDI — configuration echo | Any independent evidence |
| **ASCS** | `max(0, 1 − FDSS)` | A monotone rescaling of FDSS (attack-consistency *proxy*) | Independent attack-consistency evidence — it is a function of FDSS alone |
| **AIS** | `max(0, 1 − FDSS)` | A rescaling of FDSS presented as an invariance score | Independent invariance evidence — identical to ASCS by construction |

## Consequences for the thesis

1. FDSS/DFDI/FLS/ASCS/AIS must be reported as **"label-distribution drift proxies"**,
   not as the published FDSS/DFDI/FLS/ASCS/AIS metrics from the literature. The patcher
   (V5) marks the tiles with `*` for exactly this reason.
2. The *actual* leakage control in v97 is structural, not statistical: identifier
   columns (MAC/IP/stream/http/tls identity fields and their aggregates) are excluded
   from all scientific X views, identifiers are stored separately under SHA-256 hashed
   keys, and splits are driven by feature-only row hashes so duplicates cannot cross
   splits. That is what the leakage claim should rest on (plus the DH-A…DH-H diagnostic
   gates), with FDSS as a drift alarm only.
3. DFDI/FLS reading exactly 0 whenever `SCIENTIFIC_LEAKAGE_SAFE` is on means those two
   tiles carry no information in default runs; say so explicitly rather than reporting
   them as passed checks.
4. ASCS and AIS are both `1 − FDSS`, so they are perfectly correlated; never present them
   as two independent confirmations.

## Recommended wording for the report

> "Split-drift was monitored with a Jensen–Shannon divergence proxy over label
> distributions (FDSS), reported alongside structural leakage controls (identifier
> exclusion, hashed identifier metadata, feature-only-hash splitting). The dashboard
> tiles DFDI/FLS/ASCS/AIS are in-script rescalings or configuration echoes of FDSS and
> the leakage-safe flag, and are not independent leakage or consistency metrics."
