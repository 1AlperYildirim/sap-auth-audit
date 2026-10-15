# sap-auth-audit

[![CI](https://github.com/1AlperYildirim/sap-auth-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/1AlperYildirim/sap-auth-audit/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

Offline SAP S/4HANA & ECC authorization and Basis security audit toolkit written in pure Python (standard library only).

## Özet
`sap-auth-audit`, SAP S/4HANA ve ECC sistemlerinden dışa aktarılan yetkilendirme ve Basis profil tablolarını (`USR02`, `AGR_USERS`, `AGR_AGRS`, `AGR_1251`, `UST04`, `RSPARAM`) çevrimdışı olarak analiz eden sıfır bağımlılıklı bir güvenlik denetim aracıdır.
Görevler Ayrılığı (SoD) çakışmalarını, kritik işlem kodlarını (`S_TCODE`), tehlikeli yetki nesnelerini, kullanıcı yaşam döngüsü zafiyetlerini ve güvenlik profil parametrelerini otomatik olarak tespit eder.
Denetim bulgularını kişi bazlı risk puanlarıyla birlikte etkileşimli HTML raporu (`report.html`), CSV ve JSON çalışma kağıtları olarak üretir.

## Why This Matters
Reviewing **Segregation of Duties (SoD)**, privileged transactions, and Basis security parameters is a foundational responsibility of SAP Security and Basis consultants during internal audits, external IT general controls (ITGC) reviews, and S/4HANA hardening projects. When SAP GRC Access Control is unavailable or a rapid offline assessment is required, consultants extract standard security tables via `SE16N` and `SUIM` to identify toxic access combinations and misconfigured instance parameters.

Live interactive sample report:
**[View Sample HTML Audit Report](https://htmlpreview.github.io/?https://github.com/1AlperYildirim/sap-auth-audit/blob/main/docs/sample-report.html)**

## Quick Start

### Linux / macOS
```bash
./scripts/run_demo.sh

```

### Windows PowerShell

```powershell
.\scripts\run_demo.ps1

```

### Docker

```bash
docker build -t sap-auth-audit .
docker run --rm -v "${PWD}/out:/app/out" sap-auth-audit

```

### Manual CLI Usage

```bash
python -m unittest discover -s tests -q
python -m sapauth --data sample_data --out out --today 2026-10-15 --dormant-days 90

```

## Demo Console Output

```text
================================================================
 SAP AUTHORIZATION & BASIS SECURITY AUDIT  [S4P / 100 / PROD]
 Audit Reference Date: 2026-10-15 | Users Audited: 52
================================================================
 FINDINGS BY SEVERITY
   CRITICAL :  11
   HIGH     :  13
   MEDIUM   :   4
   LOW      :   2
   TOTAL    :  30
----------------------------------------------------------------
 TOP 5 RISKY USERS (SCORE = 10*CRIT + 5*HIGH + 2*MED + 1*LOW)
   RANK  USER          SCORE   CRIT   HIGH    MED    LOW
      1  ESAHIN           40      2      4      0      0
      2  MOZ              40      3      2      0      0
      3  FARSLAN          35      2      3      0      0
      4  SYSTEM           14      0      2      2      0
      5  AYILMAZ          10      1      0      0      0
================================================================

```

## Audit Checks & SAP Standard Tool Mapping

| Check Category | SAP Security Concept | Standard SAP Tools / Reports |
| --- | --- | --- |
| **1. User Lifecycle (`HYG-01`..`05`)** | Standard users (`SAP*`, `EARLYWATCH`, `SAPCPIC`), `SAP_ALL`/`SAP_NEW`, dormant accounts, never-logged-on users, role creep | `SUIM` (`RSUSR003`, `RSUSR200`), `SU01` |
| **2. Critical Transactions (`CA-00`, `TC-*`)** | Wildcard `S_TCODE = *` and high-risk Basis/ABAP/security t-codes (`SM49`, `SE38`, `SM59`, `SCC4`, `RZ10`, `SU01`, `PFCG`, `SE16N`) | `SUIM` (`RSUSR002`), `PFCG` |
| **3. Critical Authorizations (`CA-01`..`08`)** | Field-level `AGR_1251` combinations (`S_DEVELOP` debug/replace, `S_TABU_DIS`, `S_USER_PRO`, `S_USER_GRP`, `S_USER_AGR`, `S_RFC`, `S_BTCH_ADM`, `S_DATASET`) | `SUIM` (`RSUSR005`), `PFCG` |
| **4. Segregation of Duties (`SOD-01`..`11`)** | Cross-role toxic t-code combinations across P2P, O2C, Record-to-Report, and IT/Basis (with composite role expansion) | `SUIM` (`RSUSR002`), SAP GRC Access Control |
| **5. Parameter Baseline (`PARAM-01`..`08`)** | Kernel & instance security parameters (`login/*`, `rsau/enable`, `auth/rfc_authority_check`) | `RZ11`, `RZ10`, report `RSPARAM` |

## Input CSV Schema & SAP Tables

> **Security Warning:** Never commit real customer exports to version control. All data in `sample_data/` is 100% synthetic.

| CSV File | SAP Table / Report | Key Columns Used | How to Export in SAP |
| --- | --- | --- | --- |
| `USR02.csv` | `USR02` | `BNAME, USTYP, UFLAG, TRDAT, ERDAT, GLTGB` | `SE16N` on `USR02` or `SUIM` (`RSUSR200`) |
| `AGR_USERS.csv` | `AGR_USERS` | `AGR_NAME, UNAME, FROM_DAT, TO_DAT` | `SE16N` on `AGR_USERS` |
| `AGR_AGRS.csv` | `AGR_AGRS` | `AGR_NAME, CHILD_AGR` | `SE16N` on `AGR_AGRS` (composite role mapping) |
| `AGR_1251.csv` | `AGR_1251` | `AGR_NAME, OBJECT, AUTH, FIELD, LOW, HIGH, DELETED` | `SE16N` on `AGR_1251` (exclude `DELETED = X`) |
| `UST04.csv` | `UST04` | `BNAME, PROFILE` | `SE16N` on `UST04` |
| `PARAMS.csv` | `RSPARAM` / `RZ11` | `NAME, VALUE` | Execute `SA38` -> `RSPARAM` and export list |

## Extending the JSON Rulebooks

All rule definitions live in `sapauth/rules/` with no code changes required:

* `sapauth/rules/sod_rules.json`: Add business functions (t-code lists) under `"functions"` and conflict pairs under `"rules"`.
* `sapauth/rules/critical_access.json`: Add sensitive transactions to `"critical_tcodes"` or multi-field authorization object checks to `"critical_auths"`.
* `sapauth/rules/param_baseline.json`: Add profile parameters using `"eq"`, `"ge"`, `"le"`, or `"range"` operators.

## Limitations

* **Transaction-Level SoD:** Check 4 evaluates Segregation of Duties at the `S_TCODE` level rather than full authorization object/field level (such as company code/plant organizational levels in SAP GRC Access Control).
* **Illustrative Parameter Baseline:** Check 5 baseline thresholds are illustrative; always align parameter targets with customer security policies and current SAP Security Notes.