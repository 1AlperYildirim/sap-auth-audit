# SAP Concept: Synthetic data generator mimicking SE16N/SUIM exports for SID S4P, Client 100, PROD.
"""Generates deterministic synthetic SAP authorization CSV exports into sample_data/."""

import csv
import json
from pathlib import Path
import random
from typing import Dict, List


def generate_sample_data(out_dir: Path | None = None) -> None:
    """Writes deterministic USR02, AGR_USERS, AGR_AGRS, AGR_1251, UST04, PARAMS, and meta.json."""
    rng = random.Random(20261015)
    target = Path(out_dir) if out_dir else Path(__file__).resolve().parent.parent / "sample_data"
    target.mkdir(parents=True, exist_ok=True)

    meta = {"sid": "S4P", "client": "100", "env": "PROD"}
    (target / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    # 1. Define role authorization rows (AGR_1251)
    agr_1251: List[Dict[str, str]] = []

    def add_tcodes(role: str, auth_id: str, tcodes: List[str]) -> None:
        for tc in tcodes:
            agr_1251.append({
                "AGR_NAME": role, "OBJECT": "S_TCODE", "AUTH": auth_id,
                "FIELD": "TCD", "LOW": tc, "HIGH": "", "DELETED": "",
            })

    def add_auth(role: str, obj: str, auth_id: str, fields: Dict[str, str], deleted: str = "") -> None:
        for fld, val in fields.items():
            agr_1251.append({
                "AGR_NAME": role, "OBJECT": obj, "AUTH": auth_id,
                "FIELD": fld, "LOW": val, "HIGH": "", "DELETED": deleted,
            })

    # Clean functional single roles
    add_tcodes("Z_FI_AP_CLERK", "T_FI0100", ["FB60", "MIRO", "FB03"])
    add_tcodes("Z_FI_AP_PAYMENTS", "T_FI0200", ["F110", "F-53", "FBL1N"])
    add_tcodes("Z_FI_VENDOR_MASTER", "T_FI0300", ["XK01", "XK02", "FK01", "XK03"])
    add_tcodes("Z_FI_GL_ACCOUNTANT", "T_FI0400", ["FB50", "FB01", "FS10N"])
    add_tcodes("Z_MM_BUYER", "T_MM0100", ["ME21N", "ME22N", "ME23N"])
    add_tcodes("Z_MM_WAREHOUSE", "T_MM0200", ["MIGO", "MB51", "MMBE"])
    add_tcodes("Z_MM_PO_RELEASE", "T_MM0300", ["ME28", "ME29N"])
    add_tcodes("Z_SD_CLERK", "T_SD0100", ["VA01", "VA02", "VA03", "VL03N"])
    add_tcodes("Z_BASIS_OPERATOR", "T_BC0100", ["SM50", "SM66", "SP01", "ST22"])

    # Planted risky roles
    add_tcodes("Z_SEC_ADMIN", "T_SEC100", ["SU01", "PFCG", "SU53"])
    add_auth("Z_SEC_ADMIN", "S_USER_GRP", "A_SEC101", {"CLASS": "*", "ACTVT": "01"})
    add_auth("Z_SEC_ADMIN", "S_USER_AGR", "A_SEC102", {"ACT_GROUP": "*", "ACTVT": "02"})
    add_auth("Z_SEC_ADMIN", "S_USER_PRO", "A_SEC103", {"PROFILE": "*", "ACTVT": "22"})

    add_tcodes("Z_DEV_PROD", "T_DEV100", ["SE38", "SE80", "STMS"])
    add_auth("Z_DEV_PROD", "S_DEVELOP", "A_DEV101", {"OBJTYPE": "DEBUG", "ACTVT": "02"})

    add_tcodes("Z_SUPPORT_ALL", "T_SUP100", ["*"])

    add_tcodes("Z_BASIS_ADMIN", "T_ADM100", ["SM49", "SM59", "RZ10"])
    add_auth("Z_BASIS_ADMIN", "S_BTCH_ADM", "A_ADM101", {"BTCADMIN": "Y"})
    add_auth("Z_BASIS_ADMIN", "S_RFC", "A_ADM102", {"RFC_NAME": "*", "ACTVT": "16"})
    # One deleted row to verify DELETED=X is ignored
    add_auth("Z_FI_AP_CLERK", "S_TABU_DIS", "A_DEL999", {"DICBERCLS": "*", "ACTVT": "02"}, deleted="X")

    for i in range(1, 15):
        add_tcodes(f"Z_DISP_{i:02d}", f"T_DSP{i:03d}", ["SU53"])

    # 2. Composite roles (AGR_AGRS)
    agr_agrs = [
        {"AGR_NAME": "Z_C_PROCUREMENT", "CHILD_AGR": "Z_MM_BUYER"},
        {"AGR_NAME": "Z_C_PROCUREMENT", "CHILD_AGR": "Z_MM_WAREHOUSE"},
        {"AGR_NAME": "Z_C_PROCUREMENT", "CHILD_AGR": "Z_MM_PO_RELEASE"},
    ]

    # 3. Users (USR02) and Role Assignments (AGR_USERS)
    usr02: List[Dict[str, str]] = []
    agr_users: List[Dict[str, str]] = []
    ust04: List[Dict[str, str]] = [
        {"BNAME": "DOZTURK", "PROFILE": "SAP_ALL"},
        {"BNAME": "DDIC", "PROFILE": "SAP_ALL"},
    ]

    # Standard and technical accounts (USTYP B/C/S)
    std_users = [
        ("SAP*", "B", "0", "00000000", "20200101", "00000000"),
        ("DDIC", "B", "64", "20260110", "20200101", "00000000"),
        ("EARLYWATCH", "B", "64", "00000000", "20200101", "00000000"),
        ("SAPCPIC", "C", "64", "00000000", "20200101", "00000000"),
        ("TMSADM", "B", "0", "20261014", "20200101", "00000000"),
        ("RFC_GW_SVC", "S", "0", "20261014", "20220501", "00000000"),
        ("ALE_BATCH", "B", "0", "20261015", "20220501", "00000000"),
    ]
    for bname, ustyp, uflag, trdat, erdat, gltgb in std_users:
        usr02.append({
            "BNAME": bname, "USTYP": ustyp, "UFLAG": uflag,
            "TRDAT": trdat, "ERDAT": erdat, "GLTGB": gltgb,
        })

    # Planted dialog users (12 cases)
    planted_dialog = [
        ("AYILMAZ", "0", "20261012", "20230315", "00000000", ["Z_FI_VENDOR_MASTER", "Z_FI_AP_CLERK"]),
        ("BDEMIR", "0", "20261011", "20230410", "00000000", ["Z_FI_AP_CLERK", "Z_FI_AP_PAYMENTS"]),
        ("CKARA", "0", "20261014", "20230601", "00000000", ["Z_C_PROCUREMENT"]),
        ("DOZTURK", "0", "20261014", "20220110", "00000000", ["Z_BASIS_OPERATOR"]),
        ("ESAHIN", "0", "20261015", "20220901", "00000000", ["Z_SEC_ADMIN"]),
        ("FARSLAN", "0", "20261013", "20230120", "00000000", ["Z_DEV_PROD"]),
        ("GCELIK", "0", "20260217", "20221105", "00000000", ["Z_FI_GL_ACCOUNTANT"]),
        ("HKOC", "0", "00000000", "20260707", "00000000", ["Z_SD_CLERK"]),
        ("IBASIC", "0", "20261010", "20230512", "00000000", []),
        ("JKAYA", "0", "20261009", "20230819", "00000000", ["Z_SUPPORT_ALL"]),
        ("LTUNC", "0", "20261008", "20210415", "00000000", [f"Z_DISP_{i:02d}" for i in range(1, 15)]),
        ("MOZ", "0", "20261015", "20210201", "00000000", ["Z_BASIS_ADMIN"]),
    ]
    for bname, uflag, trdat, erdat, gltgb, roles in planted_dialog:
        usr02.append({
            "BNAME": bname, "USTYP": "A", "UFLAG": uflag,
            "TRDAT": trdat, "ERDAT": erdat, "GLTGB": gltgb,
        })
        for r in roles:
            agr_users.append({
                "AGR_NAME": r, "UNAME": bname,
                "FROM_DAT": "20240101", "TO_DAT": "99991231",
            })

    # IBASIC expired + active role
    agr_users.append({
        "AGR_NAME": "Z_FI_VENDOR_MASTER", "UNAME": "IBASIC",
        "FROM_DAT": "20250101", "TO_DAT": "20260715",
    })
    agr_users.append({
        "AGR_NAME": "Z_FI_AP_CLERK", "UNAME": "IBASIC",
        "FROM_DAT": "20250101", "TO_DAT": "99991231",
    })

    # 33 normal compliant dialog users (total dialog users = 45)
    safe_role_combos = [
        ["Z_FI_AP_CLERK"],
        ["Z_FI_AP_PAYMENTS"],
        ["Z_FI_VENDOR_MASTER"],
        ["Z_FI_GL_ACCOUNTANT"],
        ["Z_MM_BUYER"],
        ["Z_MM_WAREHOUSE"],
        ["Z_MM_PO_RELEASE"],
        ["Z_SD_CLERK"],
        ["Z_BASIS_OPERATOR"],
        ["Z_SD_CLERK", "Z_BASIS_OPERATOR"],
        ["Z_FI_GL_ACCOUNTANT", "Z_SD_CLERK"],
    ]
    for idx in range(1, 34):
        uname = f"U_DIALOG{idx:02d}"
        logon_day = rng.randint(1, 14)
        usr02.append({
            "BNAME": uname, "USTYP": "A", "UFLAG": "0",
            "TRDAT": f"202610{logon_day:02d}", "ERDAT": "20240201", "GLTGB": "00000000",
        })
        for r in safe_role_combos[(idx - 1) % len(safe_role_combos)]:
            agr_users.append({
                "AGR_NAME": r, "UNAME": uname,
                "FROM_DAT": "20240201", "TO_DAT": "00000000",
            })

    # 4. System Parameters (PARAMS)
    params = [
        {"NAME": "login/no_automatic_user_sapstar", "VALUE": "0"},
        {"NAME": "rsau/enable", "VALUE": "0"},
        {"NAME": "auth/rfc_authority_check", "VALUE": "1"},
        {"NAME": "login/min_password_lng", "VALUE": "6"},
        {"NAME": "login/fails_to_user_lock", "VALUE": "12"},
        {"NAME": "login/fails_to_session_end", "VALUE": "3"},
        {"NAME": "login/password_expiration_time", "VALUE": "60"},
        {"NAME": "login/disable_multi_gui_login", "VALUE": "1"},
    ]

    def write_table(filename: str, fieldnames: List[str], rows: List[Dict[str, str]]) -> None:
        with (target / filename).open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    write_table("USR02.csv", ["BNAME", "USTYP", "UFLAG", "TRDAT", "ERDAT", "GLTGB"], usr02)
    write_table("AGR_USERS.csv", ["AGR_NAME", "UNAME", "FROM_DAT", "TO_DAT"], agr_users)
    write_table("AGR_AGRS.csv", ["AGR_NAME", "CHILD_AGR"], agr_agrs)
    write_table("AGR_1251.csv", ["AGR_NAME", "OBJECT", "AUTH", "FIELD", "LOW", "HIGH", "DELETED"], agr_1251)
    write_table("UST04.csv", ["BNAME", "PROFILE"], ust04)
    write_table("PARAMS.csv", ["NAME", "VALUE"], params)


if __name__ == "__main__":
    generate_sample_data()