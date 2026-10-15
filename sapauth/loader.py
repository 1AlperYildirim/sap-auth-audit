# SAP Concept: Data model and CSV loader for USR02, AGR_USERS, AGR_AGRS, AGR_1251, UST04, and RSPARAM exports.
"""Loads SAP table CSV exports and resolves effective composite-to-single role assignments."""

import csv
from dataclasses import dataclass, field
from datetime import date
import json
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class UserRecord:
    """Represents a row from SAP table USR02 (logon data)."""
    bname: str
    ustyp: str
    uflag: int
    trdat: Optional[date]
    erdat: Optional[date]
    gltgb: Optional[date]

    def is_active_dialog(self, today: date) -> bool:
        """True if user is dialog (A), unlocked (0), and not expired on today."""
        if self.ustyp != "A" or self.uflag != 0:
            return False
        if self.gltgb is not None and self.gltgb < today:
            return False
        return True


@dataclass
class RoleAssignment:
    """Represents a row from SAP table AGR_USERS (role assignments to users)."""
    agr_name: str
    uname: str
    from_dat: Optional[date]
    to_dat: Optional[date]

    def is_valid_on(self, today: date) -> bool:
        """True if assignment validity window includes today."""
        if self.from_dat is not None and today < self.from_dat:
            return False
        if self.to_dat is not None and today > self.to_dat:
            return False
        return True


@dataclass
class AuthFieldRow:
    """Represents a single active row from SAP table AGR_1251 (role authorization data)."""
    agr_name: str
    object: str
    auth: str
    field: str
    low: str
    high: str


@dataclass
class AuthorizationInstance:
    """Grouped AGR_1251 rows sharing AGR_NAME + OBJECT + AUTH."""
    agr_name: str
    object: str
    auth: str
    fields: Dict[str, List[Tuple[str, str]]] = field(default_factory=dict)


@dataclass
class Dataset:
    """Holds parsed SAP authorization tables and system metadata for auditing."""
    meta: Dict[str, str]
    users: Dict[str, UserRecord]
    agr_users: List[RoleAssignment]
    agr_agrs: Dict[str, Set[str]]
    auth_instances: Dict[str, List[AuthorizationInstance]]
    ust04: Dict[str, Set[str]]
    params: Dict[str, str]


def parse_sap_date(raw: str) -> Optional[date]:
    """Parses YYYYMMDD or YYYY-MM-DD; returns None for blank or 00000000."""
    val = (raw or "").strip()
    if not val or val in ("00000000", "0000-00-00"):
        return None
    clean = val.replace("-", "")
    if len(clean) == 8 and clean.isdigit():
        return date(int(clean[0:4]), int(clean[4:6]), int(clean[6:8]))
    raise ValueError(f"Invalid SAP date value: {raw!r}")


def build_dataset(
    meta: Optional[Dict[str, str]] = None,
    usr02_rows: Optional[List[Dict[str, str]]] = None,
    agr_users_rows: Optional[List[Dict[str, str]]] = None,
    agr_agrs_rows: Optional[List[Dict[str, str]]] = None,
    agr_1251_rows: Optional[List[Dict[str, str]]] = None,
    ust04_rows: Optional[List[Dict[str, str]]] = None,
    params_rows: Optional[List[Dict[str, str]]] = None,
) -> Dataset:
    """Builds a Dataset from in-memory row dicts (used by both CSV loader and unit tests)."""
    users: Dict[str, UserRecord] = {}
    for row in usr02_rows or []:
        bname = row["BNAME"].strip()
        users[bname] = UserRecord(
            bname=bname,
            ustyp=row.get("USTYP", "A").strip(),
            uflag=int(row.get("UFLAG", "0").strip() or "0"),
            trdat=parse_sap_date(row.get("TRDAT", "")),
            erdat=parse_sap_date(row.get("ERDAT", "")),
            gltgb=parse_sap_date(row.get("GLTGB", "")),
        )

    agr_users: List[RoleAssignment] = []
    for row in agr_users_rows or []:
        agr_users.append(
            RoleAssignment(
                agr_name=row["AGR_NAME"].strip(),
                uname=row["UNAME"].strip(),
                from_dat=parse_sap_date(row.get("FROM_DAT", "")),
                to_dat=parse_sap_date(row.get("TO_DAT", "")),
            )
        )

    agr_agrs: Dict[str, Set[str]] = {}
    for row in agr_agrs_rows or []:
        parent = row["AGR_NAME"].strip()
        child = row["CHILD_AGR"].strip()
        agr_agrs.setdefault(parent, set()).add(child)

    grouped: Dict[Tuple[str, str, str], AuthorizationInstance] = {}
    for row in agr_1251_rows or []:
        if row.get("DELETED", "").strip().upper() == "X":
            continue
        agr = row["AGR_NAME"].strip()
        obj = row["OBJECT"].strip()
        auth = row["AUTH"].strip()
        fld = row["FIELD"].strip()
        low = row.get("LOW", "").strip()
        high = row.get("HIGH", "").strip()
        key = (agr, obj, auth)
        if key not in grouped:
            grouped[key] = AuthorizationInstance(agr_name=agr, object=obj, auth=auth)
        grouped[key].fields.setdefault(fld, []).append((low, high))

    auth_instances: Dict[str, List[AuthorizationInstance]] = {}
    for inst in grouped.values():
        auth_instances.setdefault(inst.agr_name, []).append(inst)

    ust04: Dict[str, Set[str]] = {}
    for row in ust04_rows or []:
        ust04.setdefault(row["BNAME"].strip(), set()).add(row["PROFILE"].strip())

    params: Dict[str, str] = {}
    for row in params_rows or []:
        params[row["NAME"].strip()] = row.get("VALUE", "").strip()

    default_meta = {"sid": "S4P", "client": "100", "env": "PROD"}
    if meta:
        default_meta.update(meta)

    return Dataset(
        meta=default_meta,
        users=users,
        agr_users=agr_users,
        agr_agrs=agr_agrs,
        auth_instances=auth_instances,
        ust04=ust04,
        params=params,
    )


def _read_csv(path: Path) -> List[Dict[str, str]]:
    """Reads a UTF-8 CSV file into a list of row dicts."""
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def load_dir(data_dir: Path) -> Dataset:
    """Loads SAP CSV exports and meta.json from a directory into a Dataset."""
    data_path = Path(data_dir)
    meta_path = data_path / "meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    return build_dataset(
        meta=meta,
        usr02_rows=_read_csv(data_path / "USR02.csv"),
        agr_users_rows=_read_csv(data_path / "AGR_USERS.csv"),
        agr_agrs_rows=_read_csv(data_path / "AGR_AGRS.csv"),
        agr_1251_rows=_read_csv(data_path / "AGR_1251.csv"),
        ust04_rows=_read_csv(data_path / "UST04.csv"),
        params_rows=_read_csv(data_path / "PARAMS.csv"),
    )


def get_effective_single_roles(dataset: Dataset, uname: str, today: date) -> Set[str]:
    """Resolves valid user role assignments on today and expands composite roles via AGR_AGRS."""
    direct = [
        a.agr_name
        for a in dataset.agr_users
        if a.uname == uname and a.is_valid_on(today)
    ]
    single_roles: Set[str] = set()
    visited: Set[str] = set()
    stack = list(direct)
    while stack:
        role = stack.pop()
        if role in visited:
            continue
        visited.add(role)
        children = dataset.agr_agrs.get(role)
        if children:
            stack.extend(children)
        else:
            single_roles.add(role)
    return single_roles