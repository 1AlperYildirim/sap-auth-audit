# SAP Concept: SUIM authorization checks (RSUSR002/003/005/200), SoD matrix evaluation, and RZ11 parameter baseline.
"""Executes the five SAP security audit check categories and computes user risk scores."""

from dataclasses import asdict, dataclass
from datetime import date
import fnmatch
import json
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

from sapauth.loader import AuthorizationInstance, Dataset, get_effective_single_roles

SEVERITY_WEIGHTS: Dict[str, int] = {
    "critical": 10,
    "high": 5,
    "medium": 2,
    "low": 1,
}


@dataclass
class Finding:
    """Represents a single audit finding produced by a check."""
    user: str
    category: str
    rule_id: str
    severity: str
    title: str
    detail: str
    sap_ref: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        """Returns dictionary representation for JSON/CSV serialization."""
        return asdict(self)


def load_rules(rules_dir: Path | None = None) -> Dict[str, Any]:
    """Loads sod_rules.json, critical_access.json, and param_baseline.json."""
    base = Path(rules_dir) if rules_dir else Path(__file__).resolve().parent / "rules"
    return {
        "sod": json.loads((base / "sod_rules.json").read_text(encoding="utf-8")),
        "critical": json.loads((base / "critical_access.json").read_text(encoding="utf-8")),
        "params": json.loads((base / "param_baseline.json").read_text(encoding="utf-8")),
    }


def match_sap_value(low: str, high: str, target: str) -> bool:
    """Matches an AGR_1251 LOW/HIGH value pair against a target value or rule requirement."""
    if target == "*":
        return low == "*"
    if low == "*":
        return True
    if high:
        return low <= target <= high
    if "*" in low:
        return fnmatch.fnmatchcase(target, low)
    return low == target


def _auth_matches_rule(inst: AuthorizationInstance, req_fields: Dict[str, List[str]]) -> bool:
    """True if one authorization instance satisfies all required fields (AND across fields, OR within allowed values)."""
    for field_name, allowed_targets in req_fields.items():
        field_rows = inst.fields.get(field_name, [])
        if not any(
            match_sap_value(low, high, target)
            for (low, high) in field_rows
            for target in allowed_targets
        ):
            return False
    return True


def _get_user_tcode_patterns(
    dataset: Dataset, roles: Set[str]
) -> Dict[Tuple[str, str], Set[str]]:
    """Extracts (LOW, HIGH) -> roles map from S_TCODE / TCD across effective single roles."""
    patterns: Dict[Tuple[str, str], Set[str]] = {}
    for role in sorted(roles):
        for inst in dataset.auth_instances.get(role, []):
            if inst.object == "S_TCODE":
                for low, high in inst.fields.get("TCD", []):
                    patterns.setdefault((low, high), set()).add(role)
    return patterns


def check_user_lifecycle(
    dataset: Dataset, rules: Dict[str, Any], today: date, dormant_days: int = 90
) -> List[Finding]:
    """Check 1: Evaluates HYG-01 through HYG-05 user lifecycle and hygiene controls."""
    findings: List[Finding] = []
    l_rules = rules["critical"]["lifecycle_rules"]

    for bname in sorted(dataset.users.keys()):
        u = dataset.users[bname]
        if bname == "SAP*" and u.uflag == 0:
            r = l_rules["HYG-01_SAPSTAR"]
            findings.append(Finding(
                user=bname, category="USER_LIFECYCLE", rule_id=r["rule_id"],
                severity=r["severity"], title=r["title"],
                detail="Standard superuser SAP* is unlocked (UFLAG=0) via roles: (user master USR02)",
                sap_ref=r["sap_ref"], remediation=r["remediation"],
            ))
        elif bname in ("EARLYWATCH", "SAPCPIC") and u.uflag == 0:
            r = l_rules["HYG-01_STD"]
            findings.append(Finding(
                user=bname, category="USER_LIFECYCLE", rule_id=r["rule_id"],
                severity=r["severity"], title=f"Standard user {bname} is unlocked",
                detail=f"Standard account {bname} is unlocked (UFLAG=0) via roles: (user master USR02)",
                sap_ref=r["sap_ref"], remediation=r["remediation"],
            ))

        profiles = dataset.ust04.get(bname, set())
        if "SAP_ALL" in profiles:
            r = l_rules["HYG-02_SAP_ALL"]
            findings.append(Finding(
                user=bname, category="USER_LIFECYCLE", rule_id=r["rule_id"],
                severity=r["severity"], title=r["title"],
                detail="Profile SAP_ALL assigned in UST04 via roles: (profile SAP_ALL)",
                sap_ref=r["sap_ref"], remediation=r["remediation"],
            ))
        if "SAP_NEW" in profiles:
            r = l_rules["HYG-02_SAP_NEW"]
            findings.append(Finding(
                user=bname, category="USER_LIFECYCLE", rule_id=r["rule_id"],
                severity=r["severity"], title=r["title"],
                detail="Profile SAP_NEW assigned in UST04 via roles: (profile SAP_NEW)",
                sap_ref=r["sap_ref"], remediation=r["remediation"],
            ))

        if not u.is_active_dialog(today):
            continue

        eff_roles = sorted(get_effective_single_roles(dataset, bname, today))
        roles_str = ", ".join(eff_roles) if eff_roles else "none"

        if u.trdat is not None:
            age = (today - u.trdat).days
            if age > dormant_days:
                r = l_rules["HYG-03"]
                findings.append(Finding(
                    user=bname, category="USER_LIFECYCLE", rule_id=r["rule_id"],
                    severity=r["severity"], title=r["title"],
                    detail=f"Last logon {u.trdat.isoformat()} ({age} days ago > {dormant_days}d) via roles: {roles_str}",
                    sap_ref=r["sap_ref"], remediation=r["remediation"],
                ))
        elif u.erdat is not None:
            created_age = (today - u.erdat).days
            if created_age > 30:
                r = l_rules["HYG-04"]
                findings.append(Finding(
                    user=bname, category="USER_LIFECYCLE", rule_id=r["rule_id"],
                    severity=r["severity"], title=r["title"],
                    detail=f"Never logged on, created {u.erdat.isoformat()} ({created_age} days ago) via roles: {roles_str}",
                    sap_ref=r["sap_ref"], remediation=r["remediation"],
                ))

        if len(eff_roles) > 12:
            r = l_rules["HYG-05"]
            findings.append(Finding(
                user=bname, category="USER_LIFECYCLE", rule_id=r["rule_id"],
                severity=r["severity"], title=r["title"],
                detail=f"{len(eff_roles)} effective single roles assigned via roles: {roles_str}",
                sap_ref=r["sap_ref"], remediation=r["remediation"],
            ))

    return findings


def check_critical_transactions(
    dataset: Dataset, rules: Dict[str, Any], today: date
) -> Tuple[List[Finding], Set[str]]:
    """Check 2: Flags S_TCODE=* (CA-00) and critical/high transactions for active dialog users."""
    findings: List[Finding] = []
    wildcard_users: Set[str] = set()
    wc_rule = rules["critical"]["wildcard_tcode"]
    tcode_rules = rules["critical"]["critical_tcodes"]

    for bname in sorted(dataset.users.keys()):
        u = dataset.users[bname]
        if not u.is_active_dialog(today):
            continue
        eff_roles = get_effective_single_roles(dataset, bname, today)
        patterns = _get_user_tcode_patterns(dataset, eff_roles)

        star_roles: Set[str] = set()
        for (low, _high), r_set in patterns.items():
            if low == "*":
                star_roles.update(r_set)

        if star_roles:
            wildcard_users.add(bname)
            findings.append(Finding(
                user=bname, category="CRITICAL_TCODE", rule_id=wc_rule["rule_id"],
                severity=wc_rule["severity"], title=wc_rule["title"],
                detail=f"S_TCODE TCD=* granted via roles: {', '.join(sorted(star_roles))}",
                sap_ref=wc_rule["sap_ref"], remediation=wc_rule["remediation"],
            ))
            continue

        for tr in tcode_rules:
            tcode = tr["tcode"]
            matched_roles: Set[str] = set()
            for (low, high), r_set in patterns.items():
                if match_sap_value(low, high, tcode):
                    matched_roles.update(r_set)
            if matched_roles:
                findings.append(Finding(
                    user=bname, category="CRITICAL_TCODE", rule_id=tr["rule_id"],
                    severity=tr["severity"], title=tr["title"],
                    detail=f"Transaction {tcode} granted via roles: {', '.join(sorted(matched_roles))}",
                    sap_ref=tr["sap_ref"], remediation=tr["remediation"],
                ))

    return findings, wildcard_users


def check_critical_authorizations(
    dataset: Dataset, rules: Dict[str, Any], today: date
) -> List[Finding]:
    """Check 3: Evaluates CA-01 through CA-08 critical authorization objects for active dialog users."""
    findings: List[Finding] = []
    auth_rules = rules["critical"]["critical_auths"]

    for bname in sorted(dataset.users.keys()):
        u = dataset.users[bname]
        if not u.is_active_dialog(today):
            continue
        eff_roles = get_effective_single_roles(dataset, bname, today)
        for ar in auth_rules:
            matched_roles: Set[str] = set()
            for role in eff_roles:
                for inst in dataset.auth_instances.get(role, []):
                    if inst.object == ar["object"] and _auth_matches_rule(inst, ar["fields"]):
                        matched_roles.add(role)
            if matched_roles:
                field_desc = ", ".join(f"{k}={','.join(v)}" for k, v in ar["fields"].items())
                findings.append(Finding(
                    user=bname, category="CRITICAL_AUTH", rule_id=ar["rule_id"],
                    severity=ar["severity"], title=ar["title"],
                    detail=f"{ar['object']} ({field_desc}) via roles: {', '.join(sorted(matched_roles))}",
                    sap_ref=ar["sap_ref"], remediation=ar["remediation"],
                ))

    return findings


def check_sod(
    dataset: Dataset, rules: Dict[str, Any], today: date, excluded_users: Set[str]
) -> List[Finding]:
    """Check 4: Evaluates Segregation of Duties conflicts at transaction level for active dialog users."""
    findings: List[Finding] = []
    functions: Dict[str, List[str]] = rules["sod"]["functions"]
    sod_rules = rules["sod"]["rules"]

    for bname in sorted(dataset.users.keys()):
        if bname in excluded_users:
            continue
        u = dataset.users[bname]
        if not u.is_active_dialog(today):
            continue
        eff_roles = get_effective_single_roles(dataset, bname, today)
        patterns = _get_user_tcode_patterns(dataset, eff_roles)

        func_hits: Dict[str, Tuple[Set[str], Set[str]]] = {}
        for func_name, tcodes in functions.items():
            matched_tcodes: Set[str] = set()
            matched_roles: Set[str] = set()
            for tcode in tcodes:
                for (low, high), r_set in patterns.items():
                    if match_sap_value(low, high, tcode):
                        matched_tcodes.add(tcode)
                        matched_roles.update(r_set)
            if matched_tcodes:
                func_hits[func_name] = (matched_tcodes, matched_roles)

        for sr in sod_rules:
            fa, fb = sr["func_a"], sr["func_b"]
            if fa in func_hits and fb in func_hits:
                tc_a, roles_a = func_hits[fa]
                tc_b, roles_b = func_hits[fb]
                all_roles = sorted(roles_a | roles_b)
                detail = (
                    f"{fa} ({', '.join(sorted(tc_a))}) conflicts with "
                    f"{fb} ({', '.join(sorted(tc_b))}) via roles: {', '.join(all_roles)}"
                )
                findings.append(Finding(
                    user=bname, category="SOD", rule_id=sr["rule_id"],
                    severity=sr["severity"], title=sr["title"],
                    detail=detail, sap_ref=sr["sap_ref"], remediation=sr["remediation"],
                ))

    return findings


def evaluate_param_rule(rule: Dict[str, Any], raw_value: str) -> bool:
    """Evaluates a single profile parameter value against eq/ge/le/range operators."""
    try:
        val = int(raw_value.strip())
    except ValueError:
        return False
    op = rule["op"]
    if op == "eq":
        return val == int(rule["expected"])
    if op == "ge":
        return val >= int(rule["expected"])
    if op == "le":
        return val <= int(rule["expected"])
    if op == "range":
        return int(rule["min"]) <= val <= int(rule["max"])
    raise ValueError(f"Unsupported parameter operator: {op}")


def check_parameters(dataset: Dataset, rules: Dict[str, Any]) -> List[Finding]:
    """Check 5: Evaluates SAP security profile parameters (RZ11/RSPARAM) against baseline."""
    findings: List[Finding] = []
    missing_meta = rules["params"]["missing_rule"]
    for pr in rules["params"]["parameters"]:
        name = pr["name"]
        if name not in dataset.params or dataset.params[name] == "":
            findings.append(Finding(
                user="SYSTEM", category="PARAMETER", rule_id=pr["rule_id"],
                severity=missing_meta["severity"],
                title=f"{name}: not in export, verify default",
                detail=f"Parameter {name} not in export, verify default via roles: (system profile RSPARAM)",
                sap_ref=pr["sap_ref"], remediation=pr["remediation"],
            ))
            continue

        actual = dataset.params[name]
        if not evaluate_param_rule(pr, actual):
            if pr["op"] == "range":
                exp_str = f"range {pr['min']}-{pr['max']}"
            else:
                exp_str = f"{pr['op']} {pr['expected']}"
            findings.append(Finding(
                user="SYSTEM", category="PARAMETER", rule_id=pr["rule_id"],
                severity=pr["severity"], title=pr["title"],
                detail=f"{name} = {actual} (expected {exp_str}) via roles: (system profile RSPARAM)",
                sap_ref=pr["sap_ref"], remediation=pr["remediation"],
            ))
    return findings


def run_all_checks(
    dataset: Dataset,
    today: date,
    dormant_days: int = 90,
    rules_dir: Path | None = None,
) -> List[Finding]:
    """Runs all five SAP security check categories and returns all findings."""
    rules = load_rules(rules_dir)
    findings: List[Finding] = []
    findings.extend(check_user_lifecycle(dataset, rules, today, dormant_days=dormant_days))
    tc_findings, wildcard_users = check_critical_transactions(dataset, rules, today)
    findings.extend(tc_findings)
    findings.extend(check_critical_authorizations(dataset, rules, today))
    findings.extend(check_sod(dataset, rules, today, excluded_users=wildcard_users))
    findings.extend(check_parameters(dataset, rules))
    return findings


def compute_user_scores(findings: List[Finding]) -> List[Dict[str, Any]]:
    """Aggregates severity weights (10/5/2/1) per user and sorts by score descending."""
    by_user: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        entry = by_user.setdefault(
            f.user,
            {"user": f.user, "score": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        )
        entry[f.severity] += 1
        entry["score"] += SEVERITY_WEIGHTS[f.severity]
    return sorted(by_user.values(), key=lambda x: (-x["score"], x["user"]))