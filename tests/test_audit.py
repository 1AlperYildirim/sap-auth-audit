# SAP Concept: Unit and integration test suite for SAP authorization rules, role resolution, and reporting.
"""Unittest suite covering date parsing, value matching, role validity, SoD, parameters, and HTML output."""

from datetime import date
from pathlib import Path
import unittest

from sapauth.checks import (
    check_sod,
    check_user_lifecycle,
    evaluate_param_rule,
    load_rules,
    match_sap_value,
    run_all_checks,
)
from sapauth.loader import build_dataset, load_dir, parse_sap_date
from sapauth.report import render_html_report

REPO_ROOT = Path(__file__).resolve().parent.parent
TODAY = date(2026, 10, 15)


class TestSapAuthAudit(unittest.TestCase):
    """Eight focused tests for SAP authorization and Basis security audit logic."""

    def test_1_date_parsing(self) -> None:
        """Parses YYYYMMDD, YYYY-MM-DD, and treats 00000000 or blank as None."""
        self.assertEqual(parse_sap_date("20261015"), date(2026, 10, 15))
        self.assertEqual(parse_sap_date("2026-10-15"), date(2026, 10, 15))
        self.assertIsNone(parse_sap_date("00000000"))
        self.assertIsNone(parse_sap_date(""))

    def test_2_value_matching(self) -> None:
        """Matches exact values, bare '*', string ranges, and fnmatch patterns; rule '*' requires LOW='*'."""
        self.assertTrue(match_sap_value("*", "", "SE38"))
        self.assertTrue(match_sap_value("*", "", "*"))
        self.assertFalse(match_sap_value("SE*", "", "*"))
        self.assertTrue(match_sap_value("SE*", "", "SE38"))
        self.assertTrue(match_sap_value("FB00", "FB99", "FB60"))
        self.assertFalse(match_sap_value("FB00", "FB50", "FB60"))

    def test_3_expired_assignment_ignored(self) -> None:
        """Expired role assignments in AGR_USERS do not trigger SoD conflicts."""
        ds = build_dataset(
            usr02_rows=[{"BNAME": "U1", "USTYP": "A", "UFLAG": "0", "TRDAT": "20261010"}],
            agr_users_rows=[
                {"AGR_NAME": "R_VEND", "UNAME": "U1", "FROM_DAT": "20250101", "TO_DAT": "20260715"},
                {"AGR_NAME": "R_AP", "UNAME": "U1", "FROM_DAT": "20250101", "TO_DAT": "99991231"},
            ],
            agr_1251_rows=[
                {"AGR_NAME": "R_VEND", "OBJECT": "S_TCODE", "AUTH": "A1", "FIELD": "TCD", "LOW": "XK01"},
                {"AGR_NAME": "R_AP", "OBJECT": "S_TCODE", "AUTH": "A2", "FIELD": "TCD", "LOW": "FB60"},
            ],
        )
        findings = check_sod(ds, load_rules(), TODAY, excluded_users=set())
        self.assertEqual(findings, [])

    def test_4_composite_expansion_triggers_sod06(self) -> None:
        """Composite role in AGR_AGRS expands child single roles and triggers SOD-06."""
        ds = build_dataset(
            usr02_rows=[{"BNAME": "BUYER1", "USTYP": "A", "UFLAG": "0", "TRDAT": "20261010"}],
            agr_users_rows=[{"AGR_NAME": "Z_COMP", "UNAME": "BUYER1", "FROM_DAT": "20260101", "TO_DAT": ""}],
            agr_agrs_rows=[
                {"AGR_NAME": "Z_COMP", "CHILD_AGR": "R_PO_CREATE"},
                {"AGR_NAME": "Z_COMP", "CHILD_AGR": "R_PO_REL"},
            ],
            agr_1251_rows=[
                {"AGR_NAME": "R_PO_CREATE", "OBJECT": "S_TCODE", "AUTH": "A1", "FIELD": "TCD", "LOW": "ME21N"},
                {"AGR_NAME": "R_PO_REL", "OBJECT": "S_TCODE", "AUTH": "A2", "FIELD": "TCD", "LOW": "ME29N"},
            ],
        )
        findings = check_sod(ds, load_rules(), TODAY, excluded_users=set())
        self.assertEqual([f.rule_id for f in findings], ["SOD-06"])

    def test_5_dormant_boundary(self) -> None:
        """Last logon exactly 90 days ago is not flagged; 91 days ago triggers HYG-03."""
        ds = build_dataset(
            usr02_rows=[
                {"BNAME": "U_90D", "USTYP": "A", "UFLAG": "0", "TRDAT": "20260717", "ERDAT": "20250101"},
                {"BNAME": "U_91D", "USTYP": "A", "UFLAG": "0", "TRDAT": "20260716", "ERDAT": "20250101"},
            ]
        )
        findings = check_user_lifecycle(ds, load_rules(), TODAY, dormant_days=90)
        flagged = [f.user for f in findings if f.rule_id == "HYG-03"]
        self.assertEqual(flagged, ["U_91D"])

    def test_6_parameter_operators(self) -> None:
        """Tests eq, ge, le, and range operators in parameter evaluation."""
        self.assertTrue(evaluate_param_rule({"op": "eq", "expected": 1}, "1"))
        self.assertFalse(evaluate_param_rule({"op": "ge", "expected": 8}, "6"))
        self.assertFalse(evaluate_param_rule({"op": "le", "expected": 5}, "12"))
        self.assertTrue(evaluate_param_rule({"op": "range", "min": 1, "max": 90}, "60"))
        self.assertFalse(evaluate_param_rule({"op": "range", "min": 1, "max": 90}, "0"))

    def test_7_sample_data_end_to_end(self) -> None:
        """Every check category fires on sample_data while IBASIC has no SoD finding."""
        ds = load_dir(REPO_ROOT / "sample_data")
        findings = run_all_checks(ds, today=TODAY)
        categories = {f.category for f in findings}
        self.assertEqual(
            categories,
            {"USER_LIFECYCLE", "CRITICAL_TCODE", "CRITICAL_AUTH", "SOD", "PARAMETER"},
        )
        ibasic_sod = [f for f in findings if f.user == "IBASIC" and f.category == "SOD"]
        self.assertEqual(ibasic_sod, [])

    def test_8_html_report_contains_severity_counts(self) -> None:
        """Rendered report.html contains exact severity card counts."""
        ds = load_dir(REPO_ROOT / "sample_data")
        findings = run_all_checks(ds, today=TODAY)
        html_doc = render_html_report(ds, findings, today=TODAY)
        self.assertIn('<div class="val" id="count-critical">11</div>', html_doc)
        self.assertIn('<div class="val" id="count-high">13</div>', html_doc)
        self.assertIn('<div class="val" id="count-medium">4</div>', html_doc)
        self.assertIn('<div class="val" id="count-low">2</div>', html_doc)


if __name__ == "__main__":
    unittest.main()