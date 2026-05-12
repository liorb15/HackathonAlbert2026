from pathlib import Path
import sys
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from mvp_web_app import build_demo_view_model, render_dashboard_html  # noqa: E402


class MvpWebAppTest(unittest.TestCase):
    def test_demo_view_model_exposes_interpretability_steps(self):
        view = build_demo_view_model(
            scenario="PowerShell command execution and suspicious parent process on Windows server",
            asset_id="win_srv_ops",
            strategy="balanced",
        )

        self.assertEqual(view["selected_ttp_id"], "T1059")
        self.assertEqual(view["asset_id"], "win_srv_ops")
        self.assertEqual(view["top_recommendation"]["log_source"], "Windows Sysmon")
        self.assertEqual(view["top_recommendation"]["priority"], "indispensable")
        self.assertGreaterEqual(len(view["decision_steps"]), 4)
        self.assertIn("Scénario", view["decision_steps"][0]["label"])
        self.assertIn("MITRE", view["decision_steps"][1]["label"])
        self.assertIn("Score", " ".join(step["label"] for step in view["decision_steps"]))
        self.assertTrue(view["why_this_result"])
        self.assertTrue(view["blind_spot"])

    def test_render_dashboard_html_is_presentable_and_explains_results(self):
        view = build_demo_view_model(
            scenario="PowerShell command execution and suspicious parent process on Windows server",
            asset_id="win_srv_ops",
            strategy="balanced",
        )
        html = render_dashboard_html(view)

        self.assertIn("Log as Code — MVP", html)
        self.assertIn("Interprétabilité", html)
        self.assertIn("Pourquoi ce résultat ?", html)
        self.assertIn("Angle mort si absent", html)
        self.assertIn("Windows Sysmon", html)
        self.assertIn("CommandLine", html)
        self.assertIn("T1059", html)
        self.assertIn("<form", html)


if __name__ == "__main__":
    unittest.main()
