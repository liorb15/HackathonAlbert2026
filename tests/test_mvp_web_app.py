from pathlib import Path
import sys
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from mvp_web_app import EXAMPLE_SCENARIOS, build_demo_view_model, render_dashboard_html  # noqa: E402


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
        self.assertIn("Collecter", view["executive_summary"])
        self.assertIn("Pourquoi", view["plain_language_result"]["title"])

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
        self.assertIn("Démo guidée", html)
        self.assertIn("Recommandation finale", html)
        self.assertIn("En clair", html)
        self.assertIn("Tester un exemple", html)
        self.assertIn("Ce score n’est pas une probabilité", html)
        self.assertGreaterEqual(html.count("name=\"preset\""), 3)

    def test_example_scenarios_make_the_interface_interactive(self):
        self.assertGreaterEqual(len(EXAMPLE_SCENARIOS), 3)
        self.assertTrue(all("scenario" in item and "asset_id" in item for item in EXAMPLE_SCENARIOS))
        for preset in EXAMPLE_SCENARIOS:
            view = build_demo_view_model(
                scenario=preset["scenario"],
                asset_id=preset["asset_id"],
                strategy=preset["strategy"],
            )
            self.assertTrue(view["executive_summary"])


if __name__ == "__main__":
    unittest.main()
