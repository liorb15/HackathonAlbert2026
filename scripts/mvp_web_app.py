"""Dependency-free web interface for the Log as Code MVP.

Run with:
    python3 scripts/mvp_web_app.py
Then open http://127.0.0.1:8000
"""

from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from log_value_engine import (
    DEFAULT_ASSET_INVENTORY_FILE,
    DEFAULT_MAPPING_FILE,
    DEFAULT_MITRE_ATTACK_ZIP_FILE,
    build_policy_from_scenario,
    export_policy,
)

DEFAULT_SCENARIO = "PowerShell command execution and suspicious parent process on Windows server"
DEFAULT_ASSET_ID = "win_srv_ops"
DEFAULT_STRATEGY = "balanced"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_UI_OUTPUT_DIR = PROJECT_ROOT / "ProjetsEtudiantsHackathon2026" / "generated_policies"


def _escape(value: object) -> str:
    return html.escape(str(value or ""), quote=True)


def _badge_class(priority: str) -> str:
    return {
        "indispensable": "danger",
        "recommandé": "warn",
        "optionnel": "soft",
    }.get(priority, "soft")


def build_demo_view_model(
    *,
    scenario: str = DEFAULT_SCENARIO,
    asset_id: str = DEFAULT_ASSET_ID,
    strategy: str = DEFAULT_STRATEGY,
) -> dict:
    """Build a presentation-focused view model from the backend policy."""

    policy = build_policy_from_scenario(
        scenario,
        mapping_file=DEFAULT_MAPPING_FILE,
        mitre_zip_file=DEFAULT_MITRE_ATTACK_ZIP_FILE,
        asset_id=asset_id,
        asset_inventory_file=DEFAULT_ASSET_INVENTORY_FILE,
        strategy=strategy,
    )
    export_policy(policy, DEFAULT_UI_OUTPUT_DIR, fmt="json")
    export_policy(policy, DEFAULT_UI_OUTPUT_DIR, fmt="yaml")

    body = policy["policy"]
    target = body["target"]
    recommendations = body["recommendations"]
    top = recommendations[0]
    mitre_candidates = body.get("mitre_candidates", [])
    matched_terms = mitre_candidates[0].get("matched_terms", []) if mitre_candidates else []
    top_fields = top.get("fields", [])

    decision_steps = [
        {
            "label": "1. Scénario opérationnel",
            "value": scenario,
            "explanation": "On part d’une phrase compréhensible par un analyste, pas d’un identifiant technique imposé.",
        },
        {
            "label": "2. Matching MITRE ATT&CK",
            "value": f"{target['selected_ttp_id']} — {target['ttp_name']}",
            "explanation": "Le moteur compare le texte du scénario aux techniques MITRE Enterprise et conserve les candidats les plus proches.",
        },
        {
            "label": "3. Contexte actif",
            "value": f"{target['asset_id']} · {target['asset_type']} · criticité {target['asset_criticality']}",
            "explanation": "La même menace ne mérite pas la même collecte selon l’actif, son exposition et son rôle métier.",
        },
        {
            "label": "4. Score coût / bruit / couverture",
            "value": f"{top['log_value_score']}/10 · {top['priority']}",
            "explanation": "La priorité combine valeur menace, criticité de l’actif, couverture de détection, coût et bruit estimés.",
        },
    ]

    why = (
        f"Le scénario contient des signaux proches de MITRE {target['selected_ttp_id']} "
        f"({', '.join(matched_terms) or 'similarité textuelle'}). Sur l’actif {target['asset_id']}, "
        f"la source {top['log_source']} couvre les champs {', '.join(top_fields)} avec une couverture "
        f"{top['detection_coverage']} et un bruit estimé {top['estimated_noise']}."
    )

    return {
        "scenario": scenario,
        "asset_id": target["asset_id"],
        "asset_type": target["asset_type"],
        "asset_criticality": target["asset_criticality"],
        "business_role": target["business_role"],
        "strategy": target["strategy"],
        "selected_ttp_id": target["selected_ttp_id"],
        "selected_ttp_name": target["ttp_name"],
        "top_recommendation": top,
        "recommendations": recommendations,
        "mitre_candidates": mitre_candidates,
        "decision_steps": decision_steps,
        "why_this_result": why,
        "blind_spot": top["blind_spot_if_missing"],
        "json_output": str(DEFAULT_UI_OUTPUT_DIR / f"policy_{target['selected_ttp_id']}.json"),
        "yaml_output": str(DEFAULT_UI_OUTPUT_DIR / f"policy_{target['selected_ttp_id']}.yaml"),
        "raw_policy": policy,
    }


def render_dashboard_html(view: dict) -> str:
    """Render a polished, self-contained MVP dashboard."""

    top = view["top_recommendation"]
    priority = top["priority"]
    fields_html = "".join(f"<span class='chip'>{_escape(field)}</span>" for field in top.get("fields", []))
    steps_html = "".join(
        f"""
        <article class="step-card">
          <div class="step-label">{_escape(step['label'])}</div>
          <div class="step-value">{_escape(step['value'])}</div>
          <p>{_escape(step['explanation'])}</p>
        </article>
        """
        for step in view["decision_steps"]
    )
    candidates_html = "".join(
        f"""
        <tr>
          <td><strong>{_escape(candidate['ttp_id'])}</strong><br><span>{_escape(candidate['name'])}</span></td>
          <td>{_escape(', '.join(candidate.get('matched_terms', [])))}</td>
          <td><div class="scorebar"><i style="width:{min(float(candidate['similarity_score']) * 100, 100):.0f}%"></i></div><b>{_escape(candidate['similarity_score'])}</b></td>
        </tr>
        """
        for candidate in view["mitre_candidates"][:5]
    )
    recommendations_html = "".join(
        f"""
        <article class="recommendation">
          <div class="recommendation-top">
            <h3>{_escape(rec['log_source'])}</h3>
            <span class="badge {_badge_class(rec['priority'])}">{_escape(rec['priority'])}</span>
          </div>
          <div class="metrics">
            <span>Score <b>{_escape(rec['log_value_score'])}/10</b></span>
            <span>Coût <b>{_escape(rec['estimated_cost'])}</b></span>
            <span>Bruit <b>{_escape(rec['estimated_noise'])}</b></span>
            <span>Couverture <b>{_escape(rec['detection_coverage'])}</b></span>
          </div>
          <p>{_escape(rec['reason'])}</p>
        </article>
        """
        for rec in view["recommendations"]
    )
    raw_json = _escape(json.dumps(view["raw_policy"], ensure_ascii=False, indent=2))

    return f"""<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Log as Code — MVP interprétable</title>
  <style>
    :root {{
      --ink:#e7f0ff; --muted:#91a1b8; --panel:#111827; --line:#253247;
      --bg:#070b12; --accent:#6ee7b7; --blue:#60a5fa; --danger:#fb7185; --warn:#fbbf24;
    }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; color:var(--ink); background:radial-gradient(circle at 18% 8%, #13315c 0, transparent 32%), radial-gradient(circle at 84% 12%, #14532d 0, transparent 30%), var(--bg); font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; }}
    body:before {{ content:""; position:fixed; inset:0; pointer-events:none; background-image:linear-gradient(rgba(255,255,255,.035) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.035) 1px, transparent 1px); background-size:34px 34px; mask-image:linear-gradient(to bottom, black, transparent 90%); }}
    main {{ width:min(1180px, calc(100% - 36px)); margin:0 auto; padding:32px 0 54px; }}
    .hero {{ display:grid; grid-template-columns:1.2fr .8fr; gap:18px; align-items:stretch; }}
    .card {{ background:linear-gradient(180deg, rgba(17,24,39,.94), rgba(9,14,24,.94)); border:1px solid var(--line); border-radius:24px; box-shadow:0 24px 70px rgba(0,0,0,.36); }}
    .headline {{ padding:28px; position:relative; overflow:hidden; }}
    .eyebrow {{ color:var(--accent); font-weight:800; letter-spacing:.12em; text-transform:uppercase; font-size:12px; }}
    h1 {{ margin:10px 0 12px; font-size:52px; line-height:.94; letter-spacing:-.06em; }}
    .subtitle {{ color:#b9c6d8; font-size:17px; line-height:1.45; max-width:760px; }}
    form {{ margin-top:22px; display:grid; grid-template-columns:1fr 1fr; gap:10px; align-items:end; }}
    .field {{ display:flex; flex-direction:column; gap:6px; min-width:0; }}
    .field.scenario-field {{ grid-column:1 / -1; }}
    .field label {{ color:#93c5fd; font-size:11px; font-weight:900; text-transform:uppercase; letter-spacing:.08em; }}
    input, select, button {{ border:1px solid var(--line); border-radius:14px; padding:13px 14px; background:#0b1220; color:var(--ink); font:inherit; min-width:0; width:100%; }}
    button {{ grid-column:1 / -1; background:linear-gradient(135deg, var(--accent), var(--blue)); color:#031018; border:0; font-weight:900; cursor:pointer; white-space:nowrap; }}
    .result-card {{ padding:24px; }}
    .big-score {{ font-size:74px; font-weight:950; letter-spacing:-.08em; }}
    .badge {{ display:inline-flex; padding:7px 11px; border-radius:999px; font-size:12px; font-weight:900; text-transform:uppercase; letter-spacing:.06em; }}
    .danger {{ background:rgba(251,113,133,.15); color:#fecdd3; border:1px solid rgba(251,113,133,.35); }}
    .warn {{ background:rgba(251,191,36,.13); color:#fde68a; border:1px solid rgba(251,191,36,.35); }}
    .soft {{ background:rgba(96,165,250,.12); color:#bfdbfe; border:1px solid rgba(96,165,250,.35); }}
    .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:18px; margin-top:18px; }}
    .section {{ padding:22px; }}
    h2 {{ margin:0 0 14px; font-size:22px; letter-spacing:-.03em; }}
    .steps {{ display:grid; grid-template-columns:repeat(4, 1fr); gap:12px; }}
    .step-card {{ padding:16px; border-radius:18px; background:#0b1220; border:1px solid var(--line); }}
    .step-label {{ color:var(--accent); font-size:12px; font-weight:900; text-transform:uppercase; }}
    .step-value {{ margin-top:8px; font-weight:850; line-height:1.25; }}
    .step-card p, .recommendation p, .explain p {{ color:var(--muted); line-height:1.42; margin-bottom:0; }}
    .chips {{ display:flex; flex-wrap:wrap; gap:8px; margin-top:12px; }}
    .chip {{ border:1px solid rgba(110,231,183,.35); color:#bbf7d0; background:rgba(110,231,183,.09); padding:7px 10px; border-radius:999px; font-weight:750; }}
    table {{ width:100%; border-collapse:collapse; overflow:hidden; border-radius:18px; }}
    th, td {{ text-align:left; border-bottom:1px solid var(--line); padding:12px; color:#cbd5e1; vertical-align:top; }}
    th {{ color:#93c5fd; font-size:12px; text-transform:uppercase; letter-spacing:.08em; }}
    .scorebar {{ height:8px; width:120px; border-radius:99px; background:#0f172a; overflow:hidden; display:inline-block; margin-right:8px; }}
    .scorebar i {{ display:block; height:100%; background:linear-gradient(90deg, var(--accent), var(--blue)); }}
    .recommendation {{ border:1px solid var(--line); border-radius:18px; padding:16px; background:#0b1220; margin-bottom:12px; }}
    .recommendation-top {{ display:flex; justify-content:space-between; gap:12px; align-items:center; }}
    h3 {{ margin:0; }}
    .metrics {{ display:flex; flex-wrap:wrap; gap:8px; margin:12px 0; }}
    .metrics span {{ padding:7px 10px; border-radius:999px; background:#111827; color:#aab8cc; border:1px solid var(--line); }}
    .explain {{ display:grid; grid-template-columns:1fr 1fr; gap:14px; }}
    .callout {{ border-radius:18px; padding:16px; background:linear-gradient(135deg, rgba(96,165,250,.12), rgba(110,231,183,.08)); border:1px solid var(--line); }}
    pre {{ max-height:360px; overflow:auto; background:#030712; border:1px solid var(--line); border-radius:18px; padding:16px; color:#d1fae5; }}
    .paths {{ color:#93c5fd; font-family:ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12px; overflow-wrap:anywhere; }}
    @media(max-width:900px) {{ .hero,.grid,.explain {{ grid-template-columns:1fr; }} .steps {{ grid-template-columns:1fr; }} form {{ grid-template-columns:1fr; }} h1 {{ font-size:38px; }} }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="card headline">
        <div class="eyebrow">Log as Code — MVP</div>
        <h1>Décider quels logs collecter.</h1>
        <p class="subtitle">Interface de démonstration : un scénario cyber est rapproché de MITRE ATT&CK, puis converti en recommandations de journalisation priorisées et expliquées.</p>
        <form method="post" action="/generate">
          <div class="field scenario-field"><label for="scenario">Scénario cyber</label><input id="scenario" name="scenario" value="{_escape(view['scenario'])}" aria-label="Scénario cyber"></div>
          <div class="field"><label for="asset_id">Contexte actif</label><select id="asset_id" name="asset_id" aria-label="Actif">
            <option value="win_srv_ops" {'selected' if view['asset_id'] == 'win_srv_ops' else ''}>win_srv_ops</option>
            <option value="web_frontend" {'selected' if view['asset_id'] == 'web_frontend' else ''}>web_frontend</option>
            <option value="network_dns" {'selected' if view['asset_id'] == 'network_dns' else ''}>network_dns</option>
          </select></div>
          <div class="field"><label for="strategy">Stratégie</label><select id="strategy" name="strategy" aria-label="Stratégie">
            <option value="minimal" {'selected' if view['strategy'] == 'minimal' else ''}>minimal</option>
            <option value="balanced" {'selected' if view['strategy'] == 'balanced' else ''}>balanced</option>
            <option value="high_assurance" {'selected' if view['strategy'] == 'high_assurance' else ''}>high assurance</option>
          </select></div>
          <button type="submit">Analyser</button>
        </form>
      </div>
      <aside class="card result-card">
        <div class="eyebrow">Résultat principal</div>
        <div class="big-score">{_escape(top['log_value_score'])}</div>
        <span class="badge {_badge_class(priority)}">{_escape(priority)}</span>
        <h2>{_escape(view['selected_ttp_id'])} · {_escape(view['selected_ttp_name'])}</h2>
        <p class="subtitle">Source recommandée : <strong>{_escape(top['log_source'])}</strong></p>
        <div class="chips">{fields_html}</div>
      </aside>
    </section>

    <section class="card section" style="margin-top:18px;">
      <h2>Interprétabilité — comment le moteur décide</h2>
      <div class="steps">{steps_html}</div>
    </section>

    <section class="grid">
      <div class="card section">
        <h2>Candidats MITRE trouvés par NLP</h2>
        <table>
          <thead><tr><th>Technique</th><th>Termes partagés</th><th>Similarité</th></tr></thead>
          <tbody>{candidates_html}</tbody>
        </table>
      </div>
      <div class="card section">
        <h2>Recommandations de logs</h2>
        {recommendations_html}
      </div>
    </section>

    <section class="card section" style="margin-top:18px;">
      <h2>Pourquoi ce résultat ?</h2>
      <div class="explain">
        <div class="callout"><h3>Justification opérationnelle</h3><p>{_escape(view['why_this_result'])}</p></div>
        <div class="callout"><h3>Angle mort si absent</h3><p>{_escape(view['blind_spot'])}</p></div>
      </div>
    </section>

    <section class="card section" style="margin-top:18px;">
      <h2>Exports générés</h2>
      <p class="paths">JSON : {_escape(view['json_output'])}<br>YAML : {_escape(view['yaml_output'])}</p>
      <details><summary>Voir la policy brute JSON</summary><pre>{raw_json}</pre></details>
    </section>
  </main>
</body>
</html>"""


class MvpRequestHandler(BaseHTTPRequestHandler):
    def _send_html(self, html_text: str, status: int = 200) -> None:
        body = html_text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path not in {"/", "/index.html"}:
            self._send_html("<h1>404</h1>", status=404)
            return
        view = build_demo_view_model()
        self._send_html(render_dashboard_html(view))

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/generate":
            self._send_html("<h1>404</h1>", status=404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        data = parse_qs(self.rfile.read(length).decode("utf-8"))
        scenario = data.get("scenario", [DEFAULT_SCENARIO])[0]
        asset_id = data.get("asset_id", [DEFAULT_ASSET_ID])[0]
        strategy = data.get("strategy", [DEFAULT_STRATEGY])[0]
        view = build_demo_view_model(scenario=scenario, asset_id=asset_id, strategy=strategy)
        self._send_html(render_dashboard_html(view))


def run(host: str = "127.0.0.1", port: int = 8000) -> None:
    server = ThreadingHTTPServer((host, port), MvpRequestHandler)
    print(f"MVP Log as Code disponible sur http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run()
