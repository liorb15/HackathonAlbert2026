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

EXAMPLE_SCENARIOS = [
    {
        "label": "Commande PowerShell suspecte",
        "scenario": DEFAULT_SCENARIO,
        "asset_id": "win_srv_ops",
        "strategy": "balanced",
        "what_to_expect": "Doit recommander Sysmon pour voir CommandLine, ProcessName et ParentProcessName.",
    },
    {
        "label": "Exploitation web type Log4Shell",
        "scenario": "Exploit public facing application log4j apache web request payload",
        "asset_id": "web_frontend",
        "strategy": "balanced",
        "what_to_expect": "Doit orienter vers l’exploitation d’application publique et les logs web.",
    },
    {
        "label": "Exfiltration DNS",
        "scenario": "Exfiltration over alternative protocol dns data transfer",
        "asset_id": "network_dns",
        "strategy": "minimal",
        "what_to_expect": "Doit mettre en avant les signaux réseau/DNS et le compromis bruit vs couverture.",
    },
]


def _escape(value: object) -> str:
    return html.escape(str(value or ""), quote=True)


def _badge_class(priority: str) -> str:
    return {"indispensable": "danger", "recommandé": "warn", "optionnel": "soft"}.get(priority, "soft")


def _selected(value: str, expected: str) -> str:
    return "selected" if value == expected else ""


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
    best_candidate = next(
        (candidate for candidate in mitre_candidates if candidate.get("ttp_id") == target.get("selected_ttp_id")),
        mitre_candidates[0] if mitre_candidates else {},
    )
    matched_terms = best_candidate.get("matched_terms", [])
    top_fields = top.get("fields", [])

    executive_summary = (
        f"Collecter {top['log_source']} sur {target['asset_id']} pour détecter {target['selected_ttp_id']} "
        f"({target['ttp_name']}). Priorité : {top['priority']}."
    )
    plain_language_result = {
        "title": "Pourquoi cette recommandation est importante",
        "body": (
            f"Le scénario ressemble à {target['selected_ttp_id']} dans MITRE ATT&CK. "
            f"Sur cet actif, les champs {', '.join(top_fields)} sont les signaux les plus utiles pour vérifier ce comportement."
        ),
    }

    decision_steps = [
        {
            "label": "1. Scénario",
            "value": scenario,
            "explanation": "L’utilisateur décrit une situation en langage naturel, comme dans un briefing SOC.",
        },
        {
            "label": "2. Matching MITRE",
            "value": f"{target['selected_ttp_id']} — {target['ttp_name']}",
            "explanation": f"Les mots communs retenus sont : {', '.join(matched_terms) or 'similarité textuelle'}.",
        },
        {
            "label": "3. Contexte actif",
            "value": f"{target['asset_id']} · {target['asset_type']} · criticité {target['asset_criticality']}",
            "explanation": f"Rôle : {target['business_role']}. La priorité dépend du contexte, pas seulement de la TTP.",
        },
        {
            "label": "4. Score final",
            "value": f"{top['log_value_score']}/10 · {top['priority']}",
            "explanation": "Ce score n’est pas une probabilité : c’est un score de valeur de collecte, basé sur menace, actif, couverture, coût et bruit.",
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
        "executive_summary": executive_summary,
        "plain_language_result": plain_language_result,
        "why_this_result": why,
        "blind_spot": top["blind_spot_if_missing"],
        "json_output": str(DEFAULT_UI_OUTPUT_DIR / f"policy_{target['selected_ttp_id']}.json"),
        "yaml_output": str(DEFAULT_UI_OUTPUT_DIR / f"policy_{target['selected_ttp_id']}.yaml"),
        "raw_policy": policy,
    }


def _render_presets() -> str:
    cards = []
    for index, preset in enumerate(EXAMPLE_SCENARIOS):
        cards.append(
            f"""
            <form method="post" action="/generate" class="preset-form">
              <input type="hidden" name="preset" value="{index}">
              <button class="preset-card" type="submit">
                <span>Tester un exemple</span>
                <strong>{_escape(preset['label'])}</strong>
                <small>{_escape(preset['what_to_expect'])}</small>
              </button>
            </form>
            """
        )
    return "".join(cards)


def render_dashboard_html(view: dict) -> str:
    """Render a clear, presentation-oriented MVP dashboard."""

    top = view["top_recommendation"]
    priority = top["priority"]
    fields_html = "".join(f"<span class='chip'>{_escape(field)}</span>" for field in top.get("fields", []))
    top_candidate = next(
        (candidate for candidate in view["mitre_candidates"] if candidate.get("ttp_id") == view["selected_ttp_id"]),
        view["mitre_candidates"][0] if view["mitre_candidates"] else {},
    )
    matched_terms = ", ".join(top_candidate.get("matched_terms", []))

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
          <p class="simple-line">À collecter : <strong>{_escape(', '.join(rec.get('fields', [])))}</strong></p>
          <div class="metrics">
            <span>Score final <b>{_escape(rec['log_value_score'])}/10</b></span>
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
    :root {{ --ink:#152033; --muted:#617087; --paper:#f8fbff; --panel:#fff; --line:#d8e2ee; --navy:#0b1728; --blue:#1463ff; --green:#087f5b; --red:#c2255c; --amber:#b7791f; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; color:var(--ink); background:linear-gradient(135deg,#eef6ff,#f8fbff 45%,#e9fff7); font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; }}
    main {{ width:min(1180px, calc(100% - 32px)); margin:0 auto; padding:24px 0 50px; }}
    .hero {{ display:grid; grid-template-columns:1fr .9fr; gap:16px; align-items:stretch; }}
    .card {{ background:rgba(255,255,255,.94); border:1px solid var(--line); border-radius:22px; box-shadow:0 18px 50px rgba(24,45,80,.11); }}
    .headline {{ padding:24px; }}
    .eyebrow {{ color:var(--blue); font-weight:900; letter-spacing:.12em; text-transform:uppercase; font-size:12px; }}
    h1 {{ margin:8px 0 10px; font-size:44px; line-height:.98; letter-spacing:-.055em; color:var(--navy); }}
    h2 {{ margin:0 0 14px; font-size:23px; letter-spacing:-.03em; color:var(--navy); }}
    h3 {{ margin:0; color:var(--navy); }}
    .subtitle {{ color:#536176; font-size:16px; line-height:1.45; }}
    .demo-strip {{ display:grid; grid-template-columns:repeat(3,1fr); gap:10px; margin-top:18px; }}
    .preset-form {{ margin:0; }}
    .preset-card {{ width:100%; height:100%; text-align:left; cursor:pointer; border:1px solid #cfe0f5; border-radius:17px; padding:13px; background:#f7fbff; color:var(--ink); }}
    .preset-card span {{ display:block; color:var(--blue); text-transform:uppercase; font-size:10px; font-weight:900; letter-spacing:.08em; }}
    .preset-card strong {{ display:block; margin:5px 0; }}
    .preset-card small {{ color:var(--muted); line-height:1.3; }}
    .controls {{ margin-top:18px; border-top:1px solid var(--line); padding-top:16px; }}
    .control-grid {{ display:grid; grid-template-columns:1fr 170px 150px; gap:10px; }}
    .field {{ display:flex; flex-direction:column; gap:6px; min-width:0; }}
    label {{ color:#34506f; font-size:11px; font-weight:900; text-transform:uppercase; letter-spacing:.08em; }}
    input, select, button.primary {{ border:1px solid var(--line); border-radius:14px; padding:13px 14px; background:white; color:var(--ink); font:inherit; min-width:0; width:100%; }}
    button.primary {{ margin-top:10px; background:linear-gradient(135deg,var(--blue),#12b886); color:white; border:0; font-weight:900; cursor:pointer; }}
    .result-card {{ padding:24px; border:2px solid rgba(20,99,255,.18); }}
    .recommendation-final {{ background:linear-gradient(135deg,#0b1728,#12345d); color:white; border-radius:20px; padding:20px; margin-bottom:16px; }}
    .recommendation-final .label {{ color:#9dd7ff; font-weight:900; text-transform:uppercase; letter-spacing:.08em; font-size:12px; }}
    .recommendation-final .action {{ font-size:30px; line-height:1.05; font-weight:950; margin:8px 0; }}
    .badge {{ display:inline-flex; padding:7px 11px; border-radius:999px; font-size:12px; font-weight:900; text-transform:uppercase; letter-spacing:.06em; }}
    .danger {{ background:#ffe3ea; color:var(--red); }} .warn {{ background:#fff3bf; color:#8a5a00; }} .soft {{ background:#dbeafe; color:#1d4ed8; }}
    .chips {{ display:flex; flex-wrap:wrap; gap:8px; margin-top:10px; }} .chip {{ border:1px solid #b7e4d2; color:#087f5b; background:#ebfff6; padding:7px 10px; border-radius:999px; font-weight:800; }}
    .explain-box {{ border:1px solid var(--line); border-radius:16px; padding:13px; background:#fbfdff; margin-top:10px; }}
    .simple-line {{ font-size:16px; line-height:1.45; }}
    .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-top:16px; }}
    .section {{ padding:20px; }}
    .steps {{ display:grid; grid-template-columns:repeat(4,1fr); gap:10px; }}
    .step-card {{ padding:14px; border-radius:16px; background:#f7fbff; border:1px solid #d9e8f8; }}
    .step-label {{ color:var(--blue); font-size:12px; font-weight:900; text-transform:uppercase; }}
    .step-value {{ margin-top:8px; font-weight:850; line-height:1.25; }}
    .step-card p, .recommendation p, .callout p {{ color:var(--muted); line-height:1.42; margin-bottom:0; }}
    table {{ width:100%; border-collapse:collapse; }} th,td {{ text-align:left; border-bottom:1px solid var(--line); padding:10px; color:#34445a; vertical-align:top; }} th {{ color:#174ea6; font-size:11px; text-transform:uppercase; letter-spacing:.08em; }}
    .scorebar {{ height:8px; width:96px; border-radius:99px; background:#e8eef7; overflow:hidden; display:inline-block; margin-right:8px; }} .scorebar i {{ display:block; height:100%; background:linear-gradient(90deg,var(--blue),#12b886); }}
    .recommendation {{ border:1px solid var(--line); border-radius:18px; padding:15px; background:#fbfdff; margin-bottom:12px; }}
    .recommendation-top {{ display:flex; justify-content:space-between; gap:12px; align-items:center; }}
    .metrics {{ display:flex; flex-wrap:wrap; gap:8px; margin:12px 0; }} .metrics span {{ padding:7px 10px; border-radius:999px; background:#eef5ff; color:#42526a; border:1px solid #d9e8f8; }}
    .callouts {{ display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px; }} .callout {{ border-radius:18px; padding:16px; background:#fbfdff; border:1px solid var(--line); }}
    pre {{ max-height:340px; overflow:auto; background:#0b1728; border-radius:18px; padding:16px; color:#d1fae5; }} .paths {{ color:#174ea6; font-family:ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12px; overflow-wrap:anywhere; }}
    @media(max-width:920px) {{ .hero,.grid,.callouts,.steps,.demo-strip,.control-grid {{ grid-template-columns:1fr; }} h1 {{ font-size:36px; }} }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="card headline">
        <div class="eyebrow">Démo guidée · Log as Code — MVP</div>
        <h1>On choisit les logs utiles, pas juste “plus de logs”.</h1>
        <p class="subtitle">But de la démo : entrer un scénario cyber, voir quelle technique MITRE est reconnue, puis comprendre précisément quelle source de logs collecter et pourquoi.</p>
        <div class="demo-strip">{_render_presets()}</div>
        <form method="post" action="/generate" class="controls">
          <div class="control-grid">
            <div class="field"><label for="scenario">Scénario à analyser</label><input id="scenario" name="scenario" value="{_escape(view['scenario'])}"></div>
            <div class="field"><label for="asset_id">Actif</label><select id="asset_id" name="asset_id"><option value="win_srv_ops" {_selected(view['asset_id'], 'win_srv_ops')}>Windows ops</option><option value="web_frontend" {_selected(view['asset_id'], 'web_frontend')}>Web public</option><option value="network_dns" {_selected(view['asset_id'], 'network_dns')}>DNS / réseau</option></select></div>
            <div class="field"><label for="strategy">Stratégie</label><select id="strategy" name="strategy"><option value="minimal" {_selected(view['strategy'], 'minimal')}>minimal</option><option value="balanced" {_selected(view['strategy'], 'balanced')}>balanced</option><option value="high_assurance" {_selected(view['strategy'], 'high_assurance')}>high assurance</option></select></div>
          </div>
          <button class="primary" type="submit">Analyser le scénario et générer la policy</button>
        </form>
      </div>
      <aside class="card result-card">
        <div class="recommendation-final">
          <div class="label">Recommandation finale</div>
          <div class="action">Collecter {_escape(top['log_source'])}</div>
          <span class="badge {_badge_class(priority)}">{_escape(priority)}</span>
        </div>
        <h2>En clair</h2>
        <p class="simple-line"><strong>{_escape(view['executive_summary'])}</strong></p>
        <div class="chips">{fields_html}</div>
        <div class="explain-box"><strong>Technique détectée :</strong> {_escape(view['selected_ttp_id'])} · {_escape(view['selected_ttp_name'])}<br><strong>Termes qui ont compté :</strong> {_escape(matched_terms)}<br><strong>Attention :</strong> Ce score n’est pas une probabilité, c’est une valeur de collecte.</div>
      </aside>
    </section>

    <section class="card section" style="margin-top:16px;">
      <h2>Interprétabilité — comment le moteur décide</h2>
      <div class="steps">{steps_html}</div>
    </section>

    <section class="grid">
      <div class="card section"><h2>1. Candidats MITRE trouvés par NLP</h2><table><thead><tr><th>Technique</th><th>Pourquoi elle sort</th><th>Similarité</th></tr></thead><tbody>{candidates_html}</tbody></table></div>
      <div class="card section"><h2>2. Recommandations de logs</h2>{recommendations_html}</div>
    </section>

    <section class="card section" style="margin-top:16px;">
      <h2>Pourquoi ce résultat ?</h2>
      <div class="callouts">
        <div class="callout"><h3>Pourquoi cette recommandation ?</h3><p>{_escape(view['why_this_result'])}</p></div>
        <div class="callout"><h3>Angle mort si absent</h3><p>{_escape(view['blind_spot'])}</p></div>
        <div class="callout"><h3>Ce qu’on présente au jury</h3><p>Le MVP ne prétend pas “prédire magiquement”. Il explique une décision : scénario → MITRE → contexte actif → valeur de collecte → policy.</p></div>
      </div>
    </section>

    <section class="card section" style="margin-top:16px;"><h2>Exports générés</h2><p class="paths">JSON : {_escape(view['json_output'])}<br>YAML : {_escape(view['yaml_output'])}</p><details><summary>Voir la policy brute JSON</summary><pre>{raw_json}</pre></details></section>
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
        self._send_html(render_dashboard_html(build_demo_view_model()))

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/generate":
            self._send_html("<h1>404</h1>", status=404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        data = parse_qs(self.rfile.read(length).decode("utf-8"))
        if "preset" in data:
            preset = EXAMPLE_SCENARIOS[int(data["preset"][0])]
            scenario = preset["scenario"]
            asset_id = preset["asset_id"]
            strategy = preset["strategy"]
        else:
            scenario = data.get("scenario", [DEFAULT_SCENARIO])[0]
            asset_id = data.get("asset_id", [DEFAULT_ASSET_ID])[0]
            strategy = data.get("strategy", [DEFAULT_STRATEGY])[0]
        self._send_html(render_dashboard_html(build_demo_view_model(scenario=scenario, asset_id=asset_id, strategy=strategy)))


def run(host: str = "127.0.0.1", port: int = 8000) -> None:
    server = ThreadingHTTPServer((host, port), MvpRequestHandler)
    print(f"MVP Log as Code disponible sur http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run()
