"""Self-contained HTML report: executive summary first, technical detail after.

``lang="ar"`` renders a right-to-left Arabic report (executive part fully translated).
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any

from jinja2 import Environment, PackageLoader
from markupsafe import Markup, escape

from .. import __version__, i18n
from ..models import Rating, ScanResult
from ..rules import NIST_2030, NIST_2035
from ..scoring import grade, readiness_score


def _code_spans(text: str) -> Markup:
    """Escape text and turn `backtick` spans into left-to-right <code> (keeps commands readable in RTL)."""
    parts = re.split(r"`([^`]+)`", str(text))
    out = [str(escape(p)) if i % 2 == 0 else f'<code dir="ltr">{escape(p)}</code>' for i, p in enumerate(parts)]
    return Markup("".join(out))


# Always escape: the report shows text controlled by scanned systems (certificate names, SSH banners,
# paths, code). select_autoescape() would NOT cover this template, because its name ends in ".j2".
_env = Environment(loader=PackageLoader("qrisk", "reports/templates"), autoescape=True)
_env.filters["code"] = _code_spans


def build_context(result: ScanResult, lang: str = "en") -> dict[str, Any]:
    if lang not in i18n.LANGUAGES:
        raise ValueError(f"unsupported language {lang!r}; choose from {', '.join(i18n.LANGUAGES)}")
    t = i18n.ui(lang)
    score = readiness_score(result.findings)
    counts = result.counts()
    total = len(result.findings)

    by_target: dict[str, list] = defaultdict(list)
    for f in result.sorted_findings():
        by_target[f.target].append(f)

    recs = Counter((f.rating, f.recommendation) for f in result.findings if f.rating is not Rating.QUANTUM_SAFE)
    top_recs = [
        {"rating": r, "text": i18n.recommendation(text, lang), "count": n}
        for (r, text), n in sorted(recs.items(), key=lambda kv: (kv[0][0].severity, -kv[1]))
    ]

    timeline = [
        {"when": t["now"], "label": t["now_label"], "count": counts[Rating.CRITICAL], "rating": Rating.CRITICAL},
        {"when": "2030", "label": t["y2030_label"], "rating": Rating.QUANTUM_VULNERABLE,
         "count": sum(1 for f in result.findings if f.nist == NIST_2030)},
        {"when": "2035", "label": t["y2035_label"], "rating": Rating.QUANTUM_VULNERABLE,
         "count": sum(1 for f in result.findings if f.nist in (NIST_2030, NIST_2035))},
    ]

    summary: list[dict[str, Any]] = []
    if total == 0:
        summary.append({"text": t["none"]})
    else:
        summary.append({"text": t["found"].format(total=total, targets=len(result.targets))})
        if counts[Rating.CRITICAL]:
            summary.append({"text": t["critical"].format(n=counts[Rating.CRITICAL]), "critical": True})
        if counts[Rating.QUANTUM_VULNERABLE]:
            summary.append({"text": t["vulnerable"].format(n=counts[Rating.QUANTUM_VULNERABLE])})
        if counts[Rating.HYBRID]:
            summary.append({"text": t["hybrid"].format(n=counts[Rating.HYBRID])})

    generated = (result.finished_at or result.started_at).strftime("%Y-%m-%d %H:%M UTC")
    version = __version__
    if lang == "ar":  # keep Latin dates and versions in left-to-right order inside Arabic text (LRI ... PDI)
        generated, version = f"⁦{generated}⁩", f"⁦{version}⁩"
    return {
        "lang": lang,
        "dir": "rtl" if lang == "ar" else "ltr",
        "t": t,
        "version": __version__,
        "generated_line": t["generated"].format(generated=generated, version=version,
                                                targets=len(result.targets), total=total),
        "score": score,
        "grade": i18n.grade(grade(score), lang),
        "counts": counts,
        "shares": {r: round(100 * counts[r] / max(total, 1), 1) for r in Rating},
        "ratings": list(Rating),
        "rating_label": i18n.RATING_LABEL[lang],
        "rating_meaning": i18n.RATING_MEANING[lang],
        "summary": summary,
        "by_target": by_target,
        "top_recs": top_recs,
        "timeline": timeline,
        "notes": result.notes,
        "total": total,
        "category": lambda c: i18n.category(c, lang),
        "rec": lambda text: i18n.recommendation(text, lang),
        "note_level": lambda lvl: i18n.note_level(lvl, lang),
        "count_label": lambda n: t["count"].format(n=n, s="s" if n != 1 else ""),
    }


def render_html(result: ScanResult, lang: str = "en") -> str:
    return _env.get_template("report.html.j2").render(**build_context(result, lang))


def write_html(result: ScanResult, path: str, lang: str = "en") -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_html(result, lang))
