"""Self-contained HTML report (Phase 4).

The markdown report is the source of truth; this renders the same content as
a single-file HTML document with no external assets, no JavaScript, and no
network fetches — safe to open on an air-gapped analyst workstation and to
attach to a ticket.

A deliberately small markdown subset is supported (exactly what report.py
emits): headings, paragraphs, bullet lists (one nesting level), pipe tables,
fenced code blocks, horizontal rules, bold, italic and inline code. Anything
else falls through as escaped text — no raw HTML from tool output or model
narrative can ever reach the document.
"""

from __future__ import annotations

import html
import re

_CSS = """
:root { color-scheme: light; }
body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
       max-width: 1100px; margin: 2rem auto; padding: 0 1.25rem;
       color: #1f2933; line-height: 1.55; }
h1 { border-bottom: 3px solid #b91c1c; padding-bottom: .35rem; }
h2 { margin-top: 2.2rem; border-bottom: 1px solid #e5e7eb; padding-bottom: .25rem; }
h3 { margin-top: 1.6rem; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; font-size: .92rem; }
th, td { border: 1px solid #d1d5db; padding: .45rem .6rem; text-align: left;
         vertical-align: top; }
th { background: #f3f4f6; }
tbody tr:nth-child(even) td { background: #fafafa; }
code { background: #f3f4f6; padding: .1rem .3rem; border-radius: 4px;
       font-size: .9em; }
pre { background: #111827; color: #e5e7eb; padding: 1rem; border-radius: 6px;
      overflow-x: auto; }
pre code { background: transparent; color: inherit; padding: 0; }
hr { border: 0; border-top: 1px solid #e5e7eb; margin: 2rem 0; }
ul { margin: .4rem 0 .8rem 1.2rem; }
li { margin: .15rem 0; }
.banner { background: #fef2f2; border: 1px solid #fecaca; color: #7f1d1d;
          border-radius: 6px; padding: .6rem .9rem; margin: 1rem 0;
          font-size: .92rem; }
"""

_BANNER = (
    "Autonomous assessment output. Every finding must be verified manually "
    "before it is acted on — unattended tools can be wrong."
)


def _escape(text: str) -> str:
    return html.escape(text, quote=False)


def _inline(text: str) -> str:
    """Inline markdown on already-escaped text: `code`, **bold**, *italic*."""
    parts = text.split("`")
    out: list[str] = []
    for i, part in enumerate(parts):
        if i % 2 == 1:                     # inside backticks
            out.append(f"<code>{part}</code>")
        else:
            part = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", part)
            part = re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)", r"<em>\1</em>", part)
            out.append(part)
    return "".join(out)


def _table(rows: list[str]) -> str:
    def cells(line: str) -> list[str]:
        return [c.strip() for c in line.strip().strip("|").split("|")]

    if not rows:
        return ""
    header = cells(rows[0])
    body = rows[1:]
    if body and re.fullmatch(r"[\s|:-]+", body[0]) and "-" in body[0]:
        body = body[1:]
    out = ["<table>", "<thead><tr>"]
    out += [f"<th>{_inline(_escape(c))}</th>" for c in header]
    out += ["</tr></thead>", "<tbody>"]
    for row in body:
        out.append("<tr>")
        out += [f"<td>{_inline(_escape(c))}</td>" for c in cells(row)]
        out.append("</tr>")
    out += ["</tbody>", "</table>"]
    return "\n".join(out)


def _list(items: list[tuple[int, str]]) -> str:
    """Tolerant nested list: one extra <ul> level for indented items."""
    base = min(indent for indent, _ in items) if items else 0
    out = ["<ul>"]
    level = 1
    for indent, text in items:
        this = 1 if indent <= base else 2
        if this > level:
            out.append("<ul>")
            level = this
        elif this < level:
            out.append("</ul>")
            level = this
        out.append(f"<li>{text}</li>")
    while level > 1:
        out.append("</ul>")
        level -= 1
    out.append("</ul>")
    return "\n".join(out)


def markdown_to_html(markdown: str) -> str:
    lines = markdown.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()

        if stripped.startswith("```"):                    # fenced code
            body: list[str] = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                body.append(lines[i])
                i += 1
            i += 1                                        # closing fence
            out.append("<pre><code>" + _escape("\n".join(body)) + "</code></pre>")
            continue

        if not stripped:
            i += 1
            continue

        if stripped == "---":
            out.append("<hr>")
            i += 1
            continue

        m = re.match(r"^(#{1,6})\s+(.*)$", stripped)
        if m:
            level = len(m.group(1))
            out.append(f"<h{level}>{_inline(_escape(m.group(2)))}</h{level}>")
            i += 1
            continue

        if stripped.startswith("|"):                      # table block
            rows: list[str] = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append(lines[i].strip())
                i += 1
            out.append(_table(rows))
            continue

        if re.match(r"^[-*]\s+", stripped):               # list block
            items: list[tuple[int, str]] = []
            while i < len(lines):
                cur = lines[i]
                st = cur.strip()
                if not re.match(r"^[-*]\s+", st):
                    break
                indent = len(cur) - len(cur.lstrip())
                text = re.sub(r"^[-*]\s+", "", st)
                items.append((indent, _inline(_escape(text))))
                i += 1
            out.append(_list(items))
            continue

        para = [stripped]                                 # paragraph
        i += 1
        while i < len(lines):
            nxt = lines[i].strip()
            if (not nxt or nxt.startswith(("#", "|", "```", "---"))
                    or re.match(r"^[-*]\s+", nxt)):
                break
            para.append(nxt)
            i += 1
        out.append("<p>" + _inline(_escape(" ".join(para))) + "</p>")
    return "\n".join(out)


def _title_from(markdown: str, fallback: str) -> str:
    for line in markdown.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return fallback


def render_html(markdown: str, title: str = "Red Team Assessment") -> str:
    page_title = _escape(_title_from(markdown, title))
    body = markdown_to_html(markdown)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{page_title}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="banner">{_escape(_BANNER)}</div>
{body}
</body>
</html>
"""
