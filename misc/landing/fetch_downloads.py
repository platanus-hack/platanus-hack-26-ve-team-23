#!/usr/bin/env python3
"""Render build step for the landing (ADR-0032).

Copies every release of the private repository into downloads/v<version>/,
checks each file against the release's SHA256SUMS, and writes
downloads/latest.json and downloads/index.html.

    GITHUB_TOKEN=... python3 misc/landing/fetch_downloads.py misc/landing/downloads

Without GITHUB_TOKEN it writes an empty downloads page and exits 0, so the
landing still deploys. With a token, any error exits 1: Render then keeps the previous
deploy online instead of one without downloads. Standard library only.
"""

import hashlib
import html
import json
import os
import re
import sys
import urllib.error
import urllib.request

REPO = os.environ.get("HAWK_RELEASE_REPO", "JEHR037/team23-private")
API = "https://api.github.com"
TAG_RE = re.compile(r"^v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # GitHub answers an asset download with a redirect to signed storage,
    # which rejects our Authorization header: follow it by hand without it.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _get(url, token, accept):
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": accept,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "hawk-landing-build",
    })
    try:
        with opener.open(req, timeout=60) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307, 308) and e.headers.get("Location"):
            plain = urllib.request.Request(e.headers["Location"], headers={"User-Agent": "hawk-landing-build"})
            with urllib.request.urlopen(plain, timeout=300) as r:
                return r.read()
        raise


def _sums(text):
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2:
            out[parts[1].lstrip("*")] = parts[0].lower()
    return out


def _human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


# What each file of a release built by release.yml is, grouped for people.
GROUPS = [
    "App del dueño",
    "Programa para cada computadora",
    "HAWK Core, para el equipo dedicado",
    "Plugin de OpenCode",
    "Verificación",
    "Otros",
]
KINDS = [
    (re.compile(r"android-arm64\.apk$"), 0, "Android, teléfonos de 64 bits. Permite instalar apps de origen desconocido para abrirlo."),
    (re.compile(r"universal-macos\.dmg$"), 0, "macOS, Apple Silicon e Intel."),
    (re.compile(r"windows-setup\.exe$"), 0, "Windows 10 y 11."),
    (re.compile(r"\.deb$"), 0, "Linux: Debian, Ubuntu y derivadas."),
    (re.compile(r"\.AppImage$"), 0, "Linux: cualquier distribución."),
    (re.compile(r"^hawk-core-.*-aarch64-linux\.tar\.gz$"), 2, "Raspberry Pi y otros equipos ARM de 64 bits con Linux."),
    (re.compile(r"^hawk-core-.*-x86_64-linux\.tar\.gz$"), 2, "Equipos x86_64 con Linux."),
    (re.compile(r"^hawk-\d.*-aarch64-linux\.tar\.gz$"), 1, "Linux ARM de 64 bits. Lo instala install.sh."),
    (re.compile(r"^hawk-\d.*-x86_64-linux\.tar\.gz$"), 1, "Linux x86_64. Lo instala install.sh."),
    (re.compile(r"^hawk-\d.*-aarch64-macos\.tar\.gz$"), 1, "macOS Apple Silicon. Lo instala install.sh."),
    (re.compile(r"^hawk-\d.*-x86_64-macos\.tar\.gz$"), 1, "macOS Intel. Lo instala install.sh."),
    (re.compile(r"^hawk-\d.*-x86_64-windows\.zip$"), 1, "Windows x86_64: descomprime y corre host-daemon.exe."),
    (re.compile(r"^(hawk-opencode-plugin|guardian)\.ts$"), 3, "Le pregunta a HAWK antes de cada herramienta del agente. install.sh lo instala y lo comprueba."),
    (re.compile(r"^SHA256SUMS$"), 4, "Suma SHA-256 de cada archivo de esta versión."),
    (re.compile(r"^SHA256SUMS\.minisig$"), 4, "Firma minisign de SHA256SUMS."),
]


def _kind(name):
    """(group, order inside the group, description) of a release file."""
    for order, (pattern, group, text) in enumerate(KINDS):
        if pattern.search(name):
            return group, order, text
    return len(GROUPS) - 1, len(KINDS), ""


def _row(version, f, text):
    href = f'v{html.escape(version)}/{html.escape(f["name"])}'
    return (
        f'<tr><td><a href="{href}">{html.escape(f["name"])}</a>'
        f'{"<span>" + html.escape(text) + "</span>" if text else ""}</td>'
        f'<td>{html.escape(_human(f["size"]))}</td>'
        f'<td><code>{html.escape(f["sha256"])}</code></td></tr>'
    )


def _index(releases):
    rows = []
    for rel in releases:
        version = rel["version"]
        rows.append(f"<h2>HAWK {html.escape(version)}</h2>")
        files = rel["files"]
        # Releases built by release.yml carry a hawk-core archive; older ones
        # were put together by hand and are listed as they are.
        if not any(f["name"].startswith("hawk-core-") for f in files):
            rows.append("<p>Versión armada a mano, anterior al proceso de releases; su contenido está en sus notas.</p>")
            rows.append("<table><tbody>" + "".join(_row(version, f, "") for f in files) + "</tbody></table>")
            continue
        by_group = {}
        for f in files:
            group, order, text = _kind(f["name"])
            by_group.setdefault(group, []).append((order, f["name"], _row(version, f, text)))
        for group in sorted(by_group):
            rows.append(f"<h3>{html.escape(GROUPS[group])}</h3>")
            rows.append("<table><tbody>" + "".join(r for _, _, r in sorted(by_group[group])) + "</tbody></table>")
    body = "\n".join(rows) if rows else "<p>No hay versiones publicadas todavía.</p>"
    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>HAWK downloads</title>
<style>
@font-face{{font-family:Saira;src:url(../fonts/saira-latin-wdth-normal.woff2) format("woff2");font-weight:100 900;font-stretch:50% 125%}}
@font-face{{font-family:"JetBrains Mono";src:url(../fonts/jetbrains-mono-latin-wght-normal.woff2) format("woff2");font-weight:100 800}}
:root{{--ground:#E4E5E1;--raised:#D6D7D3;--ink:#111214;--ink2:#4E5155}}
@media (prefers-color-scheme:dark){{:root{{--ground:#141516;--raised:#222427;--ink:#ECEDEA;--ink2:#A0A4A9}}}}
body{{margin:0;background:var(--ground);color:var(--ink);font:400 16px/1.55 Saira,system-ui,sans-serif}}
main{{max-width:1100px;margin:0 auto;padding:48px 16px}}
h1{{font-size:clamp(34px,5vw,56px);font-stretch:116%;font-weight:640;letter-spacing:-.03em;margin:0 0 8px}}
h2{{margin:56px 0 4px;font-size:30px}} h3{{margin:24px 0 6px;font-size:18px}} p{{color:var(--ink2)}} a{{color:var(--ink);font-weight:600}}
table{{width:100%;border-collapse:separate;border-spacing:0 4px}} td{{background:var(--raised);padding:10px 12px;vertical-align:top}}
table{{table-layout:fixed}} td:nth-child(1){{width:48%}} td:nth-child(2){{width:84px;white-space:nowrap}}
td span{{display:block;color:var(--ink2);font-size:14px;margin-top:2px}}
code{{font:12px/1.4 "JetBrains Mono",monospace;word-break:break-all;color:var(--ink2)}}
@media (max-width:640px){{td:nth-child(3){{display:none}} td:nth-child(1){{width:auto}}}}
</style></head><body><main>
<h1>Descargas</h1>
<p>Para empezar, sigue la <a href="../#instalar">guía de instalación</a>: en Linux y macOS, <a href="../install.sh">install.sh</a> descarga y comprueba lo que necesita cada computadora. Cada archivo aparece en <code>SHA256SUMS</code> de su versión.</p>
{body}
</main></body></html>
"""


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "downloads"
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    published = []
    releases = []
    if token:
        releases = json.loads(_get(f"{API}/repos/{REPO}/releases?per_page=30", token, "application/vnd.github+json"))
    else:
        print("GITHUB_TOKEN not set: the landing is published without downloads")
    for rel in releases:
        if rel.get("draft"):
            continue
        m = TAG_RE.match(rel.get("tag_name", ""))
        if not m:
            print(f"skipping release with tag {rel.get('tag_name')!r}")
            continue
        version = m.group(1)
        assets = {a["name"]: a for a in rel.get("assets", []) if NAME_RE.match(a.get("name", ""))}
        if "SHA256SUMS" not in assets:
            print(f"skipping {version}: no SHA256SUMS")
            continue
        sums_raw = _get(assets["SHA256SUMS"]["url"], token, "application/octet-stream")
        sums = _sums(sums_raw.decode("utf-8"))
        target = os.path.join(out, f"v{version}")
        os.makedirs(target, exist_ok=True)
        files = []
        for name, asset in sorted(assets.items()):
            data = sums_raw if name == "SHA256SUMS" else _get(asset["url"], token, "application/octet-stream")
            digest = hashlib.sha256(data).hexdigest()
            if name not in ("SHA256SUMS", "SHA256SUMS.minisig"):
                if name not in sums:
                    # Never publish a file the release does not vouch for.
                    print(f"skipping {version}/{name}: not in SHA256SUMS")
                    continue
                if sums[name] != digest:
                    raise SystemExit(f"{version}/{name}: does not match SHA256SUMS")
            with open(os.path.join(target, name), "wb") as fh:
                fh.write(data)
            files.append({"name": name, "size": len(data), "sha256": digest})
        published.append({"version": version, "tag": rel["tag_name"], "prerelease": bool(rel.get("prerelease")), "files": files})
        print(f"published {version}: {len(files)} files")

    os.makedirs(out, exist_ok=True)
    latest = published[0] if published else None
    with open(os.path.join(out, "latest.json"), "w", encoding="utf-8") as fh:
        json.dump({"latest": latest, "releases": [p["version"] for p in published]}, fh, indent=2)
    with open(os.path.join(out, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(_index(published))
    return 0


if __name__ == "__main__":
    sys.exit(main())
