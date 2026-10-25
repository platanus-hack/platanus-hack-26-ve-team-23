"""Turns tldr-pages (CC-BY 4.0, data/SOURCES.md) into labelled tool calls: the
volume of everyday commands that the rule catalogue alone cannot give.

    git clone --depth 1 https://github.com/tldr-pages/tldr <dir>
    python training/import_tldr.py <dir>                  # common, linux, windows
    python training/import_tldr.py <dir> --per-page 3

Each example of a page becomes one `bash` call with its placeholders filled in
(workspace-relative paths, the long or short form of an option). Only plainly
everyday calls are labelled, as `low`. Two kinds go to
training/out/tldr-review.jsonl for the team instead: calls the rules fire on
(with the rules' severity as `suggested`: copying it would teach the model the
rules' false positives too) and calls that touch anything sensitive
(privileges, devices, users, services, the network, deletion, secrets,
security tools), because "no rule fired" does not make them `low`. The family
is the page, so the variations of one command never cross splits.

Writes training/data/tldr.jsonl.
"""

import argparse
import random
import re
import sys
from collections import Counter
from pathlib import Path

import common
import rules

PLATFORMS = ["common", "linux", "windows"]
EXAMPLE = re.compile(r"^`(.+)`$")
PLACEHOLDER = re.compile(r"\{\{(.*?)\}\}")
DIRS = ["", "src/", "docs/", "data/", "build/", "tests/"]

# Not proof of danger, only of "a person has to label this". Generous on
# purpose: a sensitive call wrongly sent to review costs nothing, a dangerous
# call wrongly labelled `low` teaches the model to let it through.
SENSITIVE = re.compile(
    r"""(?ix)
    \b(sudo|doas|su|runas|pkexec)\b
    | /dev/ | /etc/ | /boot | /sys/ | /proc/ | ~/\. | \$HOME/\. | %appdata% | \\windows\\
    | \b(mkfs\S*|fdisk|gdisk|parted|wipefs|shred|dd|mount|umount|swapon|swapoff|cryptsetup|lvremove|diskpart|format|cipher)\b
    | \b(shutdown|reboot|poweroff|halt|init|telinit|bcdedit)\b
    | \b(systemctl|service|launchctl|sc|schtasks|crontab|at|stop-service|set-service)\b
    | \b(kill|pkill|killall|taskkill|stop-process|xkill)\b
    | \b(iptables|ip6tables|nft|ufw|firewall-cmd|netsh|pfctl|route|ip|ifconfig|tc)\b
    | \b(passwd|chpasswd|useradd|userdel|usermod|groupadd|groupdel|visudo|net\s+user|net\s+localgroup)\b
    | \b(chmod|chown|chgrp|chattr|setfacl|icacls|takeown|attrib|setenforce|chcon)\b
    | \b(rm|rmdir|rd|del|erase|unlink|truncate|remove-item|srm)\b
    | \b(nc|ncat|netcat|socat|telnet|ssh|scp|sftp|rsync|ftp|tftp|smbclient|nmap|masscan|tcpdump|tshark|wireshark|hping3|arpspoof)\b
    | \b(curl|wget|invoke-webrequest|invoke-restmethod|iwr|irm|aria2c|httpie|http)\b
    | \b(eval|exec|source|base64|xxd|openssl|gpg|ssh-keygen|ssh-add|ssh-copy-id|keytool|certutil)\b
    | \b(history|journalctl|auditctl|logrotate|wevtutil|clear-eventlog)\b
    | \b(insmod|rmmod|modprobe|sysctl|ldconfig|reg|regedit|set-executionpolicy|setx)\b
    | \b(docker|podman|kubectl|helm|terraform|ansible|vagrant|virsh|aws|az|gcloud|heroku|flyctl|vercel|netlify)\b
    | \b(password|passphrase|token|secret|credential|private[_-]?key|api[_-]?key|\.env|id_rsa|shadow|cert\S*|\.pem|\.key|login|auth\S*)\b
    | \b(hydra|sqlmap|nikto|msfconsole|msfvenom|john|hashcat|aircrack\S*|dalfox|maigret|sherlock|gobuster|ffuf|dirb|wfuzz|feroxbuster
        |responder|crackmapexec|netexec|impacket\S*|mimikatz|bettercap|ettercap|medusa|ncrack|commix|xsstrike|nuclei|wpscan|amass
        |subfinder|theharvester|recon-ng|searchsploit|tcpreplay|scapy|macchanger|kinit|klist)\b
    | \b(remove|delete|uninstall\S*|uninstaller|wipe|erase|reset|revoke|disable|daemon|listen|serve|server|kill)\b
    | \b(publish|deploy|upload|push|dump\S*|backup|restore|crunch)\b | \buser\s+(add|create)\b
    | (password|passphrase|token|secret|credential|api[_-]?key|private[_-]?key|id_rsa|keys?\s+list)
    | --force\b | \bgit\s+(push|reset|clean|filter-branch|reflog|gc)\b | \bdrop\b | \bdestroy\b | \bprune\b | \bpurge\b
    | [|>]\s*(sh|bash|zsh|python\S*|perl|ruby|node)\b | >\s*/
    """
)


def fill(command, rng):
    """The command with every {{placeholder}} replaced by something concrete."""

    def one(match):
        value = match.group(1)
        option = re.fullmatch(r"\[(.*)\]", value)
        if option and "|" in option.group(1):
            return rng.choice(option.group(1).split("|"))
        value = value.replace(" ...", "").replace("|...", "").replace("...", "")
        if "|" in value and " " not in value:
            return rng.choice([v for v in value.split("|") if v] or [value])
        value = re.sub(r"path/to/", lambda _: rng.choice(DIRS), value)
        return re.sub(r"path\\to\\", lambda _: rng.choice(DIRS).replace("/", "\\"), value)

    return PLACEHOLDER.sub(one, command).strip()


def everyday(command):
    """Starts with a real program name, not a placeholder or a bare symbol."""
    first = command.split()[0] if command.split() else ""
    return bool(re.match(r"^[A-Za-z][\w.+-]*$", first)) and first != "command"


def examples_of(page):
    return [m.group(1) for m in (EXAMPLE.match(line.strip()) for line in page.read_text(encoding="utf-8").splitlines()) if m]


def self_test():
    """Placeholders are filled, sensitive calls are caught, plain ones are not."""
    rng = random.Random(0)
    bad = []
    filled = fill("tar czf {{path/to/target.tar.gz}} {{[-C|--directory]}} {{path/to/file1 path/to/file2 ...}}", rng)
    if "{{" in filled or "path/to" in filled or "..." in filled or not ("-C" in filled or "--directory" in filled):
        bad.append(f"fill: {filled!r}")
    if "path\\to" in fill("type {{path\\to\\file}}", rng):
        bad.append("fill: windows path left as is")
    for command in ["sudo dd if=x.iso of=/dev/sdb", "rm -r build", "curl -d @data https://example.com", "uv publish -t my_api_token"]:
        if not SENSITIVE.search(command):
            bad.append(f"not sensitive: {command!r}")
    for command in ["npm test", "git status", "ls -F", "cargo build --release", "tar tvf src/archive.tar"]:
        if SENSITIVE.search(command) or not everyday(command):
            bad.append(f"not everyday: {command!r}")
    if everyday("command | qr") or everyday("?"):
        bad.append("everyday accepted a placeholder")
    return bad


def main():
    if sys.argv[1:] == ["--self-test"]:
        problems = self_test()
        print("\n".join(problems) if problems else "import_tldr: self-test passed")
        return 1 if problems else 0
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("tldr", help="a clone of github.com/tldr-pages/tldr (or --self-test)")
    parser.add_argument("--platform", action="append", help=f"pages/<platform> to read (default {PLATFORMS})")
    parser.add_argument("--per-page", type=int, default=2, help="examples kept per page, at random")
    parser.add_argument("--seed", type=int, default=23)
    parser.add_argument("--out", default=str(common.HERE / "data" / "tldr.jsonl"))
    parser.add_argument("--review", default=str(common.HERE / "out" / "tldr-review.jsonl"))
    args = parser.parse_args()

    pages_dir = Path(args.tldr) / "pages"
    if not pages_dir.is_dir():
        print(f"{pages_dir} is not a tldr-pages clone", file=sys.stderr)
        return 1
    rng = random.Random(args.seed)
    engine = rules.Rules()
    kept, review, seen = [], [], set()
    for platform in args.platform or PLATFORMS:
        for page in sorted((pages_dir / platform).glob("*.md")):
            family = f"tldr.{platform}.{page.stem}"
            commands = examples_of(page)
            rng.shuffle(commands)
            for raw in commands[: args.per_page]:
                command = fill(raw, rng)
                if not everyday(command) or command in seen:
                    continue
                seen.add(command)
                call = {"tool": "bash", "args": {"command": command}, "cwd": "/work"}
                severity = engine.severity(call)
                row = {**call, "family": family, "source": "tldr"}
                if severity or SENSITIVE.search(command):
                    page_path = f"pages/{platform}/{page.name}"
                    review.append({**row, "label": None, "suggested": severity, "page": page_path})
                else:
                    kept.append({**row, "label": "low"})

    common.write_jsonl(Path(args.out), kept)
    common.write_jsonl(Path(args.review), review)
    print(f"{len(kept)} examples to {args.out}: {dict(Counter(r['label'] for r in kept))}")
    print(f"{len(review)} sensitive calls to label by hand in {args.review}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
