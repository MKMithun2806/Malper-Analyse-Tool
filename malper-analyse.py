#!/usr/bin/env python3
"""
malper-analyse -- Vulnerability report validator & Obsidian attack map generator
Uses OpenRouter API to reanalyse scanner output and produce clean Obsidian markdown.
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# --------------------------------------------------------------
# Colour helpers (no deps)
# --------------------------------------------------------------
R   = "\033[1;31m"
G   = "\033[1;32m"
Y   = "\033[1;33m"
C   = "\033[1;36m"
B   = "\033[1;34m"
M   = "\033[1;35m"
W   = "\033[0m"
DIM = "\033[2m"

BANNER = "\n" + C + """
  ████████╗ ██████╗  ██████╗ ██╗     ██████╗  ██████╗ ██╗  ██╗
  ╚══██╔══╝██╔═══██╗██╔═══██╗██║    ██╔════╝ ██╔═══██╗╚██╗██╔╝
     ██║   ██║   ██║██║   ██║██║    ██║  ███╗██║   ██║ ╚███╔╝ 
     ██║   ██║   ██║██║   ██║██║    ██║   ██║██║   ██║ ██╔██╗ 
     ██║   ╚██████╔╝╚██████╔╝███████╗╚██████╔╝╚██████╔╝██╔╝ ██╗
     ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝
""" + W + DIM + "  malper-analyse  .  pentest report validator & obsidian attack mapper\n" + W

DEFAULT_MODEL  = "openrouter/auto"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
ENV_KEY_NAME   = "OPENROUTER_API_KEY"
ENV_MODEL_NAME = "MALPER_MODEL"


# --------------------------------------------------------------
# API key management
# --------------------------------------------------------------
def get_api_key():
    key = os.environ.get(ENV_KEY_NAME)
    if key:
        return key

    print("\n" + Y + "[!]" + W + " No " + C + ENV_KEY_NAME + W + " found in environment.\n")
    print("    Get one free at " + B + "https://openrouter.ai/keys" + W + "\n")
    try:
        key = input("    " + G + "Paste your OpenRouter API key: " + W).strip()
    except KeyboardInterrupt:
        print("\n" + R + "[x]" + W + " Cancelled.")
        sys.exit(1)

    if not key:
        print(R + "[x]" + W + " No key supplied. Exiting.")
        sys.exit(1)

    _persist_env(ENV_KEY_NAME, key)
    os.environ[ENV_KEY_NAME] = key
    return key


def _persist_env(name, value):
    # 1. /etc/environment -- system-wide, survives sudo
    etc_env = Path("/etc/environment")
    try:
        text = etc_env.read_text() if etc_env.exists() else ""
        lines = text.splitlines(keepends=True)
        new_lines = []
        replaced = False
        for line in lines:
            if line.startswith(name + "="):
                new_lines.append(name + '="' + value + '"\n')
                replaced = True
            else:
                new_lines.append(line)
        if not replaced:
            if new_lines and not new_lines[-1].endswith("\n"):
                new_lines.append("\n")
            new_lines.append(name + '="' + value + '"\n')
        etc_env.write_text("".join(new_lines))
        print(G + "[+]" + W + " Saved " + name + " to /etc/environment (system-wide)")
    except PermissionError:
        print(Y + "[!]" + W + " /etc/environment not writable -- run with sudo once to persist system-wide")
    except Exception as e:
        print(Y + "[!]" + W + " Could not write /etc/environment: " + str(e))

    # 2. Shell rc files for current user
    export_line = '\nexport ' + name + '="' + value + '"\n'
    for rc in [os.path.expanduser("~/.bashrc"), os.path.expanduser("~/.profile")]:
        try:
            text = Path(rc).read_text() if Path(rc).exists() else ""
            if name in text:
                lines = text.splitlines(keepends=True)
                new_lines = []
                for line in lines:
                    if line.startswith("export " + name + "="):
                        new_lines.append('export ' + name + '="' + value + '"\n')
                    else:
                        new_lines.append(line)
                Path(rc).write_text("".join(new_lines))
            else:
                with open(rc, "a") as f:
                    f.write(export_line)
            print(G + "[+]" + W + " Saved " + name + " to " + rc)
        except Exception as e:
            print(Y + "[!]" + W + " Could not write " + rc + ": " + str(e))


# --------------------------------------------------------------
# File loading
# --------------------------------------------------------------
def load_report(path):
    suffix = path.suffix.lower()
    if suffix not in {".json", ".md"}:
        print(R + "[x]" + W + " Unsupported file type '" + suffix + "'. Only .json and .md accepted.")
        sys.exit(1)
    if not path.exists():
        print(R + "[x]" + W + " File not found: " + str(path))
        sys.exit(1)
    raw = path.read_text(encoding="utf-8", errors="replace")
    if suffix == ".json":
        try:
            parsed = json.loads(raw)
            return json.dumps(parsed, indent=2)
        except json.JSONDecodeError as e:
            print(Y + "[!]" + W + " JSON parse warning: " + str(e) + " -- sending raw anyway.")
    return raw


# --------------------------------------------------------------
# System prompt
# --------------------------------------------------------------
SYSTEM_PROMPT = (
    "You are an elite penetration tester and red team operator reviewing an automated vulnerability scanner report.\n"
    "Automated scanners frequently over-report severity. They cannot understand actual exploitability, business context,\n"
    "or whether a finding is behind auth layers that make it practically unexploitable.\n\n"
    "Your job:\n"
    "1. Critically reanalyse every finding. Downgrade severity where the scanner is clearly wrong.\n"
    "2. Remove false positives -- if a finding has no realistic exploit path, flag it as FP and exclude it.\n"
    "3. Validate CVEs / CWEs -- only include them if they are real and match the described vulnerability.\n"
    "4. Produce a clean, obsidian-compatible markdown report with the structure below.\n"
    "5. Always think like an attacker. For each real vuln ask: can I actually exploit this? What is the impact?\n\n"
    "OUTPUT FORMAT (strictly follow this):\n\n"
    "# Shield Vulnerability Analysis Report\n"
    "> Auto-generated by malper-analyse | {timestamp}\n\n"
    "## Executive Summary\n"
    "One paragraph plain-English summary for a non-technical audience. Include overall risk level.\n\n"
    "## Risk Score\n"
    "| Metric | Value |\n"
    "|---|---|\n"
    "| Critical | N |\n"
    "| High | N |\n"
    "| Medium | N |\n"
    "| Low | N |\n"
    "| False Positives Removed | N |\n"
    "| Overall Risk | Critical / High / Medium / Low |\n\n"
    "## Validated Vulnerabilities\n\n"
    "For EACH real vulnerability use this card format:\n\n"
    "### [SEVERITY EMOJI] CVE-XXXX-XXXX -- Short Title\n"
    "(Red Circle = Critical, Orange Circle = High, Yellow Circle = Medium, Blue Circle = Low)\n\n"
    "| Field | Detail |\n"
    "|---|---|\n"
    "| **Severity** | Critical / High / Medium / Low |\n"
    "| **CVSS** | X.X |\n"
    "| **CVE** | CVE-XXXX-XXXX or N/A |\n"
    "| **CWE** | CWE-XXX |\n"
    "| **Affected Component** | |\n"
    "| **Exploitability** | Easy / Moderate / Hard |\n"
    "| **Auth Required** | Yes / No |\n\n"
    "**Description**\n"
    "Two to three sentences explaining what the vuln actually is.\n\n"
    "**Real-World Impact**\n"
    "What an attacker can actually achieve if exploited.\n\n"
    "**Proof of Concept Sketch**\n"
    "High-level steps or payload skeleton. Do NOT write full working exploits.\n\n"
    "**Remediation**\n"
    "Concrete fix. Version to upgrade to, config to change, code pattern to fix.\n\n"
    "**Tags**\n"
    "`#vuln/[category]` `[[Component Name]]` `[[CVE-XXXX-XXXX]]`\n\n"
    "---\n\n"
    "## Removed / Downgraded Findings\n\n"
    "| Original Finding | Original Severity | Action | Reason |\n"
    "|---|---|---|---|\n\n"
    "---\n\n"
    "## Attack Map\n\n"
    "> Obsidian graph-compatible. Each node is a wikilink. Copy this section into your vault.\n\n"
    "```mermaid\n"
    "graph TD\n"
    "    A[External Attacker] --> B{Initial Access}\n"
    "    B --> |Exploit CVE-XXXX-XXXX| C[Foothold]\n"
    "    C --> D{Lateral Movement}\n"
    "    D --> E[Privilege Escalation]\n"
    "    E --> F[Impact: Data Exfil / RCE / Persistence]\n"
    "```\n\n"
    "### Obsidian Node Links\n"
    "- [[Component]] -- reason it is a node in the attack path\n\n"
    "---\n\n"
    "## Analyst Notes\n"
    "Additional observations, things to manually verify, scanner quirks.\n\n"
    "---\n\n"
    "*Report generated by malper-analyse | Model: {model}*\n"
)


# --------------------------------------------------------------
# OpenRouter API call
# --------------------------------------------------------------
def call_openrouter(api_key, model, report_content, filename):
    import urllib.request

    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    system = SYSTEM_PROMPT.replace("{timestamp}", ts).replace("{model}", model)
    user_msg = "Vulnerability scanner report from `" + filename + "`:\n\n---\n" + report_content + "\n---"

    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user_msg},
        ],
        "temperature": 0.3,
        "max_tokens": 8192,
    }).encode("utf-8")

    req = urllib.request.Request(
        OPENROUTER_URL,
        data=payload,
        headers={
            "Authorization": "Bearer " + api_key,
            "Content-Type":  "application/json",
            "HTTP-Referer":  "https://github.com/MKMithun2806/Malper-Analyse-Tool",
            "X-Title":       "malper-analyse",
        },
        method="POST",
    )

    print(C + "[->]" + W + " Sending to " + B + model + W + " via OpenRouter...")
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        print(R + "[x]" + W + " HTTP " + str(e.code) + ": " + err_body)
        sys.exit(1)
    except Exception as e:
        print(R + "[x]" + W + " Request failed: " + str(e))
        sys.exit(1)

    try:
        return body["choices"][0]["message"]["content"]
    except (KeyError, IndexError):
        print(R + "[x]" + W + " Unexpected response:\n" + json.dumps(body, indent=2))
        sys.exit(1)


# --------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------
def write_output(input_path, content, out_dir=None):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = Path(out_dir) if out_dir else input_path.parent
    out_path = base / (input_path.stem + "_analysed_" + ts + ".md")
    out_path.write_text(content, encoding="utf-8")
    return out_path


def print_summary(out_path, content):
    lines = content.splitlines()
    fps = 0
    for l in lines:
        if "False Positives Removed" in l:
            for p in l.split("|"):
                p = p.strip()
                if p.isdigit():
                    fps = int(p)
                    break

    crit = sum(1 for l in lines if "| Critical |" in l or "| **Severity** | Critical |" in l)
    high = sum(1 for l in lines if "| High |" in l or "| **Severity** | High |" in l)
    med  = sum(1 for l in lines if "| Medium |" in l or "| **Severity** | Medium |" in l)
    low  = sum(1 for l in lines if "| Low |" in l or "| **Severity** | Low |" in l)

    print("\n" + G + "-" * 55 + W)
    print("  " + G + "[+]" + W + " Analysis complete!")
    print("  " + G + "[+]" + W + " Report -> " + C + str(out_path) + W)
    print("")
    print("  " + R + "* Critical " + str(crit).rjust(3) + W +
          "    " + Y + "* Medium " + str(med).rjust(3) + W)
    print("  " + M + "* High     " + str(high).rjust(3) + W +
          "    " + B + "* Low    " + str(low).rjust(3) + W)
    if fps:
        print("  " + DIM + "  " + str(fps) + " false positive(s) stripped" + W)
    print(G + "-" * 55 + W + "\n")


# --------------------------------------------------------------
# Entry point
# --------------------------------------------------------------
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        prog="malper-analyse",
        description="Reanalyse a vuln scanner report, strip FPs, generate Obsidian attack map.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  malper-analyse report.json\n"
            "  malper-analyse nmap_vulns.md --model mistralai/mistral-7b-instruct\n"
            "  malper-analyse scan.json --output ~/vault/reports/\n\n"
            "env vars:\n"
            "  OPENROUTER_API_KEY   your key (prompted + saved if missing)\n"
            "  MALPER_MODEL         override model (default: openrouter/auto)\n"
        ),
    )
    parser.add_argument("report", metavar="FILE", help=".json or .md vulnerability report")
    parser.add_argument("--model", "-m", default=None, help="OpenRouter model string")
    parser.add_argument("--output", "-o", default=None, help="Output directory")
    parser.add_argument("--no-banner", action="store_true", help="Suppress banner")
    args = parser.parse_args()

    input_path = Path(args.report).expanduser().resolve()

    out_dir = None
    if args.output:
        out_dir = Path(args.output).expanduser().resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

    model   = args.model or os.environ.get(ENV_MODEL_NAME) or DEFAULT_MODEL
    api_key = get_api_key()

    print(G + "[+]" + W + " Loading " + C + input_path.name + W + "...")
    report_content = load_report(input_path)
    size_kb = round(len(report_content.encode()) / 1024, 1)
    print(G + "[+]" + W + " Read " + str(size_kb) + " KB  --  model: " + B + model + W)

    result   = call_openrouter(api_key, model, report_content, input_path.name)
    out_path = write_output(input_path, result, out_dir)
    print_summary(out_path, result)


if __name__ == "__main__":
    main()
