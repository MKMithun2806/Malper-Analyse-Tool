# 🔍 Malper-Analyse

> **Vulnerability report validator & Obsidian attack map generator**  
> Reanalyses automated scanner output, strips false positives, corrects severity ratings, and produces a clean Obsidian-compatible markdown report with a Mermaid attack map.

-----

## ⚡ One-Shot Install

```bash
curl -sL $(curl -s https://api.github.com/repos/MKMithun2806/Malper-Analyse-Tool/releases/latest \
  | grep "browser_download_url.*\.deb" \
  | cut -d '"' -f 4) -o /tmp/malper-analyse.deb \
  && sudo dpkg -i /tmp/malper-analyse.deb \
  && rm /tmp/malper-analyse.deb
```

That’s it. No pip, no venv, no extra deps — just `python3` (already on your system).

-----

## 🚀 Usage

```bash
malper-analyse report.json
malper-analyse nmap_vulns.md
malper-analyse scan.json --output ~/vault/reports/
malper-analyse report.md --model mistralai/mistral-7b-instruct
```

### Arguments

|Argument        |Description                                               |
|----------------|----------------------------------------------------------|
|`FILE`          |Path to `.json` or `.md` vulnerability report (required)  |
|`--model`, `-m` |Override the OpenRouter model (default: `openrouter/auto`)|
|`--output`, `-o`|Output directory (default: same dir as input file)        |
|`--no-banner`   |Suppress the ASCII banner                                 |

### Environment Variables

|Variable            |Description                                                         |
|--------------------|--------------------------------------------------------------------|
|`OPENROUTER_API_KEY`|Your OpenRouter API key — prompted and saved on first run if missing|
|`MALPER_MODEL`      |Persistent model override (e.g. `anthropic/claude-opus-4-5`)        |

-----

## 🔑 API Key

Get a free key at **[openrouter.ai/keys](https://openrouter.ai/keys)**.

On first run without a key set, `malper-analyse` will prompt you to paste it and **automatically persist it** to `~/.bashrc` and `~/.profile` — no manual setup needed.

```bash
# Or set it manually
export OPENROUTER_API_KEY=sk-or-v1-...
```

-----

## 📄 Output Format

Output is saved as `<input>_analysed_<timestamp>.md` next to the input file (or in `--output` dir).

The report includes:

- **Executive Summary** — plain-English risk overview
- **Risk Score Table** — Critical / High / Medium / Low / FP count
- **Validated Vulnerability Cards** — per-vuln with CVSS, CVE, CWE, exploitability, PoC sketch, remediation, Obsidian `[[wikilinks]]`
- **Removed / Downgraded Findings** — table of what the scanner got wrong and why
- **🗺️ Attack Map** — Mermaid flowchart + Obsidian node links for vault graph view

### Example Output

```
report_analysed_20260428_143201.md
```

```markdown
# 🛡️ Vulnerability Analysis Report

## Risk Score
| Critical | High | Medium | Low | FPs Removed |
|---|---|---|---|---|
| 2 | 4 | 3 | 1 | 7 |

### 🔴 CVE-2025-67896 — Exim Heap Buffer Overflow
...

## 🗺️ Attack Map
graph TD
    A[🌐 External Attacker] --> B{Initial Access}
    B --> |Exploit [[CVE-2025-67896]]| C[Foothold: Mail Server]
    ...
```

-----

## 🧠 How It Works

Automated scanners lie. They flag everything as Critical because they can’t reason about:

- Whether a service is actually reachable from the internet
- Whether auth/WAF layers make a vuln practically unexploitable
- Whether a CVE actually applies to the exact version/config in use

`malper-analyse` sends your report to **OpenRouter’s auto-routing model** (`openrouter/auto`) — which picks the best available free model — with a system prompt that explicitly tells it to assume the scanner is slightly wrong and to think like a red team operator validating actual exploitability.

-----

## 🏗️ Requirements

- Python 3.8+
- Debian/Ubuntu-based system (for `.deb` install)
- Internet access to OpenRouter API
- Free [OpenRouter account](https://openrouter.ai)

-----

## 🛠️ Manual Install (no .deb)

```bash
git clone https://github.com/MKMithun2806/Malper-Analyse-Tool
cd Malper-Analyse-Tool
sudo cp malper_analyse.py /usr/local/bin/malper-analyse
sudo chmod +x /usr/local/bin/malper-analyse
```

-----

## 📦 Build .deb from Source

```bash
git clone https://github.com/MKMithun2806/Malper-Analyse-Tool
cd Malper-Analyse-Tool
chmod +x build.sh && ./build.sh
sudo dpkg -i dist/malper-analyse_*.deb
```

-----

## 🗺️ Watchdog Integration

`malper-analyse` pairs naturally with the [Watchdog](https://github.com/MKMithun2806) recon pipeline — drop it at the end of your n8n flow to auto-analyse whatever Nmap/Nuclei/searchsploit pushes to NAS:

```
Flipper Zero → ESP32 → n8n webhook → EC2 recon → NAS → malper-analyse → Obsidian vault
```

-----

## 📝 License

MIT — do whatever, don’t blame me.

-----

<div align="center">
  <sub>Built by <a href="https://github.com/MKMithun2806">MKMithun2806</a> · powered by <a href="https://openrouter.ai">OpenRouter</a></sub>
</div>
