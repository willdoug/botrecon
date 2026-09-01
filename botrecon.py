#!/usr/bin/env python3

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ============================================================
# CONFIGURAÇÃO
# ============================================================

TARGET = "EXAMPLE.com"

BASE_DIR = Path("recon_results") / TARGET.replace("/", "_")

THREADS = 30

# NÃO COPIAR WORDLISTS.
# O script apenas referencia os arquivos originais.
SECLists = Path("/opt/SecLists")

WORDLIST_SOURCES = {
    "dns": [
        SECLists / "Discovery/DNS/subdomains-top1million-5000.txt",
        SECLists / "Discovery/DNS/subdomains-top1million-20000.txt",
        SECLists / "Discovery/DNS/bitquark-subdomains-top100000.txt",
        SECLists / "Discovery/DNS/namelist.txt",
        SECLists / "Discovery/DNS/fierce-hostlist.txt",
    ],

    "web": [
        SECLists / "Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt",
        SECLists / "Discovery/Web-Content/raft-medium-directories.txt",
        SECLists / "Discovery/Web-Content/trickest-robots-disallowed-wordlists/top-10000.txt",
        Path("/usr/share/wordlists/dirb/common.txt"),
    ],

    "files": [
        SECLists / "Discovery/Web-Content/raft-medium-files.txt",
        SECLists / "Discovery/Web-Content/raft-medium-words.txt",
    ],
}

# ============================================================
# ESTRUTURA
# ============================================================

DIRS = {
    "00_wordlists": BASE_DIR / "00_wordlists",
    "01_subdomains": BASE_DIR / "01_subdomains",
    "02_dns": BASE_DIR / "02_dns",
    "03_ips": BASE_DIR / "03_ips",
    "04_ports": BASE_DIR / "04_ports",
    "05_services": BASE_DIR / "05_services",
    "06_http": BASE_DIR / "06_http",
    "07_technologies": BASE_DIR / "07_technologies",
    "08_urls": BASE_DIR / "08_urls",
    "09_endpoints": BASE_DIR / "09_endpoints",
    "10_files": BASE_DIR / "10_files",
    "11_directories": BASE_DIR / "11_directories",
    "12_vulnerabilities": BASE_DIR / "12_vulnerabilities",
    "13_reports": BASE_DIR / "13_reports",
}

for directory in DIRS.values():
    directory.mkdir(parents=True, exist_ok=True)

REPORT = DIRS["13_reports"] / "REPORT.md"
COMMAND_LOG = DIRS["13_reports"] / "commands.log"
CHECKPOINT = DIRS["13_reports"] / "checkpoint.json"

# ============================================================
# ESTADO
# ============================================================

STOP_REQUESTED = False


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(message):
    print(f"[{now()}] {message}", flush=True)


def banner(message):
    print()
    print("=" * 78)
    print(message)
    print("=" * 78)
    print(flush=True)


def command_exists(command):
    return shutil.which(command) is not None


def write_file(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        content,
        encoding="utf-8",
        errors="ignore"
    )


def append_file(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open(
        "a",
        encoding="utf-8",
        errors="ignore"
    ) as f:
        f.write(content)


def clean_lines(text):
    return sorted(
        set(
            line.strip()
            for line in text.splitlines()
            if line.strip()
        )
    )


def read_lines(path):
    if not path.exists():
        return []

    return clean_lines(
        path.read_text(
            encoding="utf-8",
            errors="ignore"
        )
    )


def save_unique(lines, path):
    if isinstance(lines, str):
        lines = lines.splitlines()

    cleaned = sorted(
        set(
            x.strip()
            for x in lines
            if x and x.strip()
        )
    )

    write_file(
        path,
        "\n".join(cleaned) +
        ("\n" if cleaned else "")
    )

    return cleaned


# ============================================================
# CHECKPOINT
# ============================================================

def load_checkpoint():
    if not CHECKPOINT.exists():
        return {
            "target": TARGET,
            "started": now(),
            "stages": {},
            "tools": {}
        }

    try:
        return json.loads(
            CHECKPOINT.read_text(
                encoding="utf-8"
            )
        )
    except Exception:
        return {
            "target": TARGET,
            "started": now(),
            "stages": {},
            "tools": {}
        }


STATE = load_checkpoint()


def save_checkpoint():
    STATE["updated"] = now()

    tmp = CHECKPOINT.with_suffix(".tmp")

    tmp.write_text(
        json.dumps(
            STATE,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    tmp.replace(CHECKPOINT)


def tool_key(stage, tool):
    return f"{stage}:{tool}"


def is_tool_done(stage, tool):
    return STATE.get("tools", {}).get(
        tool_key(stage, tool),
        {}
    ).get("status") == "DONE"


def mark_tool_running(stage, tool):
    STATE.setdefault("tools", {})[
        tool_key(stage, tool)
    ] = {
        "status": "RUNNING",
        "started": now()
    }

    save_checkpoint()


def mark_tool_done(stage, tool, output=None):
    data = {
        "status": "DONE",
        "finished": now()
    }

    if output:
        data["output"] = str(output)

    STATE.setdefault("tools", {})[
        tool_key(stage, tool)
    ] = data

    save_checkpoint()


def mark_tool_failed(stage, tool, reason=""):
    STATE.setdefault("tools", {})[
        tool_key(stage, tool)
    ] = {
        "status": "FAILED",
        "finished": now(),
        "reason": reason
    }

    save_checkpoint()


def stage_done(stage):
    return STATE.get(
        "stages",
        {}
    ).get(stage, {}).get("status") == "DONE"


def mark_stage_done(stage):
    STATE.setdefault("stages", {})[stage] = {
        "status": "DONE",
        "finished": now()
    }

    save_checkpoint()


# ============================================================
# SINAL
# ============================================================

def signal_handler(signum, frame):
    global STOP_REQUESTED

    STOP_REQUESTED = True

    log("INTERRUPÇÃO SOLICITADA.")
    log("Checkpoint salvo. O próximo início continuará daqui.")


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# ============================================================
# EXECUÇÃO DE FERRAMENTAS
# ============================================================

def run_cmd(
    stage,
    tool,
    cmd,
    output_file=None,
    timeout=1800
):
    """
    Uma ferramenta = uma unidade de checkpoint.

    Se o processo for interrompido:
    - NÃO marca DONE
    - o próximo início executará novamente essa ferramenta.
    """

    global STOP_REQUESTED

    if is_tool_done(stage, tool):
        log(f"[SKIP] [{tool}] checkpoint DONE")
        return ""

    if not command_exists(cmd[0]):
        log(f"[AUSENTE] [{tool}] {cmd[0]}")
        return ""

    mark_tool_running(stage, tool)

    command_string = " ".join(
        str(x) for x in cmd
    )

    banner(
        f"[FERRAMENTA] {tool}\n"
        f"[ETAPA] {stage}\n"
        f"[COMANDO] {command_string}"
    )

    append_file(
        COMMAND_LOG,
        f"\n[{now()}]\n"
        f"[STAGE] {stage}\n"
        f"[TOOL] {tool}\n"
        f"$ {command_string}\n"
    )

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="ignore",
            bufsize=1
        )

        output_lines = []

        start_time = time.time()

        while True:

            if STOP_REQUESTED:
                process.terminate()

                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()

                append_file(
                    COMMAND_LOG,
                    "\n[INTERRUPTED]\n"
                )

                log(
                    f"[INTERRUPT] [{tool}] "
                    "não foi marcado como concluído."
                )

                return ""

            if time.time() - start_time > timeout:
                process.kill()

                log(
                    f"[TIMEOUT] [{tool}] "
                    f"limite={timeout}s"
                )

                mark_tool_failed(
                    stage,
                    tool,
                    "timeout"
                )

                return ""

            line = process.stdout.readline()

            if line:
                line = line.rstrip()

                output_lines.append(line)

                print(
                    f"[{tool}] {line}",
                    flush=True
                )

                continue

            if process.poll() is not None:
                break

            time.sleep(0.05)

        returncode = process.returncode

        output = "\n".join(output_lines)

        append_file(
            COMMAND_LOG,
            output +
            f"\n[exit={returncode}]\n"
        )

        if output_file:
            write_file(
                output_file,
                output +
                ("\n" if output else "")
            )

        if returncode == 0:
            mark_tool_done(
                stage,
                tool,
                output_file
            )

            log(
                f"[DONE] [{tool}]"
            )

        else:
            mark_tool_failed(
                stage,
                tool,
                f"exit={returncode}"
            )

            log(
                f"[FAILED] [{tool}] exit={returncode}"
            )

        return output

    except Exception as exc:

        log(
            f"[ERRO] [{tool}] {exc}"
        )

        mark_tool_failed(
            stage,
            tool,
            str(exc)
        )

        return ""


# ============================================================
# WORDLISTS
# ============================================================

def prepare_wordlist_references():
    banner("[WORDLISTS] Verificando referências")

    for category, sources in WORDLIST_SOURCES.items():

        valid = []

        for path in sources:

            if path.exists():
                valid.append(path)

                log(
                    f"[WORDLIST] {category}: {path}"
                )
            else:
                log(
                    f"[WORDLIST AUSENTE] {path}"
                )

        # IMPORTANTE:
        # O arquivo abaixo contém apenas caminhos.
        # Não copia conteúdo das wordlists.
        reference_file = (
            DIRS["00_wordlists"] /
            f"{category}-sources.txt"
        )

        write_file(
            reference_file,
            "\n".join(
                str(x)
                for x in valid
            ) +
            ("\n" if valid else "")
        )

        log(
            f"[WORDLIST] {category}: "
            f"{len(valid)} arquivos referenciados"
        )


def wordlist_paths(category):
    return [
        path
        for path in WORDLIST_SOURCES.get(
            category,
            []
        )
        if path.exists()
    ]


def first_wordlist(category):
    paths = wordlist_paths(category)

    if not paths:
        return None

    return str(paths[0])


# ============================================================
# RELATÓRIO
# ============================================================

def init_report():

    if REPORT.exists():
        return

    write_file(
        REPORT,
        f"""# Deep Recon Report

## Target

`{TARGET}`

## Início

`{now()}`

## Modelo

Reconhecimento sequencial com checkpoint individual por ferramenta.

## Wordlists

As wordlists são referenciadas diretamente em `/opt/SecLists`.
Nenhuma wordlist é copiada para o diretório do alvo.

"""
    )


def report_section(title):
    append_file(
        REPORT,
        f"\n\n## {title}\n\n"
    )


def report_line(text):
    append_file(
        REPORT,
        text + "\n"
    )


# ============================================================
# 01 — SUBDOMÍNIOS
# ============================================================

def stage_subdomains():

    stage = "01_subdomains"

    if stage_done(stage):
        log(f"[SKIP] {stage} já concluída")
        return

    banner("01 — SUBDOMAIN ENUMERATION")

    discovered = set()

    # --------------------------------------------------------
    # subfinder
    # --------------------------------------------------------

    out = run_cmd(
        stage,
        "subfinder",
        [
            "subfinder",
            "-d",
            TARGET,
            "-silent"
        ],
        DIRS[stage] / "subfinder.txt",
        3600
    )

    discovered.update(
        clean_lines(out)
    )

    # --------------------------------------------------------
    # amass
    # --------------------------------------------------------

    out = run_cmd(
        stage,
        "amass",
        [
            "amass",
            "enum",
            "-passive",
            "-d",
            TARGET
        ],
        DIRS[stage] / "amass-passive.txt",
        3600
    )

    for line in out.splitlines():

        line = line.strip()

        if re.match(
            r"^[A-Za-z0-9._*-]+\." +
            re.escape(TARGET) +
            r"$",
            line
        ):
            discovered.add(line)

    # --------------------------------------------------------
    # chaos
    # --------------------------------------------------------

    out = run_cmd(
        stage,
        "chaos-client",
        [
            "chaos-client",
            "-d",
            TARGET
        ],
        DIRS[stage] / "chaos.txt",
        3600
    )

    discovered.update(
        clean_lines(out)
    )

    # --------------------------------------------------------
    # assetfinder
    # --------------------------------------------------------

    out = run_cmd(
        stage,
        "assetfinder",
        [
            "assetfinder",
            "--subs-only",
            TARGET
        ],
        DIRS[stage] / "assetfinder.txt",
        3600
    )

    discovered.update(
        clean_lines(out)
    )

    # --------------------------------------------------------
    # findomain
    # --------------------------------------------------------

    out = run_cmd(
        stage,
        "findomain",
        [
            "findomain",
            "-t",
            TARGET,
            "-q"
        ],
        DIRS[stage] / "findomain.txt",
        3600
    )

    discovered.update(
        clean_lines(out)
    )

    # --------------------------------------------------------
    # sublist3r
    # --------------------------------------------------------

    out = run_cmd(
        stage,
        "sublist3r",
        [
            "sublist3r",
            "-d",
            TARGET,
            "-o",
            str(DIRS[stage] / "sublist3r.txt")
        ],
        None,
        3600
    )

    discovered.update(
        clean_lines(out)
    )

    # --------------------------------------------------------
    # DNSGEN
    # --------------------------------------------------------

    seed_file = (
        DIRS[stage] /
        "dnsgen-input.txt"
    )

    if discovered:
        save_unique(
            discovered,
            seed_file
        )

        out = run_cmd(
            stage,
            "dnsgen",
            [
                "dnsgen",
                str(seed_file)
            ],
            DIRS[stage] / "dnsgen-generated.txt",
            3600
        )

        # dnsgen gera candidatos.
        # Só adicionamos candidatos válidos ao conjunto.
        discovered.update(
            clean_lines(out)
        )

    # --------------------------------------------------------
    # normalização
    # --------------------------------------------------------

    normalized = set()

    for host in discovered:

        host = host.lower().strip()

        host = host.replace(
            "http://",
            ""
        ).replace(
            "https://",
            ""
        )

        host = host.strip(".")

        if (
            host == TARGET or
            host.endswith("." + TARGET)
        ):
            normalized.add(host)

    subdomain_file = (
        DIRS[stage] /
        "all-subdomains.txt"
    )

    save_unique(
        normalized,
        subdomain_file
    )

    report_section(
        "01 — Subdomain Enumeration"
    )

    report_line(
        f"**Subdomínios:** `{len(normalized)}`"
    )

    for host in sorted(normalized):
        report_line(f"- `{host}`")

    mark_stage_done(stage)


# ============================================================
# 02 — DNS
# ============================================================

def stage_dns():

    stage = "02_dns"

    if stage_done(stage):
        log(f"[SKIP] {stage} já concluída")
        return

    banner("02 — DNS ENUMERATION")

    subdomains = read_lines(
        DIRS["01_subdomains"] /
        "all-subdomains.txt"
    )

    if not subdomains:
        log("[DNS] Nenhum subdomínio disponível.")
        mark_stage_done(stage)
        return

    input_file = (
        DIRS[stage] /
        "hosts.txt"
    )

    save_unique(
        subdomains,
        input_file
    )

    # dnsx

    run_cmd(
        stage,
        "dnsx",
        [
            "dnsx",
            "-l",
            str(input_file),
            "-a",
            "-aaaa",
            "-cname",
            "-resp",
            "-silent"
        ],
        DIRS[stage] / "dnsx.txt",
        3600
    )

    # shuffledns

    dns_wordlists = wordlist_paths("dns")

    if command_exists("shuffledns") and dns_wordlists:

        # shuffledns trabalha melhor com uma wordlist.
        # Usamos a referência maior disponível.
        selected = max(
            dns_wordlists,
            key=lambda p: p.stat().st_size
        )

        run_cmd(
            stage,
            "shuffledns",
            [
                "shuffledns",
                "-d",
                TARGET,
                "-w",
                str(selected),
                "-silent"
            ],
            DIRS[stage] / "shuffledns.txt",
            7200
        )

    # massdns

    if command_exists("massdns"):

        run_cmd(
            stage,
            "massdns",
            [
                "massdns",
                "-r",
                "/usr/share/wordlists/dns.txt",
                "-t",
                "A",
                "-o",
                "S",
                str(input_file)
            ],
            DIRS[stage] / "massdns.txt",
            3600
        )

    # extrair IPv4 de dnsx/massdns

    ips = set()

    for result_file in [
        DIRS[stage] / "dnsx.txt",
        DIRS[stage] / "massdns.txt",
    ]:

        for line in read_lines(result_file):

            found = re.findall(
                r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                line
            )

            ips.update(found)

    save_unique(
        ips,
        DIRS["03_ips"] / "ipv4.txt"
    )

    report_section("02 — DNS")

    report_line(
        f"**IPv4 encontrados:** `{len(ips)}`"
    )

    mark_stage_done(stage)


# ============================================================
# 03 — IP
# ============================================================

def stage_ips():

    stage = "03_ips"

    if stage_done(stage):
        log(f"[SKIP] {stage} já concluída")
        return

    banner("03 — IP ENUMERATION")

    ips = read_lines(
        DIRS["03_ips"] /
        "ipv4.txt"
    )

    save_unique(
        ips,
        DIRS["03_ips"] /
        "all-ips.txt"
    )

    report_section(
        "03 — IP Enumeration"
    )

    for ip in ips:
        report_line(
            f"- `{ip}`"
        )

    mark_stage_done(stage)


# ============================================================
# 04 — PORTAS
# ============================================================

def stage_ports():

    stage = "04_ports"

    if stage_done(stage):
        log(f"[SKIP] {stage} já concluída")
        return

    banner("04 — PORT ENUMERATION")

    subdomains = read_lines(
        DIRS["01_subdomains"] /
        "all-subdomains.txt"
    )

    ips = read_lines(
        DIRS["03_ips"] /
        "ipv4.txt"
    )

    if subdomains and command_exists("naabu"):

        targets = (
            DIRS[stage] /
            "targets.txt"
        )

        save_unique(
            subdomains,
            targets
        )

        run_cmd(
            stage,
            "naabu",
            [
                "naabu",
                "-list",
                str(targets),
                "-top-ports",
                "1000",
                "-silent"
            ],
            DIRS[stage] /
            "naabu-top1000.txt",
            7200
        )

    if ips and command_exists("nmap"):

        ip_file = (
            DIRS[stage] /
            "ips.txt"
        )

        save_unique(
            ips,
            ip_file
        )

        run_cmd(
            stage,
            "nmap",
            [
                "nmap",
                "-sV",
                "--open",
                "-T3",
                "-iL",
                str(ip_file)
            ],
            DIRS[stage] /
            "nmap-services.txt",
            7200
        )

    if ips and command_exists("masscan"):

        ip_file = (
            DIRS[stage] /
            "masscan-ips.txt"
        )

        save_unique(
            ips,
            ip_file
        )

        run_cmd(
            stage,
            "masscan",
            [
                "masscan",
                "-iL",
                str(ip_file),
                "--top-ports",
                "1000",
                "--rate",
                "1000"
            ],
            DIRS[stage] /
            "masscan.txt",
            7200
        )

    report_section(
        "04 — Port Enumeration"
    )

    mark_stage_done(stage)


# ============================================================
# 05 — SERVIÇOS
# ============================================================

def stage_services():

    stage = "05_services"

    if stage_done(stage):
        log(f"[SKIP] {stage} já concluída")
        return

    banner("05 — SERVICES / BANNERS")

    ips = read_lines(
        DIRS["03_ips"] /
        "ipv4.txt"
    )

    subdomains = read_lines(
        DIRS["01_subdomains"] /
        "all-subdomains.txt"
    )

    if ips and command_exists("nmap"):

        ip_file = (
            DIRS[stage] /
            "ips.txt"
        )

        save_unique(
            ips,
            ip_file
        )

        run_cmd(
            stage,
            "nmap-service-detection",
            [
                "nmap",
                "-sV",
                "-sC",
                "--open",
                "-T3",
                "-iL",
                str(ip_file)
            ],
            DIRS[stage] /
            "nmap-service-detection.txt",
            7200
        )

    if subdomains and command_exists("tlsx"):

        hosts = (
            DIRS[stage] /
            "hosts.txt"
        )

        save_unique(
            subdomains,
            hosts
        )

        run_cmd(
            stage,
            "tlsx",
            [
                "tlsx",
                "-l",
                str(hosts),
                "-silent"
            ],
            DIRS[stage] /
            "tls.txt",
            3600
        )

    mark_stage_done(stage)


# ============================================================
# 06 — HTTP
# ============================================================

def stage_http():

    stage = "06_http"

    if stage_done(stage):
        log(f"[SKIP] {stage} já concluída")
        return

    banner("06 — HTTP ENUMERATION")

    subdomains = read_lines(
        DIRS["01_subdomains"] /
        "all-subdomains.txt"
    )

    hosts = (
        DIRS[stage] /
        "hosts.txt"
    )

    save_unique(
        subdomains,
        hosts
    )

    if subdomains and command_exists("httpx"):

        run_cmd(
            stage,
            "httpx",
            [
                "httpx",
                "-l",
                str(hosts),
                "-silent",
                "-status-code",
                "-title",
                "-tech-detect",
                "-web-server",
                "-content-length",
                "-follow-redirects"
            ],
            DIRS[stage] /
            "httpx.txt",
            7200
        )

    mark_stage_done(stage)


# ============================================================
# 07 — TECNOLOGIAS
# ============================================================

def stage_technologies():

    stage = "07_technologies"

    if stage_done(stage):
        log(f"[SKIP] {stage} já concluída")
        return

    banner("07 — TECHNOLOGY FINGERPRINTING")

    subdomains = read_lines(
        DIRS["01_subdomains"] /
        "all-subdomains.txt"
    )

    if command_exists("whatweb"):

        for host in subdomains:

            if STOP_REQUESTED:
                return

            safe = re.sub(
                r"[^A-Za-z0-9_.-]",
                "_",
                host
            )

            run_cmd(
                stage,
                f"whatweb-{safe}",
                [
                    "whatweb",
                    "-a",
                    "1",
                    f"https://{host}"
                ],
                DIRS[stage] /
                f"{safe}.txt",
                180
            )

    if subdomains and command_exists("wafw00f"):

        hosts = (
            DIRS["06_http"] /
            "hosts.txt"
        )

        run_cmd(
            stage,
            "wafw00f",
            [
                "wafw00f",
                "-i",
                str(hosts)
            ],
            DIRS[stage] /
            "wafw00f.txt",
            3600
        )

    mark_stage_done(stage)


# ============================================================
# 08 — URL DISCOVERY
# ============================================================

def stage_urls():

    stage = "08_urls"

    if stage_done(stage):
        log(f"[SKIP] {stage} já concluída")
        return

    banner("08 — URL DISCOVERY")

    subdomains = read_lines(
        DIRS["01_subdomains"] /
        "all-subdomains.txt"
    )

    hosts = (
        DIRS[stage] /
        "hosts.txt"
    )

    save_unique(
        subdomains,
        hosts
    )

    url_sources = set()

    # katana

    out = run_cmd(
        stage,
        "katana",
        [
            "katana",
            "-list",
            str(hosts),
            "-silent",
            "-d",
            "3",
            "-jc"
        ],
        DIRS[stage] /
        "katana.txt",
        7200
    )

    url_sources.update(
        x for x in clean_lines(out)
        if x.startswith("http")
    )

    # urlfinder

    out = run_cmd(
        stage,
        "urlfinder",
        [
            "urlfinder",
            "-list",
            str(hosts),
            "-silent"
        ],
        DIRS[stage] /
        "urlfinder.txt",
        7200
    )

    url_sources.update(
        x for x in clean_lines(out)
        if x.startswith("http")
    )

    # waybackurls

    out = run_cmd(
        stage,
        "waybackurls",
        [
            "bash",
            "-c",
            f"printf '%s\\n' '{TARGET}' | waybackurls"
        ],
        DIRS[stage] /
        "waybackurls.txt",
        3600
    )

    url_sources.update(
        x for x in clean_lines(out)
        if x.startswith("http")
    )

    # gau

    out = run_cmd(
        stage,
        "gau",
        [
            "gau",
            TARGET
        ],
        DIRS[stage] /
        "gau.txt",
        3600
    )

    url_sources.update(
        x for x in clean_lines(out)
        if x.startswith("http")
    )

    # hakrawler

    out = run_cmd(
        stage,
        "hakrawler",
        [
            "bash",
            "-c",
            f"printf '%s\\n' '{TARGET}' | hakrawler"
        ],
        DIRS[stage] /
        "hakrawler.txt",
        3600
    )

    url_sources.update(
        x for x in clean_lines(out)
        if x.startswith("http")
    )

    # gospider

    out = run_cmd(
        stage,
        "gospider",
        [
            "gospider",
            "-s",
            f"https://{TARGET}",
            "-c",
            str(THREADS),
            "-t",
            str(THREADS),
            "--quiet"
        ],
        DIRS[stage] /
        "gospider.txt",
        7200
    )

    url_sources.update(
        x for x in clean_lines(out)
        if x.startswith("http")
    )

    save_unique(
        url_sources,
        DIRS[stage] /
        "all-urls.txt"
    )

    report_section(
        "08 — URL Discovery"
    )

    report_line(
        f"**URLs:** `{len(url_sources)}`"
    )

    mark_stage_done(stage)


# ============================================================
# 09 — ENDPOINTS
# ============================================================

def stage_endpoints():

    stage = "09_endpoints"

    if stage_done(stage):
        log(f"[SKIP] {stage} já concluída")
        return

    banner("09 — ENDPOINT EXTRACTION")

    urls = read_lines(
        DIRS["08_urls"] /
        "all-urls.txt"
    )

    endpoints = set()
    api_candidates = set()

    for url in urls:

        match = re.match(
            r"^https?://[^/]+(/.*)?$",
            url
        )

        if match and match.group(1):
            path = match.group(1)

            if path not in ("", "/"):
                endpoints.add(path)

        lower = url.lower()

        if any(
            marker in lower
            for marker in [
                "/api/",
                "/api",
                "/graphql",
                "/swagger",
                "/openapi",
                ".json",
                ".xml",
                ".yaml",
                ".yml"
            ]
        ):
            api_candidates.add(url)

    save_unique(
        endpoints,
        DIRS[stage] /
        "endpoints.txt"
    )

    save_unique(
        api_candidates,
        DIRS[stage] /
        "api-candidates.txt"
    )

    report_section(
        "09 — Endpoints"
    )

    report_line(
        f"**Endpoints:** `{len(endpoints)}`"
    )

    report_line(
        f"**Possíveis APIs:** `{len(api_candidates)}`"
    )

    mark_stage_done(stage)


# ============================================================
# 10 — ARQUIVOS
# ============================================================

def stage_files():

    stage = "10_files"

    if stage_done(stage):
        log(f"[SKIP] {stage} já concluída")
        return

    banner(
        "10 — FILE DISCOVERY "
        "(.git / .env / BACKUPS / CONFIG)"
    )

    urls = read_lines(
        DIRS["08_urls"] /
        "all-urls.txt"
    )

    interesting_extensions = {
        ".js",
        ".json",
        ".xml",
        ".yaml",
        ".yml",
        ".txt",
        ".csv",
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
        ".tgz",
        ".bak",
        ".old",
        ".backup",
        ".conf",
        ".config",
        ".env",
        ".map",
        ".sql",
        ".log",
        ".ini",
        ".toml",
    }

    # Arquivos diretamente observados nas URLs
    interesting = set()

    for url in urls:

        clean = url.lower().split("?")[0]

        if any(
            clean.endswith(ext)
            for ext in interesting_extensions
        ):
            interesting.add(url)

    save_unique(
        interesting,
        DIRS[stage] /
        "interesting-files.txt"
    )

    # --------------------------------------------------------
    # WORDLIST ESPECÍFICA PARA ARQUIVOS
    # --------------------------------------------------------

    file_wordlists = wordlist_paths("files")

    if file_wordlists and command_exists("ffuf"):

        # Cada wordlist continua em seu local original.
        # O FFUF recebe diretamente o caminho.
        for index, wordlist in enumerate(
            file_wordlists,
            start=1
        ):

            run_cmd(
                stage,
                f"ffuf-files-{index}",
                [
                    "ffuf",
                    "-u",
                    f"https://{TARGET}/FUZZ",
                    "-w",
                    str(wordlist),
                    "-mc",
                    "200,204,301,302,307,308,401,403",
                    "-t",
                    str(THREADS),
                    "-of",
                    "json",
                    "-o",
                    str(
                        DIRS[stage] /
                        f"ffuf-files-{index}.json"
                    ),
                    "-s"
                ],
                None,
                7200
            )

    # --------------------------------------------------------
    # .git
    # --------------------------------------------------------

    git_targets = [
        ".git",
        ".git/",
        ".git/HEAD",
        ".git/config",
        ".git/index",
        ".git/logs/HEAD",
        ".git/description",
        ".gitignore",
    ]

    git_file = (
        DIRS[stage] /
        "git-candidates.txt"
    )

    write_file(
        git_file,
        "\n".join(
            f"https://{TARGET}/{x}"
            for x in git_targets
        ) +
        "\n"
    )

    # --------------------------------------------------------
    # .env
    # --------------------------------------------------------

    env_targets = [
        ".env",
        ".env/",
        ".env.local",
        ".env.production",
        ".env.development",
        ".env.staging",
        ".env.test",
        ".env.backup",
        ".env.bak",
        ".env.old",
        ".env.save",
        ".env.example",
        ".env.sample",
    ]

    env_file = (
        DIRS[stage] /
        "env-candidates.txt"
    )

    write_file(
        env_file,
        "\n".join(
            f"https://{TARGET}/{x}"
            for x in env_targets
        ) +
        "\n"
    )

    report_section(
        "10 — File / Configuration Discovery"
    )

    report_line(
        f"**Arquivos interessantes observados:** "
        f"`{len(interesting)}`"
    )

    report_line(
        "**Classes especiais verificadas:** "
        "`.git`, `.git/config`, `.git/HEAD`, "
        "`.gitignore`, `.env`, `.env.local`, "
        "`.env.production`, backups e source maps."
    )

    mark_stage_done(stage)


# ============================================================
# 11 — DIRETÓRIOS
# ============================================================

def extract_http_targets():

    result = []

    httpx_file = (
        DIRS["06_http"] /
        "httpx.txt"
    )

    for line in read_lines(httpx_file):

        match = re.match(
            r"(https?://[^\s]+)",
            line
        )

        if match:
            result.append(
                match.group(1)
            )

    if not result:

        subdomains = read_lines(
            DIRS["01_subdomains"] /
            "all-subdomains.txt"
        )

        result = [
            f"https://{x}"
            for x in subdomains
        ]

    return sorted(
        set(result)
    )


def stage_directories():

    stage = "11_directories"

    if stage_done(stage):
        log(f"[SKIP] {stage} já concluída")
        return

    banner(
        "11 — DIRECTORY / FILE ENUMERATION"
    )

    targets = extract_http_targets()

    web_lists = wordlist_paths("web")

    if not web_lists:
        log(
            "[WORDLIST] Nenhuma wordlist web encontrada."
        )

        mark_stage_done(stage)
        return

    # IMPORTANTE:
    # As ferramentas recebem os caminhos originais.
    # Não há cópia para dentro do alvo.

    for target_index, base in enumerate(
        targets,
        start=1
    ):

        if STOP_REQUESTED:
            return

        safe_name = re.sub(
            r"[^A-Za-z0-9_.-]",
            "_",
            base
        )

        # ----------------------------------------------------
        # FFUF
        # ----------------------------------------------------

        if command_exists("ffuf"):

            for wl_index, wordlist in enumerate(
                web_lists,
                start=1
            ):

                run_cmd(
                    stage,
                    f"ffuf-{target_index}-{wl_index}",
                    [
                        "ffuf",
                        "-u",
                        f"{base}/FUZZ",
                        "-w",
                        str(wordlist),
                        "-mc",
                        "200,204,301,302,307,308,401,403",
                        "-t",
                        str(THREADS),
                        "-of",
                        "json",
                        "-o",
                        str(
                            DIRS[stage] /
                            f"ffuf_{safe_name}_{wl_index}.json"
                        ),
                        "-s"
                    ],
                    None,
                    7200
                )

        # ----------------------------------------------------
        # FERoxbuster
        # ----------------------------------------------------

        if command_exists("feroxbuster"):

            for wl_index, wordlist in enumerate(
                web_lists,
                start=1
            ):

                run_cmd(
                    stage,
                    f"ferox-{target_index}-{wl_index}",
                    [
                        "feroxbuster",
                        "-u",
                        base,
                        "-w",
                        str(wordlist),
                        "-t",
                        str(THREADS),
                        "--silent",
                        "-o",
                        str(
                            DIRS[stage] /
                            f"ferox_{safe_name}_{wl_index}.txt"
                        )
                    ],
                    None,
                    7200
                )

        # ----------------------------------------------------
        # GOBUSTER
        # ----------------------------------------------------

        if command_exists("gobuster"):

            for wl_index, wordlist in enumerate(
                web_lists,
                start=1
            ):

                run_cmd(
                    stage,
                    f"gobuster-{target_index}-{wl_index}",
                    [
                        "gobuster",
                        "dir",
                        "-u",
                        base,
                        "-w",
                        str(wordlist),
                        "-t",
                        str(THREADS),
                        "-o",
                        str(
                            DIRS[stage] /
                            f"gobuster_{safe_name}_{wl_index}.txt"
                        ),
                        "--no-error"
                    ],
                    None,
                    7200
                )

        # ----------------------------------------------------
        # DIRSEARCH
        # ----------------------------------------------------

        if command_exists("dirsearch"):

            # dirsearch aceita wordlist individual.
            for wl_index, wordlist in enumerate(
                web_lists,
                start=1
            ):

                run_cmd(
                    stage,
                    f"dirsearch-{target_index}-{wl_index}",
                    [
                        "dirsearch",
                        "-u",
                        base,
                        "-w",
                        str(wordlist),
                        "--format",
                        "plain",
                        "--output",
                        str(
                            DIRS[stage] /
                            f"dirsearch_{safe_name}_{wl_index}.txt"
                        )
                    ],
                    None,
                    7200
                )

    mark_stage_done(stage)


# ============================================================
# 12 — VULNERABILIDADES
# ============================================================

def stage_vulnerabilities():

    stage = "12_vulnerabilities"

    if stage_done(stage):
        log(f"[SKIP] {stage} já concluída")
        return

    banner(
        "12 — VULNERABILITY / EXPOSURE DISCOVERY"
    )

    targets = extract_http_targets()

    targets_file = (
        DIRS[stage] /
        "http-targets.txt"
    )

    save_unique(
        targets,
        targets_file
    )

    # --------------------------------------------------------
    # NUCLEI
    # --------------------------------------------------------

    if targets:

        run_cmd(
            stage,
            "nuclei",
            [
                "nuclei",
                "-l",
                str(targets_file),
                "-silent",
                "-severity",
                "info,low,medium,high,critical",
                "-o",
                str(
                    DIRS[stage] /
                    "nuclei.txt"
                )
            ],
            None,
            14400
        )

    # --------------------------------------------------------
    # DALFOX
    # --------------------------------------------------------

    urls_file = (
        DIRS["08_urls"] /
        "all-urls.txt"
    )

    if command_exists("dalfox") and urls_file.exists():

        run_cmd(
            stage,
            "dalfox",
            [
                "dalfox",
                "file",
                str(urls_file),
                "--silence",
                "--output",
                str(
                    DIRS[stage] /
                    "dalfox.txt"
                )
            ],
            None,
            14400
        )

    # --------------------------------------------------------
    # NIKTO
    # --------------------------------------------------------

    if command_exists("nikto"):

        nikto_dir = (
            DIRS[stage] /
            "nikto"
        )

        nikto_dir.mkdir(
            parents=True,
            exist_ok=True
        )

        for index, base in enumerate(
            targets,
            start=1
        ):

            if STOP_REQUESTED:
                return

            safe = re.sub(
                r"[^A-Za-z0-9_.-]",
                "_",
                base
            )

            run_cmd(
                stage,
                f"nikto-{index}",
                [
                    "nikto",
                    "-h",
                    base
                ],
                nikto_dir /
                f"{safe}.txt",
                3600
            )

    mark_stage_done(stage)


# ============================================================
# 13 — CONSOLIDAÇÃO
# ============================================================

def stage_consolidation():

    stage = "13_consolidation"

    if stage_done(stage):
        log(
            f"[SKIP] {stage} já concluída"
        )
        return

    banner(
        "13 — CONSOLIDATION"
    )

    subdomain_count = len(
        read_lines(
            DIRS["01_subdomains"] /
            "all-subdomains.txt"
        )
    )

    ip_count = len(
        read_lines(
            DIRS["03_ips"] /
            "ipv4.txt"
        )
    )

    url_count = len(
        read_lines(
            DIRS["08_urls"] /
            "all-urls.txt"
        )
    )

    endpoint_count = len(
        read_lines(
            DIRS["09_endpoints"] /
            "endpoints.txt"
        )
    )

    api_count = len(
        read_lines(
            DIRS["09_endpoints"] /
            "api-candidates.txt"
        )
    )

    file_count = len(
        read_lines(
            DIRS["10_files"] /
            "interesting-files.txt"
        )
    )

    report_section(
        "13 — Consolidated Summary"
    )

    report_line(
        f"""
| Categoria | Quantidade |
|---|---:|
| Subdomínios | {subdomain_count} |
| IPv4 | {ip_count} |
| URLs | {url_count} |
| Endpoints | {endpoint_count} |
| Possíveis APIs | {api_count} |
| Arquivos interessantes | {file_count} |
"""
    )

    report_line(
        f"""
### Evidências

- Wordlists: `{DIRS["00_wordlists"]}`
- Subdomínios: `{DIRS["01_subdomains"]}`
- DNS: `{DIRS["02_dns"]}`
- IPs: `{DIRS["03_ips"]}`
- Portas: `{DIRS["04_ports"]}`
- Serviços: `{DIRS["05_services"]}`
- HTTP: `{DIRS["06_http"]}`
- Tecnologias: `{DIRS["07_technologies"]}`
- URLs: `{DIRS["08_urls"]}`
- Endpoints: `{DIRS["09_endpoints"]}`
- Arquivos: `{DIRS["10_files"]}`
- Diretórios: `{DIRS["11_directories"]}`
- Vulnerabilidades: `{DIRS["12_vulnerabilities"]}`
"""
    )

    report_line(
        f"\nRecon finalizado: `{now()}`"
    )

    mark_stage_done(stage)


# ============================================================
# STATUS DAS FERRAMENTAS
# ============================================================

def tool_status():

    tools = [
        "subfinder",
        "amass",
        "chaos-client",
        "dnsgen",
        "dnsx",
        "shuffledns",
        "massdns",
        "puredns",
        "assetfinder",
        "findomain",
        "sublist3r",

        "httpx",
        "naabu",
        "nmap",
        "masscan",
        "tlsx",

        "katana",
        "urlfinder",
        "waybackurls",
        "gau",
        "hakrawler",
        "gospider",

        "ffuf",
        "feroxbuster",
        "gobuster",
        "dirsearch",

        "whatweb",
        "wafw00f",
        "nikto",

        "nuclei",
        "dalfox",
        "uncover",

        "jq",
        "anew",
    ]

    banner(
        "FERRAMENTAS DISPONÍVEIS"
    )

    for tool in tools:

        path = shutil.which(tool)

        if path:
            print(
                f"[OK]       {tool:<18} {path}"
            )
        else:
            print(
                f"[AUSENTE]  {tool:<18}"
            )

    print()


# ============================================================
# MAIN
# ============================================================

def main():

    global STOP_REQUESTED

    init_report()

    banner(
        "DEEP RECON 2026\n"
        f"TARGET: {TARGET}\n"
        f"OUTPUT: {BASE_DIR}"
    )

    tool_status()

    prepare_wordlist_references()

    # ========================================================
    # EXECUÇÃO SEQUENCIAL
    # ========================================================

    stages = [
        ("01_subdomains", stage_subdomains),
        ("02_dns", stage_dns),
        ("03_ips", stage_ips),
        ("04_ports", stage_ports),
        ("05_services", stage_services),
        ("06_http", stage_http),
        ("07_technologies", stage_technologies),
        ("08_urls", stage_urls),
        ("09_endpoints", stage_endpoints),
        ("10_files", stage_files),
        ("11_directories", stage_directories),
        ("12_vulnerabilities", stage_vulnerabilities),
        ("13_consolidation", stage_consolidation),
    ]

    for name, function in stages:

        if STOP_REQUESTED:
            break

        if stage_done(name):
            log(
                f"[SKIP] {name} -> DONE"
            )
            continue

        log(
            f"[START] {name}"
        )

        function()

        if STOP_REQUESTED:
            break

    # ========================================================
    # FINAL
    # ========================================================

    save_checkpoint()

    banner(
        "PIPELINE FINALIZADO / INTERROMPIDO"
    )

    log(
        f"TARGET: {TARGET}"
    )

    log(
        f"OUTPUT: {BASE_DIR}"
    )

    log(
        f"REPORT: {REPORT}"
    )

    log(
        f"CHECKPOINT: {CHECKPOINT}"
    )

    if STOP_REQUESTED:
        log(
            "STATUS: INTERROMPIDO — "
            "próxima execução continuará pelo checkpoint."
        )
    else:
        log(
            "STATUS: CONCLUÍDO"
        )


if __name__ == "__main__":
    main()
