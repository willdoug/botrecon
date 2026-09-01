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
# RECONBOT 2026
# Sequential Deep Recon Pipeline
# ============================================================

TARGET = "EXAMPLE.com"

BASE_DIR = Path("recon_results") / TARGET.replace("/", "_")
THREADS = 30

SECLists = Path("/opt/SecLists")

# ============================================================
# WORDLISTS
# Apenas referências.
# NENHUMA wordlist é copiada para o alvo.
# ============================================================

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
# DIRETÓRIOS
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

STOP_REQUESTED = False


# ============================================================
# UTILIDADES
# ============================================================

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
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        content,
        encoding="utf-8",
        errors="ignore",
    )


def append_file(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open(
        "a",
        encoding="utf-8",
        errors="ignore",
    ) as f:
        f.write(content)


def clean_lines(text):
    result = set()

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        result.add(line)

    return sorted(result)


def read_lines(path):
    path = Path(path)

    if not path.exists():
        return []

    try:
        return clean_lines(
            path.read_text(
                encoding="utf-8",
                errors="ignore",
            )
        )
    except Exception:
        return []


def save_unique(lines, path):
    if isinstance(lines, str):
        lines = lines.splitlines()

    cleaned = sorted(
        set(
            str(x).strip()
            for x in lines
            if str(x).strip()
        )
    )

    write_file(
        path,
        "\n".join(cleaned) +
        ("\n" if cleaned else ""),
    )

    return cleaned


def safe_name(value):
    return re.sub(
        r"[^A-Za-z0-9_.-]",
        "_",
        value,
    )


# ============================================================
# CHECKPOINT
# ============================================================

def load_checkpoint():

    if not CHECKPOINT.exists():
        return {
            "target": TARGET,
            "started": now(),
            "updated": now(),
            "stages": {},
            "tools": {},
        }

    try:
        state = json.loads(
            CHECKPOINT.read_text(
                encoding="utf-8",
            )
        )

        state.setdefault("target", TARGET)
        state.setdefault("stages", {})
        state.setdefault("tools", {})

        return state

    except Exception:

        return {
            "target": TARGET,
            "started": now(),
            "updated": now(),
            "stages": {},
            "tools": {},
        }


STATE = load_checkpoint()


def save_checkpoint():

    STATE["updated"] = now()

    tmp = CHECKPOINT.with_suffix(".tmp")

    tmp.write_text(
        json.dumps(
            STATE,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    tmp.replace(CHECKPOINT)


def tool_key(stage, tool):
    return f"{stage}:{tool}"


def is_tool_done(stage, tool):

    return (
        STATE
        .get("tools", {})
        .get(tool_key(stage, tool), {})
        .get("status")
        == "DONE"
    )


def mark_tool_running(stage, tool):

    STATE.setdefault("tools", {})[
        tool_key(stage, tool)
    ] = {
        "status": "RUNNING",
        "started": now(),
    }

    save_checkpoint()


def mark_tool_done(stage, tool, output=None):

    data = {
        "status": "DONE",
        "finished": now(),
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
        "reason": reason,
    }

    save_checkpoint()


def stage_done(stage):

    return (
        STATE
        .get("stages", {})
        .get(stage, {})
        .get("status")
        == "DONE"
    )


def mark_stage_done(stage):

    STATE.setdefault("stages", {})[stage] = {
        "status": "DONE",
        "finished": now(),
    }

    save_checkpoint()


# ============================================================
# SINAIS
# ============================================================

def signal_handler(signum, frame):

    global STOP_REQUESTED

    STOP_REQUESTED = True

    log("INTERRUPÇÃO SOLICITADA.")
    log("A ferramenta atual não será marcada como concluída.")
    log("A próxima execução retomará pelo checkpoint.")


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# ============================================================
# EXECUTOR
# ============================================================

def run_cmd(
    stage,
    tool,
    cmd,
    output_file=None,
    timeout=1800,
):

    global STOP_REQUESTED

    if is_tool_done(stage, tool):

        log(
            f"[SKIP] [{tool}] checkpoint DONE"
        )

        if output_file and Path(output_file).exists():

            return Path(output_file).read_text(
                encoding="utf-8",
                errors="ignore",
            )

        return ""

    executable = cmd[0]

    if not command_exists(executable):

        log(
            f"[AUSENTE] [{tool}] {executable}"
        )

        mark_tool_failed(
            stage,
            tool,
            "tool not installed",
        )

        return ""

    mark_tool_running(stage, tool)

    command_string = " ".join(
        str(x)
        for x in cmd
    )

    banner(
        f"[FERRAMENTA] {tool}\n"
        f"[ETAPA]      {stage}\n"
        f"[COMANDO]    {command_string}"
    )

    append_file(
        COMMAND_LOG,
        f"\n[{now()}]\n"
        f"[STAGE] {stage}\n"
        f"[TOOL] {tool}\n"
        f"$ {command_string}\n",
    )

    try:

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="ignore",
            bufsize=1,
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

                    process.wait()

                append_file(
                    COMMAND_LOG,
                    "\n[INTERRUPTED]\n",
                )

                log(
                    f"[INTERRUPT] [{tool}] "
                    "checkpoint preservado."
                )

                return ""

            if time.time() - start_time > timeout:

                process.kill()

                process.wait()

                mark_tool_failed(
                    stage,
                    tool,
                    f"timeout={timeout}s",
                )

                log(
                    f"[TIMEOUT] [{tool}]"
                )

                return ""

            line = process.stdout.readline()

            if line:

                line = line.rstrip()

                output_lines.append(line)

                print(
                    f"[{tool}] {line}",
                    flush=True,
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
            f"\n[exit={returncode}]\n",
        )

        if output_file:

            write_file(
                output_file,
                output +
                ("\n" if output else ""),
            )

        if returncode == 0:

            mark_tool_done(
                stage,
                tool,
                output_file,
            )

            log(
                f"[DONE] [{tool}]"
            )

        else:

            mark_tool_failed(
                stage,
                tool,
                f"exit={returncode}",
            )

            log(
                f"[FAILED] [{tool}] exit={returncode}"
            )

        return output

    except Exception as exc:

        mark_tool_failed(
            stage,
            tool,
            str(exc),
        )

        log(
            f"[ERRO] [{tool}] {exc}"
        )

        return ""


# ============================================================
# WORDLISTS
# ============================================================

def prepare_wordlist_references():

    banner(
        "[WORDLISTS] REFERÊNCIAS"
    )

    for category, sources in WORDLIST_SOURCES.items():

        valid = []

        for path in sources:

            if path.exists():

                valid.append(path)

                log(
                    f"[WORDLIST OK] {category}: {path}"
                )

            else:

                log(
                    f"[WORDLIST AUSENTE] {path}"
                )

        reference_file = (
            DIRS["00_wordlists"] /
            f"{category}-sources.txt"
        )

        write_file(
            reference_file,
            "\n".join(
                str(path)
                for path in valid
            ) +
            ("\n" if valid else ""),
        )


def wordlist_paths(category):

    return [
        path
        for path in WORDLIST_SOURCES.get(
            category,
            [],
        )
        if path.exists()
    ]


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

## Started

`{now()}`

## Pipeline

Sequential reconnaissance pipeline with individual tool
checkpoints and automatic resume.

## Wordlists

Wordlists are referenced from their original locations.

No wordlist content is copied into the target directory.

"""
    )


def report_section(title):

    append_file(
        REPORT,
        f"\n\n## {title}\n\n",
    )


def report_line(text):

    append_file(
        REPORT,
        text + "\n",
    )


# ============================================================
# HOST NORMALIZATION
# ============================================================

def normalize_host(value):

    value = value.strip().lower()

    value = re.sub(
        r"^https?://",
        "",
        value,
    )

    value = value.split("/")[0]
    value = value.split(":")[0]
    value = value.strip(".")

    return value


def valid_target_host(host):

    host = normalize_host(host)

    if host == TARGET:
        return True

    return host.endswith(
        "." + TARGET
    )


# ============================================================
# 01 SUBDOMÍNIOS
# ============================================================

def stage_subdomains():

    stage = "01_subdomains"

    if stage_done(stage):

        log(
            f"[SKIP] {stage} já concluída"
        )

        return

    banner(
        "01 — SUBDOMAIN ENUMERATION"
    )

    discovered = set()

    # --------------------------------------------------------
    # SUBFINDER
    # --------------------------------------------------------

    out = run_cmd(
        stage,
        "subfinder",
        [
            "subfinder",
            "-d",
            TARGET,
            "-silent",
        ],
        DIRS[stage] / "subfinder.txt",
        3600,
    )

    for line in clean_lines(out):

        host = normalize_host(line)

        if valid_target_host(host):
            discovered.add(host)

    # --------------------------------------------------------
    # AMASS ACTIVE
    # --------------------------------------------------------

    out = run_cmd(
        stage,
        "amass-active",
        [
            "amass",
            "enum",
            "-active",
            "-d",
            TARGET,
        ],
        DIRS[stage] / "amass-active.txt",
        7200,
    )

    for line in clean_lines(out):

        host = normalize_host(line)

        if valid_target_host(host):
            discovered.add(host)

    # --------------------------------------------------------
    # CHAOS
    # --------------------------------------------------------

    out = run_cmd(
        stage,
        "chaos-client",
        [
            "chaos-client",
            "-d",
            TARGET,
        ],
        DIRS[stage] / "chaos.txt",
        3600,
    )

    for line in clean_lines(out):

        host = normalize_host(line)

        if valid_target_host(host):
            discovered.add(host)

    # --------------------------------------------------------
    # ASSETFINDER
    # --------------------------------------------------------

    out = run_cmd(
        stage,
        "assetfinder",
        [
            "assetfinder",
            "--subs-only",
            TARGET,
        ],
        DIRS[stage] / "assetfinder.txt",
        3600,
    )

    for line in clean_lines(out):

        host = normalize_host(line)

        if valid_target_host(host):
            discovered.add(host)

    # --------------------------------------------------------
    # FINDOMAIN
    # --------------------------------------------------------

    out = run_cmd(
        stage,
        "findomain",
        [
            "findomain",
            "-t",
            TARGET,
            "-q",
        ],
        DIRS[stage] / "findomain.txt",
        3600,
    )

    for line in clean_lines(out):

        host = normalize_host(line)

        if valid_target_host(host):
            discovered.add(host)

    # --------------------------------------------------------
    # SUBLIST3R
    # --------------------------------------------------------

    sublist_output = (
        DIRS[stage] /
        "sublist3r.txt"
    )

    run_cmd(
        stage,
        "sublist3r",
        [
            "sublist3r",
            "-d",
            TARGET,
            "-o",
            str(sublist_output),
        ],
        None,
        3600,
    )

    for line in read_lines(sublist_output):

        host = normalize_host(line)

        if valid_target_host(host):
            discovered.add(host)

    # --------------------------------------------------------
    # SEED PARA DNSGEN
    # --------------------------------------------------------

    seed_file = (
        DIRS[stage] /
        "dnsgen-input.txt"
    )

    save_unique(
        discovered,
        seed_file,
    )

    # --------------------------------------------------------
    # DNSGEN
    # --------------------------------------------------------

    if discovered:

        out = run_cmd(
            stage,
            "dnsgen",
            [
                "dnsgen",
                str(seed_file),
            ],
            DIRS[stage] /
            "dnsgen-generated.txt",
            3600,
        )

        for line in clean_lines(out):

            host = normalize_host(line)

            if valid_target_host(host):
                discovered.add(host)

    # --------------------------------------------------------
    # ANEW
    #
    # IMPORTANTE:
    # fornecemos stdin explicitamente.
    # O anew não fica esperando input do terminal.
    # --------------------------------------------------------

    if command_exists("anew"):

        anew_key = tool_key(
            stage,
            "anew",
        )

        if not is_tool_done(stage, "anew"):

            mark_tool_running(
                stage,
                "anew",
            )

            banner(
                "[FERRAMENTA] anew\n"
                "[ETAPA]      01_subdomains\n"
                "[FUNÇÃO]     deduplicação incremental"
            )

            try:

                process = subprocess.run(
                    [
                        "anew",
                        str(
                            DIRS[stage] /
                            "all-subdomains.txt"
                        ),
                    ],
                    input="\n".join(
                        sorted(discovered)
                    ) +
                    (
                        "\n"
                        if discovered
                        else ""
                    ),
                    capture_output=True,
                    text=True,
                    errors="ignore",
                    timeout=3600,
                )

                output = process.stdout

                if process.returncode == 0:

                    # anew pode retornar apenas entradas novas.
                    # O arquivo final continua sendo consolidado
                    # pelo próprio ReconBot.
                    save_unique(
                        discovered,
                        DIRS[stage] /
                        "all-subdomains.txt",
                    )

                    mark_tool_done(
                        stage,
                        "anew",
                        DIRS[stage] /
                        "all-subdomains.txt",
                    )

                    log(
                        "[DONE] [anew]"
                    )

                else:

                    mark_tool_failed(
                        stage,
                        "anew",
                        f"exit={process.returncode}",
                    )

                    log(
                        f"[FAILED] [anew] "
                        f"exit={process.returncode}"
                    )

            except Exception as exc:

                mark_tool_failed(
                    stage,
                    "anew",
                    str(exc),
                )

                log(
                    f"[ERRO] [anew] {exc}"
                )

    # --------------------------------------------------------
    # CONSOLIDAÇÃO
    # --------------------------------------------------------

    normalized = set()

    for host in discovered:

        host = normalize_host(host)

        if valid_target_host(host):
            normalized.add(host)

    subdomain_file = (
        DIRS[stage] /
        "all-subdomains.txt"
    )

    save_unique(
        normalized,
        subdomain_file,
    )

    report_section(
        "01 — Subdomain Enumeration"
    )

    report_line(
        f"**Candidates discovered:** `{len(normalized)}`"
    )

    mark_stage_done(stage)


# ============================================================
# 02 DNS
# ============================================================

def stage_dns():

    stage = "02_dns"

    if stage_done(stage):

        log(
            f"[SKIP] {stage} já concluída"
        )

        return

    banner(
        "02 — DNS RESOLUTION"
    )

    subdomains = read_lines(
        DIRS["01_subdomains"] /
        "all-subdomains.txt"
    )

    if not subdomains:

        log(
            "[DNS] Nenhum domínio disponível."
        )

        mark_stage_done(stage)

        return

    input_file = (
        DIRS[stage] /
        "hosts.txt"
    )

    save_unique(
        subdomains,
        input_file,
    )

    # --------------------------------------------------------
    # DNSX
    # --------------------------------------------------------

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
            "-silent",
        ],
        DIRS[stage] /
        "dnsx.txt",
        7200,
    )

    # --------------------------------------------------------
    # SHUFFLEDNS
    # --------------------------------------------------------

    dns_lists = wordlist_paths("dns")

    if dns_lists and command_exists("shuffledns"):

        selected = max(
            dns_lists,
            key=lambda p: p.stat().st_size,
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
                "-silent",
            ],
            DIRS[stage] /
            "shuffledns.txt",
            7200,
        )

    # --------------------------------------------------------
    # MASSDNS
    # --------------------------------------------------------

    massdns_resolver = Path(
        "/usr/share/wordlists/dns.txt"
    )

    if (
        command_exists("massdns")
        and massdns_resolver.exists()
    ):

        run_cmd(
            stage,
            "massdns",
            [
                "massdns",
                "-r",
                str(massdns_resolver),
                "-t",
                "A",
                "-o",
                "S",
                str(input_file),
            ],
            DIRS[stage] /
            "massdns.txt",
            7200,
        )

    # --------------------------------------------------------
    # PUREDNS
    # --------------------------------------------------------

    if command_exists("puredns"):

        run_cmd(
            stage,
            "puredns",
            [
                "puredns",
                "resolve",
                str(input_file),
                "--resolvers",
                str(massdns_resolver),
            ],
            DIRS[stage] /
            "puredns.txt",
            7200,
        )

    # --------------------------------------------------------
    # EXTRAÇÃO DE IP
    # --------------------------------------------------------

    ips = set()

    source_files = [
        DIRS[stage] / "dnsx.txt",
        DIRS[stage] / "shuffledns.txt",
        DIRS[stage] / "massdns.txt",
        DIRS[stage] / "puredns.txt",
    ]

    for result_file in source_files:

        for line in read_lines(result_file):

            found = re.findall(
                r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                line,
            )

            ips.update(found)

    save_unique(
        ips,
        DIRS["03_ips"] /
        "ipv4.txt",
    )

    report_section(
        "02 — DNS Resolution"
    )

    report_line(
        f"**Resolved IPv4 addresses:** `{len(ips)}`"
    )

    mark_stage_done(stage)


# ============================================================
# 03 IP
# ============================================================

def stage_ips():

    stage = "03_ips"

    if stage_done(stage):

        log(
            f"[SKIP] {stage} já concluída"
        )

        return

    banner(
        "03 — IP CONSOLIDATION"
    )

    ips = read_lines(
        DIRS[stage] /
        "ipv4.txt"
    )

    save_unique(
        ips,
        DIRS[stage] /
        "all-ips.txt",
    )

    report_section(
        "03 — IP Enumeration"
    )

    report_line(
        f"**IPv4:** `{len(ips)}`"
    )

    mark_stage_done(stage)


# ============================================================
# 04 PORTAS
# ============================================================

def stage_ports():

    stage = "04_ports"

    if stage_done(stage):

        log(
            f"[SKIP] {stage} já concluída"
        )

        return

    banner(
        "04 — PORT ENUMERATION"
    )

    # IMPORTANTE:
    # Não usamos mais todos os subdomínios cegamente.
    # Primeiro usamos os hosts vivos identificados pelo httpx.
    # Para a primeira descoberta de portas, usamos apenas
    # os hosts resolvidos pelo DNS.

    dns_hosts = read_lines(
        DIRS["02_dns"] /
        "hosts.txt"
    )

    ips = read_lines(
        DIRS["03_ips"] /
        "ipv4.txt"
    )

    if dns_hosts and command_exists("naabu"):

        targets = (
            DIRS[stage] /
            "dns-resolved-targets.txt"
        )

        save_unique(
            dns_hosts,
            targets,
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
                "-silent",
            ],
            DIRS[stage] /
            "naabu-top1000.txt",
            7200,
        )

    if ips and command_exists("nmap"):

        ip_file = (
            DIRS[stage] /
            "ips.txt"
        )

        save_unique(
            ips,
            ip_file,
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
                str(ip_file),
            ],
            DIRS[stage] /
            "nmap-services.txt",
            7200,
        )

    if ips and command_exists("masscan"):

        ip_file = (
            DIRS[stage] /
            "masscan-ips.txt"
        )

        save_unique(
            ips,
            ip_file,
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
                "1000",
            ],
            DIRS[stage] /
            "masscan.txt",
            7200,
        )

    mark_stage_done(stage)


# ============================================================
# 05 SERVIÇOS
# ============================================================

def stage_services():

    stage = "05_services"

    if stage_done(stage):

        log(
            f"[SKIP] {stage} já concluída"
        )

        return

    banner(
        "05 — SERVICE / BANNER ENUMERATION"
    )

    ips = read_lines(
        DIRS["03_ips"] /
        "ipv4.txt"
    )

    hosts = read_lines(
        DIRS["02_dns"] /
        "hosts.txt"
    )

    if ips and command_exists("nmap"):

        ip_file = (
            DIRS[stage] /
            "ips.txt"
        )

        save_unique(
            ips,
            ip_file,
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
                str(ip_file),
            ],
            DIRS[stage] /
            "nmap-service-detection.txt",
            7200,
        )

    if hosts and command_exists("tlsx"):

        host_file = (
            DIRS[stage] /
            "hosts.txt"
        )

        save_unique(
            hosts,
            host_file,
        )

        run_cmd(
            stage,
            "tlsx",
            [
                "tlsx",
                "-l",
                str(host_file),
                "-silent",
            ],
            DIRS[stage] /
            "tls.txt",
            3600,
        )

    mark_stage_done(stage)


# ============================================================
# 06 HTTP
# ============================================================

def stage_http():

    stage = "06_http"

    if stage_done(stage):

        log(
            f"[SKIP] {stage} já concluída"
        )

        return

    banner(
        "06 — LIVE HTTP HOST DISCOVERY"
    )

    hosts = read_lines(
        DIRS["02_dns"] /
        "hosts.txt"
    )

    if not hosts:

        log(
            "[HTTP] Nenhum host DNS disponível."
        )

        mark_stage_done(stage)

        return

    hosts_file = (
        DIRS[stage] /
        "hosts.txt"
    )

    save_unique(
        hosts,
        hosts_file,
    )

    if command_exists("httpx"):

        run_cmd(
            stage,
            "httpx",
            [
                "httpx",
                "-l",
                str(hosts_file),
                "-silent",
                "-status-code",
                "-title",
                "-tech-detect",
                "-web-server",
                "-content-length",
                "-follow-redirects",
            ],
            DIRS[stage] /
            "httpx.txt",
            7200,
        )

    # --------------------------------------------------------
    # Extrair SOMENTE hosts HTTP realmente observados
    # --------------------------------------------------------

    live_urls = set()
    live_hosts = set()

    httpx_file = (
        DIRS[stage] /
        "httpx.txt"
    )

    for line in read_lines(httpx_file):

        match = re.match(
            r"(https?://[^\s]+)",
            line,
        )

        if not match:
            continue

        url = match.group(1)

        live_urls.add(url)

        host_match = re.match(
            r"https?://([^/:]+)",
            url,
        )

        if host_match:

            live_hosts.add(
                normalize_host(
                    host_match.group(1)
                )
            )

    save_unique(
        live_hosts,
        DIRS[stage] /
        "live-hosts.txt",
    )

    save_unique(
        live_urls,
        DIRS[stage] /
        "live-urls.txt",
    )

    report_section(
        "06 — HTTP"
    )

    report_line(
        f"**Live HTTP hosts:** `{len(live_hosts)}`"
    )

    mark_stage_done(stage)


# ============================================================
# 07 TECNOLOGIAS
# ============================================================

def stage_technologies():

    stage = "07_technologies"

    if stage_done(stage):

        log(
            f"[SKIP] {stage} já concluída"
        )

        return

    banner(
        "07 — TECHNOLOGY FINGERPRINTING"
    )

    hosts = read_lines(
        DIRS["06_http"] /
        "live-hosts.txt"
    )

    if command_exists("whatweb"):

        for host in hosts:

            if STOP_REQUESTED:
                return

            safe = safe_name(host)

            run_cmd(
                stage,
                f"whatweb-{safe}",
                [
                    "whatweb",
                    "-a",
                    "1",
                    f"https://{host}",
                ],
                DIRS[stage] /
                f"{safe}.txt",
                300,
            )

    if hosts and command_exists("wafw00f"):

        host_file = (
            DIRS[stage] /
            "hosts.txt"
        )

        save_unique(
            [
                f"https://{host}"
                for host in hosts
            ],
            host_file,
        )

        run_cmd(
            stage,
            "wafw00f",
            [
                "wafw00f",
                "-i",
                str(host_file),
            ],
            DIRS[stage] /
            "wafw00f.txt",
            3600,
        )

    mark_stage_done(stage)


# ============================================================
# 08 URLS
# ============================================================

def stage_urls():

    stage = "08_urls"

    if stage_done(stage):

        log(
            f"[SKIP] {stage} já concluída"
        )

        return

    banner(
        "08 — URL DISCOVERY"
    )

    live_urls = read_lines(
        DIRS["06_http"] /
        "live-urls.txt"
    )

    live_hosts = read_lines(
        DIRS["06_http"] /
        "live-hosts.txt"
    )

    hosts_file = (
        DIRS[stage] /
        "live-hosts.txt"
    )

    save_unique(
        live_hosts,
        hosts_file,
    )

    urls = set(live_urls)

    # --------------------------------------------------------
    # KATANA
    # --------------------------------------------------------

    if live_hosts:

        out = run_cmd(
            stage,
            "katana",
            [
                "katana",
                "-list",
                str(hosts_file),
                "-silent",
                "-d",
                "3",
                "-jc",
            ],
            DIRS[stage] /
            "katana.txt",
            7200,
        )

        for line in clean_lines(out):

            if line.startswith("http"):
                urls.add(line)

    # --------------------------------------------------------
    # URLFINDER
    # --------------------------------------------------------

    if live_hosts:

        out = run_cmd(
            stage,
            "urlfinder",
            [
                "urlfinder",
                "-list",
                str(hosts_file),
                "-silent",
            ],
            DIRS[stage] /
            "urlfinder.txt",
            7200,
        )

        for line in clean_lines(out):

            if line.startswith("http"):
                urls.add(line)

    # --------------------------------------------------------
    # WAYBACKURLS
    # --------------------------------------------------------

    if live_hosts:

        out = run_cmd(
            stage,
            "waybackurls",
            [
                "bash",
                "-c",
                (
                    "cat " +
                    str(hosts_file) +
                    " | waybackurls"
                ),
            ],
            DIRS[stage] /
            "waybackurls.txt",
            7200,
        )

        for line in clean_lines(out):

            if line.startswith("http"):
                urls.add(line)

    # --------------------------------------------------------
    # GAU
    # --------------------------------------------------------

    out = run_cmd(
        stage,
        "gau",
        [
            "gau",
            TARGET,
        ],
        DIRS[stage] /
        "gau.txt",
        7200,
    )

    for line in clean_lines(out):

        if line.startswith("http"):
            urls.add(line)

    # --------------------------------------------------------
    # HAKRAWLER
    # --------------------------------------------------------

    if live_hosts:

        out = run_cmd(
            stage,
            "hakrawler",
            [
                "bash",
                "-c",
                (
                    "cat " +
                    str(hosts_file) +
                    " | hakrawler"
                ),
            ],
            DIRS[stage] /
            "hakrawler.txt",
            7200,
        )

        for line in clean_lines(out):

            match = re.search(
                r"https?://[^\s]+",
                line,
            )

            if match:
                urls.add(match.group(0))

    # --------------------------------------------------------
    # GOSPIDER
    # --------------------------------------------------------

    if live_hosts:

        out = run_cmd(
            stage,
            "gospider",
            [
                "gospider",
                "-S",
                str(hosts_file),
                "-c",
                str(THREADS),
                "-t",
                str(THREADS),
                "--quiet",
            ],
            DIRS[stage] /
            "gospider.txt",
            7200,
        )

        for line in clean_lines(out):

            match = re.search(
                r"https?://[^\s]+",
                line,
            )

            if match:
                urls.add(match.group(0))

    # --------------------------------------------------------
    # FINAL
    # --------------------------------------------------------

    save_unique(
        urls,
        DIRS[stage] /
        "all-urls.txt",
    )

    report_section(
        "08 — URL Discovery"
    )

    report_line(
        f"**URLs:** `{len(urls)}`"
    )

    mark_stage_done(stage)


# ============================================================
# 09 ENDPOINTS
# ============================================================

def stage_endpoints():

    stage = "09_endpoints"

    if stage_done(stage):

        log(
            f"[SKIP] {stage} já concluída"
        )

        return

    banner(
        "09 — ENDPOINT EXTRACTION"
    )

    urls = read_lines(
        DIRS["08_urls"] /
        "all-urls.txt"
    )

    endpoints = set()
    api_candidates = set()

    for url in urls:

        match = re.match(
            r"^https?://[^/]+(/.*)?$",
            url,
        )

        if match and match.group(1):

            path = match.group(1)

            if path not in ("", "/"):
                endpoints.add(path)

        lower = url.lower()

        if any(
            marker in lower
            for marker in (
                "/api/",
                "/api",
                "/graphql",
                "/swagger",
                "/openapi",
                ".json",
                ".xml",
                ".yaml",
                ".yml",
            )
        ):

            api_candidates.add(url)

    save_unique(
        endpoints,
        DIRS[stage] /
        "endpoints.txt",
    )

    save_unique(
        api_candidates,
        DIRS[stage] /
        "api-candidates.txt",
    )

    report_section(
        "09 — Endpoints"
    )

    report_line(
        f"**Endpoints:** `{len(endpoints)}`"
    )

    report_line(
        f"**API candidates:** `{len(api_candidates)}`"
    )

    mark_stage_done(stage)


# ============================================================
# 10 FILES / .GIT / .ENV
# ============================================================

def stage_files():

    stage = "10_files"

    if stage_done(stage):

        log(
            f"[SKIP] {stage} já concluída"
        )

        return

    banner(
        "10 — FILE / CONFIGURATION DISCOVERY"
    )

    live_hosts = read_lines(
        DIRS["06_http"] /
        "live-hosts.txt"
    )

    urls = read_lines(
        DIRS["08_urls"] /
        "all-urls.txt"
    )

    interesting = set()

    extensions = (
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
    )

    for url in urls:

        clean = url.lower().split("?")[0]

        if any(
            clean.endswith(ext)
            for ext in extensions
        ):

            interesting.add(url)

    save_unique(
        interesting,
        DIRS[stage] /
        "interesting-files.txt",
    )

    # --------------------------------------------------------
    # .GIT / .ENV CANDIDATES
    # --------------------------------------------------------

    git_paths = [
        ".git",
        ".git/",
        ".git/HEAD",
        ".git/config",
        ".git/index",
        ".git/logs/HEAD",
        ".git/description",
        ".gitignore",
    ]

    env_paths = [
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

    git_urls = set()
    env_urls = set()

    for host in live_hosts:

        for path in git_paths:

            git_urls.add(
                f"https://{host}/{path}"
            )

        for path in env_paths:

            env_urls.add(
                f"https://{host}/{path}"
            )

    git_file = (
        DIRS[stage] /
        "git-candidates.txt"
    )

    env_file = (
        DIRS[stage] /
        "env-candidates.txt"
    )

    save_unique(
        git_urls,
        git_file,
    )

    save_unique(
        env_urls,
        env_file,
    )

    # --------------------------------------------------------
    # FFUF FILE DISCOVERY
    # --------------------------------------------------------

    file_lists = wordlist_paths("files")

    if (
        file_lists
        and command_exists("ffuf")
        and live_hosts
    ):

        for host_index, host in enumerate(
            live_hosts,
            start=1,
        ):

            for wl_index, wordlist in enumerate(
                file_lists,
                start=1,
            ):

                run_cmd(
                    stage,
                    f"ffuf-files-{host_index}-{wl_index}",
                    [
                        "ffuf",
                        "-u",
                        f"https://{host}/FUZZ",
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
                            f"ffuf-files-{host_index}-{wl_index}.json"
                        ),
                        "-s",
                    ],
                    None,
                    7200,
                )

    report_section(
        "10 — File / Configuration Discovery"
    )

    report_line(
        f"**Interesting observed URLs:** `{len(interesting)}`"
    )

    report_line(
        f"**Git candidates:** `{len(git_urls)}`"
    )

    report_line(
        f"**Environment candidates:** `{len(env_urls)}`"
    )

    report_line(
        "Explicit candidate coverage includes `.git`, "
        "`.git/config`, `.git/HEAD`, `.gitignore`, `.env`, "
        "environment variants, backups and source maps."
    )

    mark_stage_done(stage)


# ============================================================
# HTTP TARGETS
# ============================================================

def extract_http_targets():

    result = set()

    live_urls = read_lines(
        DIRS["06_http"] /
        "live-urls.txt"
    )

    for url in live_urls:

        match = re.match(
            r"https?://[^/\s]+",
            url,
        )

        if match:
            result.add(
                match.group(0)
            )

    if not result:

        hosts = read_lines(
            DIRS["06_http"] /
            "live-hosts.txt"
        )

        for host in hosts:

            result.add(
                f"https://{host}"
            )

    return sorted(result)


# ============================================================
# 11 DIRECTORIES
# ============================================================

def stage_directories():

    stage = "11_directories"

    if stage_done(stage):

        log(
            f"[SKIP] {stage} já concluída"
        )

        return

    banner(
        "11 — DIRECTORY / FILE ENUMERATION"
    )

    targets = extract_http_targets()

    web_lists = wordlist_paths("web")

    if not targets:

        log(
            "[DIRECTORIES] Nenhum host HTTP vivo."
        )

        mark_stage_done(stage)

        return

    if not web_lists:

        log(
            "[DIRECTORIES] Nenhuma wordlist web."
        )

        mark_stage_done(stage)

        return

    for target_index, base in enumerate(
        targets,
        start=1,
    ):

        if STOP_REQUESTED:
            return

        safe = safe_name(base)

        # ----------------------------------------------------
        # FFUF
        # ----------------------------------------------------

        if command_exists("ffuf"):

            for wl_index, wordlist in enumerate(
                web_lists,
                start=1,
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
                            f"ffuf_{safe}_{wl_index}.json"
                        ),
                        "-s",
                    ],
                    None,
                    7200,
                )

        # ----------------------------------------------------
        # FERoxbuster
        # ----------------------------------------------------

        if command_exists("feroxbuster"):

            for wl_index, wordlist in enumerate(
                web_lists,
                start=1,
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
                            f"ferox_{safe}_{wl_index}.txt"
                        ),
                    ],
                    None,
                    7200,
                )

        # ----------------------------------------------------
        # GOBUSTER
        # ----------------------------------------------------

        if command_exists("gobuster"):

            for wl_index, wordlist in enumerate(
                web_lists,
                start=1,
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
                            f"gobuster_{safe}_{wl_index}.txt"
                        ),
                        "--no-error",
                    ],
                    None,
                    7200,
                )

        # ----------------------------------------------------
        # DIRSEARCH
        # ----------------------------------------------------

        if command_exists("dirsearch"):

            for wl_index, wordlist in enumerate(
                web_lists,
                start=1,
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
                            f"dirsearch_{safe}_{wl_index}.txt"
                        ),
                        "--skip-on-status",
                        "429",
                    ],
                    None,
                    7200,
                )

    mark_stage_done(stage)


# ============================================================
# 12 VULNERABILIDADES
# ============================================================

def stage_vulnerabilities():

    stage = "12_vulnerabilities"

    if stage_done(stage):

        log(
            f"[SKIP] {stage} já concluída"
        )

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
        targets_file,
    )

    # --------------------------------------------------------
    # NUCLEI
    # --------------------------------------------------------

    if targets and command_exists("nuclei"):

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
                ),
            ],
            None,
            14400,
        )

    # --------------------------------------------------------
    # DALFOX
    # --------------------------------------------------------

    urls_file = (
        DIRS["08_urls"] /
        "all-urls.txt"
    )

    if (
        command_exists("dalfox")
        and urls_file.exists()
        and urls_file.stat().st_size > 0
    ):

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
                ),
            ],
            None,
            14400,
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
            exist_ok=True,
        )

        for index, target in enumerate(
            targets,
            start=1,
        ):

            if STOP_REQUESTED:
                return

            safe = safe_name(target)

            run_cmd(
                stage,
                f"nikto-{index}",
                [
                    "nikto",
                    "-h",
                    target,
                ],
                nikto_dir /
                f"{safe}.txt",
                3600,
            )

    mark_stage_done(stage)


# ============================================================
# 13 CONSOLIDAÇÃO
# ============================================================

def stage_consolidation():

    stage = "13_consolidation"

    if stage_done(stage):

        log(
            f"[SKIP] {stage} já concluída"
        )

        return

    banner(
        "13 — CONSOLIDATION / REPORT"
    )

    counts = {
        "subdomains": len(
            read_lines(
                DIRS["01_subdomains"] /
                "all-subdomains.txt"
            )
        ),
        "resolved_hosts": len(
            read_lines(
                DIRS["02_dns"] /
                "hosts.txt"
            )
        ),
        "ipv4": len(
            read_lines(
                DIRS["03_ips"] /
                "ipv4.txt"
            )
        ),
        "live_http_hosts": len(
            read_lines(
                DIRS["06_http"] /
                "live-hosts.txt"
            )
        ),
        "urls": len(
            read_lines(
                DIRS["08_urls"] /
                "all-urls.txt"
            )
        ),
        "endpoints": len(
            read_lines(
                DIRS["09_endpoints"] /
                "endpoints.txt"
            )
        ),
        "api_candidates": len(
            read_lines(
                DIRS["09_endpoints"] /
                "api-candidates.txt"
            )
        ),
        "interesting_files": len(
            read_lines(
                DIRS["10_files"] /
                "interesting-files.txt"
            )
        ),
        "git_candidates": len(
            read_lines(
                DIRS["10_files"] /
                "git-candidates.txt"
            )
        ),
        "env_candidates": len(
            read_lines(
                DIRS["10_files"] /
                "env-candidates.txt"
            )
        ),
    }

    report_section(
        "13 — Consolidated Summary"
    )

    report_line(
        "| Category | Count |"
    )

    report_line(
        "|---|---:|"
    )

    for key, value in counts.items():

        report_line(
            f"| {key.replace('_', ' ').title()} | {value} |"
        )

    report_line(
        "\n### Evidence Directories"
    )

    for key, path in DIRS.items():

        report_line(
            f"- `{key}` → `{path}`"
        )

    report_line(
        f"\n### Finished\n\n`{now()}`"
    )

    mark_stage_done(stage)


# ============================================================
# STATUS
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
        "anew",

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

    if TARGET == "EXAMPLE.com":

        print(
            "ERRO: altere TARGET = "
            "\"EXAMPLE.com\" para o domínio desejado."
        )

        sys.exit(1)

    init_report()

    banner(
        "DEEP RECON 2026\n"
        f"TARGET: {TARGET}\n"
        f"OUTPUT: {BASE_DIR}\n"
        "MODE: SEQUENTIAL / CHECKPOINT / LIVE-HOST CHAIN"
    )

    tool_status()

    prepare_wordlist_references()

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

        try:

            function()

        except Exception as exc:

            log(
                f"[FATAL STAGE ERROR] "
                f"{name}: {exc}"
            )

            STATE.setdefault(
                "stages",
                {}
            )[name] = {
                "status": "FAILED",
                "finished": now(),
                "reason": str(exc),
            }

            save_checkpoint()

            break

        if STOP_REQUESTED:
            break

    save_checkpoint()

    banner(
        "DEEP RECON — FINAL STATUS"
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
            "STATUS: INTERROMPIDO"
        )

        log(
            "Próxima execução continuará "
            "pelo checkpoint."
        )

    else:

        all_done = all(
            stage_done(name)
            for name, _ in stages
        )

        if all_done:

            log(
                "STATUS: CONCLUÍDO"
            )

        else:

            log(
                "STATUS: PARCIAL — "
                "há etapas não concluídas."
            )


if __name__ == "__main__":
    main()
