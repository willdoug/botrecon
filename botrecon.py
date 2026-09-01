#!/usr/bin/env python3

import json
import os
import re
import shlex
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

# Timeout padrão por ferramenta
DEFAULT_TIMEOUT = 3600

# Não copiar wordlists.
# Todas permanecem nos locais originais.
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
# ESTADO GLOBAL
# ============================================================

STOP_REQUESTED = False


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def banner(message):
    print()
    print("=" * 82)
    print(message)
    print("=" * 82)
    print(flush=True)


def log(message):
    print(f"[{now()}] {message}", flush=True)


def command_exists(command):
    return shutil.which(command) is not None


def safe_name(value):
    return re.sub(
        r"[^A-Za-z0-9_.-]",
        "_",
        str(value)
    )


# ============================================================
# ARQUIVOS
# ============================================================

def write_file(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        content,
        encoding="utf-8",
        errors="ignore"
    )


def append_file(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open(
        "a",
        encoding="utf-8",
        errors="ignore"
    ) as f:
        f.write(content)


def read_text(path):
    path = Path(path)

    if not path.exists():
        return ""

    try:
        return path.read_text(
            encoding="utf-8",
            errors="ignore"
        )
    except Exception:
        return ""


def clean_lines(text):
    if not text:
        return []

    return sorted(
        set(
            line.strip()
            for line in text.splitlines()
            if line.strip()
        )
    )


def read_lines(path):
    return clean_lines(
        read_text(path)
    )


def save_unique(lines, path):
    if isinstance(lines, str):
        lines = lines.splitlines()

    cleaned = sorted(
        set(
            str(x).strip()
            for x in lines
            if x is not None and str(x).strip()
        )
    )

    write_file(
        path,
        "\n".join(cleaned) +
        ("\n" if cleaned else "")
    )

    return cleaned


def append_unique(lines, path):
    existing = set(read_lines(path))

    if isinstance(lines, str):
        lines = lines.splitlines()

    new_items = []

    for item in lines:
        item = str(item).strip()

        if not item:
            continue

        if item not in existing:
            existing.add(item)
            new_items.append(item)

    if new_items:
        with Path(path).open(
            "a",
            encoding="utf-8"
        ) as f:
            for item in sorted(new_items):
                f.write(item + "\n")

    return sorted(existing)


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
            "tools": {}
        }

    try:
        state = json.loads(
            CHECKPOINT.read_text(
                encoding="utf-8"
            )
        )

        state.setdefault("target", TARGET)
        state.setdefault("stages", {})
        state.setdefault("tools", {})

        return state

    except Exception:
        log("[WARN] checkpoint inválido. Criando novo estado.")

        return {
            "target": TARGET,
            "started": now(),
            "updated": now(),
            "stages": {},
            "tools": {}
        }


STATE = load_checkpoint()


def save_checkpoint():
    STATE["updated"] = now()

    CHECKPOINT.parent.mkdir(
        parents=True,
        exist_ok=True
    )

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


def get_tool_state(stage, tool):
    return STATE.get(
        "tools",
        {}
    ).get(
        tool_key(stage, tool),
        {}
    )


def is_tool_done(stage, tool):
    return (
        get_tool_state(stage, tool)
        .get("status") == "DONE"
    )


def mark_tool_running(stage, tool):
    STATE.setdefault(
        "tools",
        {}
    )[tool_key(stage, tool)] = {
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

    STATE.setdefault(
        "tools",
        {}
    )[tool_key(stage, tool)] = data

    save_checkpoint()


def mark_tool_failed(stage, tool, reason=""):
    STATE.setdefault(
        "tools",
        {}
    )[tool_key(stage, tool)] = {
        "status": "FAILED",
        "finished": now(),
        "reason": reason
    }

    save_checkpoint()


def stage_status(stage):
    return STATE.get(
        "stages",
        {}
    ).get(
        stage,
        {}
    ).get("status")


def stage_done(stage):
    return stage_status(stage) == "DONE"


def mark_stage_running(stage):
    STATE.setdefault(
        "stages",
        {}
    )[stage] = {
        "status": "RUNNING",
        "started": now()
    }

    save_checkpoint()


def mark_stage_done(stage):
    STATE.setdefault(
        "stages",
        {}
    )[stage] = {
        "status": "DONE",
        "finished": now()
    }

    save_checkpoint()


def mark_stage_failed(stage, reason=""):
    STATE.setdefault(
        "stages",
        {}
    )[stage] = {
        "status": "FAILED",
        "finished": now(),
        "reason": reason
    }

    save_checkpoint()


# ============================================================
# SIGNAL
# ============================================================

def signal_handler(signum, frame):
    global STOP_REQUESTED

    STOP_REQUESTED = True

    log("")
    log("======================================================")
    log("INTERRUPÇÃO SOLICITADA")
    log("Checkpoint preservado.")
    log("A próxima execução continuará a partir do estado salvo.")
    log("======================================================")


signal.signal(
    signal.SIGINT,
    signal_handler
)

signal.signal(
    signal.SIGTERM,
    signal_handler
)


# ============================================================
# EXECUÇÃO DE COMANDOS
# ============================================================

def run_cmd(
    stage,
    tool,
    cmd,
    output_file=None,
    timeout=DEFAULT_TIMEOUT,
    stdin_text=None,
    allow_failure=False
):
    """
    Executa uma ferramenta como unidade independente.

    Características:
    - checkpoint individual;
    - saída em tempo real;
    - nome da ferramenta no terminal;
    - timeout;
    - recuperação após interrupção;
    - logging do comando;
    - saída opcional para arquivo.

    Retorno:
        texto produzido pela ferramenta.
    """

    global STOP_REQUESTED

    if is_tool_done(stage, tool):
        log(
            f"[SKIP] [{tool}] checkpoint DONE"
        )

        if output_file and Path(output_file).exists():
            return read_text(output_file)

        return ""

    executable = cmd[0]

    if not command_exists(executable):
        log(
            f"[AUSENTE] [{tool}] {executable}"
        )

        mark_tool_failed(
            stage,
            tool,
            f"command not found: {executable}"
        )

        return ""

    mark_tool_running(
        stage,
        tool
    )

    command_string = " ".join(
        shlex.quote(str(x))
        for x in cmd
    )

    banner(
        f"[FERRAMENTA] {tool}\n"
        f"[ETAPA]      {stage}\n"
        f"[COMANDO]    {command_string}"
    )

    append_file(
        COMMAND_LOG,
        "\n"
        + "=" * 82
        + "\n"
        + f"[{now()}]\n"
        + f"[STAGE] {stage}\n"
        + f"[TOOL] {tool}\n"
        + f"$ {command_string}\n"
    )

    process = None
    output_lines = []

    try:
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if stdin_text is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="ignore",
            bufsize=1
        )

        if stdin_text is not None:
            try:
                process.stdin.write(stdin_text)
                process.stdin.close()
            except Exception:
                pass

        start_time = time.time()

        while True:

            if STOP_REQUESTED:

                try:
                    process.terminate()
                    process.wait(timeout=10)
                except Exception:
                    try:
                        process.kill()
                    except Exception:
                        pass

                append_file(
                    COMMAND_LOG,
                    "[INTERRUPTED]\n"
                )

                log(
                    f"[INTERRUPTED] [{tool}]"
                )

                # NÃO marca DONE.
                # Próxima execução tentará novamente.
                return ""

            if (
                time.time() - start_time
                > timeout
            ):
                try:
                    process.kill()
                except Exception:
                    pass

                reason = (
                    f"timeout after {timeout}s"
                )

                mark_tool_failed(
                    stage,
                    tool,
                    reason
                )

                log(
                    f"[TIMEOUT] [{tool}] {timeout}s"
                )

                return ""

            line = process.stdout.readline()

            if line:

                line = line.rstrip(
                    "\r\n"
                )

                output_lines.append(
                    line
                )

                print(
                    f"[{tool}] {line}",
                    flush=True
                )

                continue

            if process.poll() is not None:
                break

            time.sleep(0.05)

        returncode = process.returncode

        output = "\n".join(
            output_lines
        )

        append_file(
            COMMAND_LOG,
            output
            + "\n"
            + f"[exit={returncode}]\n"
        )

        if output_file is not None:

            write_file(
                output_file,
                output
                + (
                    "\n"
                    if output
                    else ""
                )
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

            reason = (
                f"exit={returncode}"
            )

            mark_tool_failed(
                stage,
                tool,
                reason
            )

            log(
                f"[FAILED] [{tool}] exit={returncode}"
            )

            if not allow_failure:
                return output

        return output

    except Exception as exc:

        reason = str(exc)

        mark_tool_failed(
            stage,
            tool,
            reason
        )

        log(
            f"[ERROR] [{tool}] {reason}"
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

                valid.append(
                    path
                )

                log(
                    f"[WORDLIST] {category:<6} -> {path}"
                )

            else:

                log(
                    f"[WORDLIST AUSENTE] {path}"
                )

        reference_file = (
            DIRS["00_wordlists"]
            / f"{category}-sources.txt"
        )

        write_file(
            reference_file,
            "\n".join(
                str(path)
                for path in valid
            )
            + (
                "\n"
                if valid
                else ""
            )
        )

        log(
            f"[WORDLIST] {category}: "
            f"{len(valid)} referência(s)"
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

## Architecture

Sequential reconnaissance pipeline with individual
tool checkpoints and automatic resume.

## Wordlists

Wordlists are referenced from their original locations.
They are **not copied** into the target directory.

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
# HOST / DOMAIN NORMALIZAÇÃO
# ============================================================

def normalize_hostname(value):

    value = str(value).strip().lower()

    value = re.sub(
        r"^https?://",
        "",
        value
    )

    value = value.split(
        "/",
        1
    )[0]

    value = value.split(
        ":",
        1
    )[0]

    value = value.strip(
        "."
    )

    return value


def valid_target_hostname(host):

    host = normalize_hostname(
        host
    )

    if not host:
        return False

    if host == TARGET.lower():
        return True

    return host.endswith(
        "." + TARGET.lower()
    )


def extract_ipv4(text):

    found = set()

    for ip in re.findall(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        text
    ):

        parts = ip.split(".")

        try:
            if all(
                0 <= int(x) <= 255
                for x in parts
            ):
                found.add(ip)
        except Exception:
            pass

    return found


# ============================================================
# 01 — SUBDOMÍNIOS
# ============================================================

def stage_subdomains():

    stage = "01_subdomains"

    if stage_done(stage):
        log(
            f"[SKIP] {stage} -> DONE"
        )
        return True

    mark_stage_running(
        stage
    )

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
            "-silent"
        ],
        DIRS[stage] / "subfinder.txt",
        3600
    )

    discovered.update(
        normalize_hostname(x)
        for x in out.splitlines()
        if valid_target_hostname(x)
    )

    # --------------------------------------------------------
    # AMASS
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

        host = normalize_hostname(
            line
        )

        if valid_target_hostname(host):
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
            TARGET
        ],
        DIRS[stage] / "chaos.txt",
        3600
    )

    for line in out.splitlines():

        host = normalize_hostname(
            line
        )

        if valid_target_hostname(host):
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
            TARGET
        ],
        DIRS[stage] / "assetfinder.txt",
        3600
    )

    for line in out.splitlines():

        host = normalize_hostname(
            line
        )

        if valid_target_hostname(host):
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
            "-q"
        ],
        DIRS[stage] / "findomain.txt",
        3600
    )

    for line in out.splitlines():

        host = normalize_hostname(
            line
        )

        if valid_target_hostname(host):
            discovered.add(host)

    # --------------------------------------------------------
    # SUBLIST3R
    # --------------------------------------------------------

    sublist_output = (
        DIRS[stage]
        / "sublist3r.txt"
    )

    run_cmd(
        stage,
        "sublist3r",
        [
            "sublist3r",
            "-d",
            TARGET,
            "-o",
            str(sublist_output)
        ],
        None,
        3600
    )

    for line in read_lines(
        sublist_output
    ):

        host = normalize_hostname(
            line
        )

        if valid_target_hostname(host):
            discovered.add(host)

    # --------------------------------------------------------
    # DNSGEN
    # --------------------------------------------------------

    dnsgen_input = (
        DIRS[stage]
        / "dnsgen-input.txt"
    )

    save_unique(
        discovered,
        dnsgen_input
    )

    if discovered and command_exists("dnsgen"):

        out = run_cmd(
            stage,
            "dnsgen",
            [
                "dnsgen",
                str(dnsgen_input)
            ],
            DIRS[stage]
            / "dnsgen-generated.txt",
            3600
        )

        for line in out.splitlines():

            host = normalize_hostname(
                line
            )

            if valid_target_hostname(host):
                discovered.add(host)

    # --------------------------------------------------------
    # ANEW
    # --------------------------------------------------------

    all_file = (
        DIRS[stage]
        / "all-subdomains.txt"
    )

    if command_exists("anew"):

        existing = read_text(
            all_file
        )

        candidates = "\n".join(
            sorted(discovered)
        )

        if candidates:

            run_cmd(
                stage,
                "anew",
                [
                    "anew",
                    str(all_file)
                ],
                None,
                1800,
                stdin_text=candidates + "\n",
                allow_failure=True
            )

        discovered.update(
            read_lines(all_file)
        )

    else:

        save_unique(
            discovered,
            all_file
        )

    # --------------------------------------------------------
    # NORMALIZAÇÃO FINAL
    # --------------------------------------------------------

    normalized = set()

    for host in discovered:

        host = normalize_hostname(
            host
        )

        if valid_target_hostname(host):
            normalized.add(host)

    save_unique(
        normalized,
        all_file
    )

    report_section(
        "01 — Subdomain Enumeration"
    )

    report_line(
        f"**Subdomains discovered:** `{len(normalized)}`"
    )

    report_line("")

    for host in sorted(normalized):
        report_line(
            f"- `{host}`"
        )

    if STOP_REQUESTED:
        return False

    mark_stage_done(
        stage
    )

    return True


# ============================================================
# 02 — DNS
# ============================================================

def stage_dns():

    stage = "02_dns"

    if stage_done(stage):
        log(
            f"[SKIP] {stage} -> DONE"
        )
        return True

    mark_stage_running(
        stage
    )

    banner(
        "02 — DNS RESOLUTION"
    )

    subdomains = read_lines(
        DIRS["01_subdomains"]
        / "all-subdomains.txt"
    )

    if not subdomains:

        log(
            "[DNS] Nenhum domínio disponível."
        )

        mark_stage_failed(
            stage,
            "no subdomains"
        )

        return False

    hosts_file = (
        DIRS[stage]
        / "hosts.txt"
    )

    save_unique(
        subdomains,
        hosts_file
    )

    dnsx_file = (
        DIRS[stage]
        / "dnsx.txt"
    )

    # --------------------------------------------------------
    # DNSX
    # --------------------------------------------------------

    dnsx_output = run_cmd(
        stage,
        "dnsx",
        [
            "dnsx",
            "-l",
            str(hosts_file),
            "-a",
            "-aaaa",
            "-cname",
            "-resp",
            "-silent"
        ],
        dnsx_file,
        7200
    )

    # --------------------------------------------------------
    # SHUFFLEDNS
    # --------------------------------------------------------

    dns_wordlists = wordlist_paths(
        "dns"
    )

    if (
        command_exists("shuffledns")
        and dns_wordlists
    ):

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
            DIRS[stage]
            / "shuffledns.txt",
            7200
        )

    # --------------------------------------------------------
    # PUREDNS
    # --------------------------------------------------------

    if (
        command_exists("puredns")
        and dns_wordlists
    ):

        selected = max(
            dns_wordlists,
            key=lambda p: p.stat().st_size
        )

        resolvers = (
            DIRS[stage]
            / "resolvers.txt"
        )

        # Usa resolvers existentes no sistema.
        resolver_candidates = []

        resolv_conf = Path(
            "/etc/resolv.conf"
        )

        if resolv_conf.exists():

            for line in read_lines(
                resolv_conf
            ):

                if line.startswith(
                    "nameserver "
                ):

                    resolver_candidates.append(
                        line.split()[1]
                    )

        save_unique(
            resolver_candidates,
            resolvers
        )

        if resolver_candidates:

            run_cmd(
                stage,
                "puredns",
                [
                    "puredns",
                    "bruteforce",
                    str(selected),
                    TARGET,
                    "--resolvers",
                    str(resolvers),
                    "-w",
                    str(
                        DIRS[stage]
                        / "puredns.txt"
                    )
                ],
                None,
                7200,
                allow_failure=True
            )

    # --------------------------------------------------------
    # MASSDNS
    # --------------------------------------------------------

    if command_exists("massdns"):

        massdns_resolvers = Path(
            "/etc/resolv.conf"
        )

        run_cmd(
            stage,
            "massdns",
            [
                "massdns",
                "-r",
                str(massdns_resolvers),
                "-t",
                "A",
                "-o",
                "S",
                str(hosts_file)
            ],
            DIRS[stage]
            / "massdns.txt",
            7200,
            allow_failure=True
        )

    # --------------------------------------------------------
    # IP EXTRACTION
    # --------------------------------------------------------

    ips = set()

    for source in [
        dnsx_file,
        DIRS[stage] / "massdns.txt",
        DIRS[stage] / "puredns.txt",
    ]:

        ips.update(
            extract_ipv4(
                read_text(source)
            )
        )

    save_unique(
        ips,
        DIRS["03_ips"]
        / "ipv4.txt"
    )

    # --------------------------------------------------------
    # RESOLVED HOSTS
    # --------------------------------------------------------

    resolved_hosts = set()

    for line in read_lines(
        dnsx_file
    ):

        host = normalize_hostname(
            line.split()[0]
            if line.split()
            else line
        )

        if (
            valid_target_hostname(host)
            and extract_ipv4(line)
        ):
            resolved_hosts.add(host)

    save_unique(
        resolved_hosts,
        DIRS[stage]
        / "resolved-hosts.txt"
    )

    report_section(
        "02 — DNS Resolution"
    )

    report_line(
        f"**Resolved hosts:** `{len(resolved_hosts)}`"
    )

    report_line(
        f"**IPv4 addresses:** `{len(ips)}`"
    )

    if STOP_REQUESTED:
        return False

    mark_stage_done(
        stage
    )

    return True


# ============================================================
# 03 — IP
# ============================================================

def stage_ips():

    stage = "03_ips"

    if stage_done(stage):
        log(
            f"[SKIP] {stage} -> DONE"
        )
        return True

    mark_stage_running(
        stage
    )

    banner(
        "03 — IP CONSOLIDATION"
    )

    ips = read_lines(
        DIRS["03_ips"]
        / "ipv4.txt"
    )

    save_unique(
        ips,
        DIRS["03_ips"]
        / "all-ips.txt"
    )

    report_section(
        "03 — IP Enumeration"
    )

    report_line(
        f"**IPv4:** `{len(ips)}`"
    )

    for ip in ips:
        report_line(
            f"- `{ip}`"
        )

    mark_stage_done(
        stage
    )

    return True


# ============================================================
# 04 — PORTAS
# ============================================================

def stage_ports():

    stage = "04_ports"

    if stage_done(stage):
        log(
            f"[SKIP] {stage} -> DONE"
        )
        return True

    mark_stage_running(
        stage
    )

    banner(
        "04 — PORT ENUMERATION"
    )

    ips = read_lines(
        DIRS["03_ips"]
        / "all-ips.txt"
    )

    if not ips:

        log(
            "[PORTS] Nenhum IP resolvido."
        )

        report_section(
            "04 — Port Enumeration"
        )

        report_line(
            "**No resolved IPs available. Port scanning skipped.**"
        )

        mark_stage_done(
            stage
        )

        return True

    ip_file = (
        DIRS[stage]
        / "targets.txt"
    )

    save_unique(
        ips,
        ip_file
    )

    # --------------------------------------------------------
    # NAABU
    # --------------------------------------------------------

    run_cmd(
        stage,
        "naabu",
        [
            "naabu",
            "-list",
            str(ip_file),
            "-top-ports",
            "1000",
            "-silent"
        ],
        DIRS[stage]
        / "naabu-top1000.txt",
        7200
    )

    # --------------------------------------------------------
    # NMAP
    # --------------------------------------------------------

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
        DIRS[stage]
        / "nmap-services.txt",
        7200
    )

    # --------------------------------------------------------
    # MASSCAN
    # --------------------------------------------------------

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
        DIRS[stage]
        / "masscan.txt",
        7200,
        allow_failure=True
    )

    report_section(
        "04 — Port Enumeration"
    )

    report_line(
        f"**IPs scanned:** `{len(ips)}`"
    )

    mark_stage_done(
        stage
    )

    return True


# ============================================================
# 05 — SERVIÇOS
# ============================================================

def stage_services():

    stage = "05_services"

    if stage_done(stage):
        log(
            f"[SKIP] {stage} -> DONE"
        )
        return True

    mark_stage_running(
        stage
    )

    banner(
        "05 — SERVICES / TLS"
    )

    ips = read_lines(
        DIRS["03_ips"]
        / "all-ips.txt"
    )

    subdomains = read_lines(
        DIRS["01_subdomains"]
        / "all-subdomains.txt"
    )

    if ips and command_exists("nmap"):

        ip_file = (
            DIRS[stage]
            / "ips.txt"
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
            DIRS[stage]
            / "nmap-service-detection.txt",
            7200
        )

    if subdomains and command_exists("tlsx"):

        hosts = (
            DIRS[stage]
            / "hosts.txt"
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
            DIRS[stage]
            / "tls.txt",
            3600,
            allow_failure=True
        )

    report_section(
        "05 — Services / TLS"
    )

    mark_stage_done(
        stage
    )

    return True


# ============================================================
# 06 — HTTP
# ============================================================

def stage_http():

    stage = "06_http"

    if stage_done(stage):
        log(
            f"[SKIP] {stage} -> DONE"
        )
        return True

    mark_stage_running(
        stage
    )

    banner(
        "06 — HTTP LIVE HOST DISCOVERY"
    )

    subdomains = read_lines(
        DIRS["01_subdomains"]
        / "all-subdomains.txt"
    )

    if not subdomains:

        mark_stage_failed(
            stage,
            "no subdomains"
        )

        return False

    hosts = (
        DIRS[stage]
        / "hosts.txt"
    )

    save_unique(
        subdomains,
        hosts
    )

    httpx_file = (
        DIRS[stage]
        / "httpx.txt"
    )

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
        httpx_file,
        7200
    )

    # --------------------------------------------------------
    # Extrai somente URLs HTTP realmente retornadas
    # --------------------------------------------------------

    live_urls = set()

    for line in read_lines(
        httpx_file
    ):

        match = re.search(
            r"https?://[^\s]+",
            line
        )

        if match:
            live_urls.add(
                match.group(0)
            )

    live_file = (
        DIRS[stage]
        / "live-urls.txt"
    )

    save_unique(
        live_urls,
        live_file
    )

    live_hosts = set()

    for url in live_urls:

        match = re.match(
            r"https?://([^/:]+)",
            url
        )

        if match:

            host = normalize_hostname(
                match.group(1)
            )

            if valid_target_hostname(
                host
            ):
                live_hosts.add(
                    host
                )

    save_unique(
        live_hosts,
        DIRS[stage]
        / "live-hosts.txt"
    )

    report_section(
        "06 — HTTP"
    )

    report_line(
        f"**Live HTTP URLs:** `{len(live_urls)}`"
    )

    report_line(
        f"**Live HTTP hosts:** `{len(live_hosts)}`"
    )

    mark_stage_done(
        stage
    )

    return True


# ============================================================
# 07 — TECNOLOGIAS
# ============================================================

def stage_technologies():

    stage = "07_technologies"

    if stage_done(stage):
        log(
            f"[SKIP] {stage} -> DONE"
        )
        return True

    mark_stage_running(
        stage
    )

    banner(
        "07 — TECHNOLOGY FINGERPRINTING"
    )

    live_hosts = read_lines(
        DIRS["06_http"]
        / "live-hosts.txt"
    )

    if command_exists("whatweb"):

        for index, host in enumerate(
            live_hosts,
            start=1
        ):

            if STOP_REQUESTED:
                return False

            name = safe_name(
                host
            )

            run_cmd(
                stage,
                f"whatweb-{index}-{name}",
                [
                    "whatweb",
                    "-a",
                    "1",
                    f"https://{host}"
                ],
                DIRS[stage]
                / f"{name}.txt",
                300,
                allow_failure=True
            )

    if live_hosts and command_exists(
        "wafw00f"
    ):

        hosts = (
            DIRS[stage]
            / "hosts.txt"
        )

        save_unique(
            live_hosts,
            hosts
        )

        run_cmd(
            stage,
            "wafw00f",
            [
                "wafw00f",
                "-i",
                str(hosts)
            ],
            DIRS[stage]
            / "wafw00f.txt",
            3600,
            allow_failure=True
        )

    mark_stage_done(
        stage
    )

    return True


# ============================================================
# 08 — URL DISCOVERY
# ============================================================

def stage_urls():

    stage = "08_urls"

    if stage_done(stage):
        log(
            f"[SKIP] {stage} -> DONE"
        )
        return True

    mark_stage_running(
        stage
    )

    banner(
        "08 — URL DISCOVERY"
    )

    live_hosts = read_lines(
        DIRS["06_http"]
        / "live-hosts.txt"
    )

    if not live_hosts:

        log(
            "[URL] Nenhum host HTTP vivo."
        )

        mark_stage_failed(
            stage,
            "no live HTTP hosts"
        )

        return False

    hosts = (
        DIRS[stage]
        / "hosts.txt"
    )

    save_unique(
        live_hosts,
        hosts
    )

    urls = set()

    # --------------------------------------------------------
    # KATANA
    # --------------------------------------------------------

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
        DIRS[stage]
        / "katana.txt",
        7200
    )

    urls.update(
        x for x in clean_lines(out)
        if x.startswith("http")
    )

    # --------------------------------------------------------
    # URLFINDER
    # --------------------------------------------------------

    out = run_cmd(
        stage,
        "urlfinder",
        [
            "urlfinder",
            "-list",
            str(hosts),
            "-silent"
        ],
        DIRS[stage]
        / "urlfinder.txt",
        7200,
        allow_failure=True
    )

    urls.update(
        x for x in clean_lines(out)
        if x.startswith("http")
    )

    # --------------------------------------------------------
    # WAYBACKURLS
    # --------------------------------------------------------

    out = run_cmd(
        stage,
        "waybackurls",
        [
            "waybackurls"
        ],
        DIRS[stage]
        / "waybackurls.txt",
        3600,
        stdin_text="\n".join(
            live_hosts
        ) + "\n",
        allow_failure=True
    )

    urls.update(
        x for x in clean_lines(out)
        if x.startswith("http")
    )

    # --------------------------------------------------------
    # GAU
    # --------------------------------------------------------

    out = run_cmd(
        stage,
        "gau",
        [
            "gau",
            "--threads",
            str(THREADS),
            TARGET
        ],
        DIRS[stage]
        / "gau.txt",
        3600,
        allow_failure=True
    )

    urls.update(
        x for x in clean_lines(out)
        if x.startswith("http")
    )

    # --------------------------------------------------------
    # HAKRAWLER
    # --------------------------------------------------------

    for index, host in enumerate(
        live_hosts,
        start=1
    ):

        if STOP_REQUESTED:
            return False

        out = run_cmd(
            stage,
            f"hakrawler-{index}",
            [
                "hakrawler",
                "-url",
                f"https://{host}"
            ],
            DIRS[stage]
            / f"hakrawler-{index}.txt",
            3600,
            allow_failure=True
        )

        urls.update(
            x for x in clean_lines(out)
            if x.startswith("http")
        )

    # --------------------------------------------------------
    # GOSPIDER
    # --------------------------------------------------------

    for index, host in enumerate(
        live_hosts,
        start=1
    ):

        if STOP_REQUESTED:
            return False

        out = run_cmd(
            stage,
            f"gospider-{index}",
            [
                "gospider",
                "-s",
                f"https://{host}",
                "-c",
                str(THREADS),
                "-t",
                str(THREADS),
                "--quiet"
            ],
            DIRS[stage]
            / f"gospider-{index}.txt",
            7200,
            allow_failure=True
        )

        urls.update(
            x for x in clean_lines(out)
            if x.startswith("http")
        )

    # --------------------------------------------------------
    # AGREGAÇÃO
    # --------------------------------------------------------

    all_urls = (
        DIRS[stage]
        / "all-urls.txt"
    )

    save_unique(
        urls,
        all_urls
    )

    # --------------------------------------------------------
    # ANEW
    # --------------------------------------------------------

    if command_exists("anew"):

        run_cmd(
            stage,
            "anew-url-consolidation",
            [
                "anew",
                str(all_urls)
            ],
            None,
            1800,
            stdin_text="\n".join(
                sorted(urls)
            ) + "\n",
            allow_failure=True
        )

    report_section(
        "08 — URL Discovery"
    )

    report_line(
        f"**URLs:** `{len(read_lines(all_urls))}`"
    )

    mark_stage_done(
        stage
    )

    return True


# ============================================================
# 09 — ENDPOINTS
# ============================================================

def stage_endpoints():

    stage = "09_endpoints"

    if stage_done(stage):
        log(
            f"[SKIP] {stage} -> DONE"
        )
        return True

    mark_stage_running(
        stage
    )

    banner(
        "09 — ENDPOINT EXTRACTION"
    )

    urls = read_lines(
        DIRS["08_urls"]
        / "all-urls.txt"
    )

    endpoints = set()
    api_candidates = set()
    javascript = set()

    for url in urls:

        match = re.match(
            r"^https?://[^/]+(/.*)?$",
            url
        )

        if match and match.group(1):

            path = match.group(1)

            if path not in (
                "",
                "/"
            ):
                endpoints.add(
                    path
                )

        lower = url.lower()

        if lower.endswith(
            ".js"
        ):
            javascript.add(
                url
            )

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
                ".yml",
            ]
        ):
            api_candidates.add(
                url
            )

    save_unique(
        endpoints,
        DIRS[stage]
        / "endpoints.txt"
    )

    save_unique(
        api_candidates,
        DIRS[stage]
        / "api-candidates.txt"
    )

    save_unique(
        javascript,
        DIRS[stage]
        / "javascript.txt"
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

    report_line(
        f"**JavaScript URLs:** `{len(javascript)}`"
    )

    mark_stage_done(
        stage
    )

    return True


# ============================================================
# 10 — FILES / .GIT / .ENV
# ============================================================

def stage_files():

    stage = "10_files"

    if stage_done(stage):
        log(
            f"[SKIP] {stage} -> DONE"
        )
        return True

    mark_stage_running(
        stage
    )

    banner(
        "10 — FILE / CONFIGURATION EXPOSURE"
    )

    urls = read_lines(
        DIRS["08_urls"]
        / "all-urls.txt"
    )

    live_urls = read_lines(
        DIRS["06_http"]
        / "live-urls.txt"
    )

    interesting = set()

    extensions = {
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
        ".bz2",
        ".7z",
        ".rar",
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

    for url in urls:

        clean = url.lower().split(
            "?",
            1
        )[0]

        if any(
            clean.endswith(ext)
            for ext in extensions
        ):
            interesting.add(
                url
            )

    save_unique(
        interesting,
        DIRS[stage]
        / "interesting-files.txt"
    )

    # --------------------------------------------------------
    # WORDLIST FILE FUZZING
    # --------------------------------------------------------

    file_wordlists = wordlist_paths(
        "files"
    )

    live_hosts = read_lines(
        DIRS["06_http"]
        / "live-hosts.txt"
    )

    if (
        file_wordlists
        and live_hosts
        and command_exists("ffuf")
    ):

        for host_index, host in enumerate(
            live_hosts,
            start=1
        ):

            for wl_index, wordlist in enumerate(
                file_wordlists,
                start=1
            ):

                if STOP_REQUESTED:
                    return False

                output_json = (
                    DIRS[stage]
                    / f"ffuf-files-{host_index}-{wl_index}.json"
                )

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
                        str(output_json),
                        "-s"
                    ],
                    None,
                    7200,
                    allow_failure=True
                )

    # --------------------------------------------------------
    # .GIT
    # --------------------------------------------------------

    git_paths = [
        ".git",
        ".git/",
        ".git/HEAD",
        ".git/config",
        ".git/index",
        ".git/logs/HEAD",
        ".git/description",
        ".git/packed-refs",
        ".gitignore",
    ]

    git_candidates = set()

    for base in live_urls:

        base = base.rstrip("/")

        for item in git_paths:

            git_candidates.add(
                f"{base}/{item}"
            )

    git_file = (
        DIRS[stage]
        / "git-candidates.txt"
    )

    save_unique(
        git_candidates,
        git_file
    )

    # --------------------------------------------------------
    # .ENV
    # --------------------------------------------------------

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

    env_candidates = set()

    for base in live_urls:

        base = base.rstrip("/")

        for item in env_paths:

            env_candidates.add(
                f"{base}/{item}"
            )

    env_file = (
        DIRS[stage]
        / "env-candidates.txt"
    )

    save_unique(
        env_candidates,
        env_file
    )

    # --------------------------------------------------------
    # OUTROS ARQUIVOS SENSÍVEIS
    # --------------------------------------------------------

    sensitive_paths = [
        "robots.txt",
        "sitemap.xml",
        "security.txt",
        ".well-known/security.txt",
        "crossdomain.xml",
        "clientaccesspolicy.xml",
        "phpinfo.php",
        "server-status",
        "server-info",
    ]

    sensitive_candidates = set()

    for base in live_urls:

        base = base.rstrip("/")

        for item in sensitive_paths:

            sensitive_candidates.add(
                f"{base}/{item}"
            )

    save_unique(
        sensitive_candidates,
        DIRS[stage]
        / "special-files.txt"
    )

    report_section(
        "10 — File / Configuration Discovery"
    )

    report_line(
        f"**Interesting files from URLs:** `{len(interesting)}`"
    )

    report_line(
        f"**.git candidates:** `{len(git_candidates)}`"
    )

    report_line(
        f"**.env candidates:** `{len(env_candidates)}`"
    )

    report_line(
        f"**Special files:** `{len(sensitive_candidates)}`"
    )

    report_line(
        "Explicit checks generated for `.git`, `.git/config`, "
        "`.git/HEAD`, `.gitignore`, `.env`, `.env.local`, "
        "`.env.production`, backups and source maps."
    )

    mark_stage_done(
        stage
    )

    return True


# ============================================================
# EXTRAIR TARGETS HTTP
# ============================================================

def extract_http_targets():

    result = []

    live_file = (
        DIRS["06_http"]
        / "live-urls.txt"
    )

    for url in read_lines(
        live_file
    ):

        match = re.match(
            r"(https?://[^/\s]+)",
            url
        )

        if match:

            result.append(
                match.group(1)
            )

    return sorted(
        set(result)
    )


# ============================================================
# 11 — DIRETÓRIOS
# ============================================================

def stage_directories():

    stage = "11_directories"

    if stage_done(stage):
        log(
            f"[SKIP] {stage} -> DONE"
        )
        return True

    mark_stage_running(
        stage
    )

    banner(
        "11 — DIRECTORY / FILE ENUMERATION"
    )

    targets = extract_http_targets()

    if not targets:

        log(
            "[DIRECTORIES] Nenhum HTTP target vivo."
        )

        mark_stage_failed(
            stage,
            "no live HTTP targets"
        )

        return False

    web_lists = wordlist_paths(
        "web"
    )

    if not web_lists:

        log(
            "[WORDLIST] Nenhuma wordlist web."
        )

        mark_stage_failed(
            stage,
            "no web wordlists"
        )

        return False

    for target_index, base in enumerate(
        targets,
        start=1
    ):

        if STOP_REQUESTED:
            return False

        target_name = safe_name(
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
                            DIRS[stage]
                            / f"ffuf_{target_name}_{wl_index}.json"
                        ),
                        "-s"
                    ],
                    None,
                    7200,
                    allow_failure=True
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
                            DIRS[stage]
                            / f"ferox_{target_name}_{wl_index}.txt"
                        )
                    ],
                    None,
                    7200,
                    allow_failure=True
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
                            DIRS[stage]
                            / f"gobuster_{target_name}_{wl_index}.txt"
                        ),
                        "--no-error"
                    ],
                    None,
                    7200,
                    allow_failure=True
                )

        # ----------------------------------------------------
        # DIRSEARCH
        # ----------------------------------------------------

        if command_exists("dirsearch"):

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
                            DIRS[stage]
                            / f"dirsearch_{target_name}_{wl_index}.txt"
                        )
                    ],
                    None,
                    7200,
                    allow_failure=True
                )

    mark_stage_done(
        stage
    )

    return True


# ============================================================
# 12 — VULNERABILIDADES
# ============================================================

def stage_vulnerabilities():

    stage = "12_vulnerabilities"

    if stage_done(stage):
        log(
            f"[SKIP] {stage} -> DONE"
        )
        return True

    mark_stage_running(
        stage
    )

    banner(
        "12 — VULNERABILITY / EXPOSURE DISCOVERY"
    )

    targets = extract_http_targets()

    if not targets:

        log(
            "[VULN] Nenhum HTTP target vivo."
        )

        mark_stage_failed(
            stage,
            "no live HTTP targets"
        )

        return False

    targets_file = (
        DIRS[stage]
        / "http-targets.txt"
    )

    save_unique(
        targets,
        targets_file
    )

    # --------------------------------------------------------
    # NUCLEI
    # --------------------------------------------------------

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
                DIRS[stage]
                / "nuclei.txt"
            )
        ],
        None,
        14400,
        allow_failure=True
    )

    # --------------------------------------------------------
    # DALFOX
    # --------------------------------------------------------

    urls_file = (
        DIRS["08_urls"]
        / "all-urls.txt"
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
                    DIRS[stage]
                    / "dalfox.txt"
                )
            ],
            None,
            14400,
            allow_failure=True
        )

    # --------------------------------------------------------
    # NIKTO
    # --------------------------------------------------------

    if command_exists("nikto"):

        nikto_dir = (
            DIRS[stage]
            / "nikto"
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
                return False

            name = safe_name(
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
                nikto_dir
                / f"{name}.txt",
                3600,
                allow_failure=True
            )

    # --------------------------------------------------------
    # UNCover
    # --------------------------------------------------------

    if command_exists("uncover"):

        run_cmd(
            stage,
            "uncover",
            [
                "uncover",
                "-q",
                TARGET
            ],
            DIRS[stage]
            / "uncover.txt",
            3600,
            allow_failure=True
        )

    mark_stage_done(
        stage
    )

    return True


# ============================================================
# 13 — CONSOLIDAÇÃO
# ============================================================

def stage_consolidation():

    stage = "13_consolidation"

    if stage_done(stage):
        log(
            f"[SKIP] {stage} -> DONE"
        )
        return True

    mark_stage_running(
        stage
    )

    banner(
        "13 — FINAL CONSOLIDATION"
    )

    counts = {
        "Subdomains": len(
            read_lines(
                DIRS["01_subdomains"]
                / "all-subdomains.txt"
            )
        ),

        "Resolved hosts": len(
            read_lines(
                DIRS["02_dns"]
                / "resolved-hosts.txt"
            )
        ),

        "IPv4": len(
            read_lines(
                DIRS["03_ips"]
                / "all-ips.txt"
            )
        ),

        "Live HTTP hosts": len(
            read_lines(
                DIRS["06_http"]
                / "live-hosts.txt"
            )
        ),

        "Live HTTP URLs": len(
            read_lines(
                DIRS["06_http"]
                / "live-urls.txt"
            )
        ),

        "URLs": len(
            read_lines(
                DIRS["08_urls"]
                / "all-urls.txt"
            )
        ),

        "Endpoints": len(
            read_lines(
                DIRS["09_endpoints"]
                / "endpoints.txt"
            )
        ),

        "API candidates": len(
            read_lines(
                DIRS["09_endpoints"]
                / "api-candidates.txt"
            )
        ),

        "JavaScript": len(
            read_lines(
                DIRS["09_endpoints"]
                / "javascript.txt"
            )
        ),

        "Interesting files": len(
            read_lines(
                DIRS["10_files"]
                / "interesting-files.txt"
            )
        ),

        ".git candidates": len(
            read_lines(
                DIRS["10_files"]
                / "git-candidates.txt"
            )
        ),

        ".env candidates": len(
            read_lines(
                DIRS["10_files"]
                / "env-candidates.txt"
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

    for category, count in counts.items():

        report_line(
            f"| {category} | {count} |"
        )

    report_line(
        ""
    )

    report_line(
        "## Evidence Directories"
    )

    for name, path in DIRS.items():

        report_line(
            f"- `{name}` → `{path}`"
        )

    report_line(
        ""
    )

    report_line(
        "## Wordlist Policy"
    )

    report_line(
        "Wordlists are referenced directly from their original "
        "locations and are not copied into the target directory."
    )

    report_line(
        ""
    )

    report_line(
        f"**Completed:** `{now()}`"
    )

    mark_stage_done(
        stage
    )

    return True


# ============================================================
# STATUS DAS FERRAMENTAS
# ============================================================

def tool_status():

    tools = [
        # Subdomains / DNS
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

        # Network
        "httpx",
        "naabu",
        "nmap",
        "masscan",
        "tlsx",

        # URLs
        "katana",
        "urlfinder",
        "waybackurls",
        "gau",
        "hakrawler",
        "gospider",

        # Content
        "ffuf",
        "feroxbuster",
        "gobuster",
        "dirsearch",

        # Fingerprinting
        "whatweb",
        "wafw00f",

        # Vulnerability
        "nuclei",
        "dalfox",
        "nikto",
        "uncover",

        # Utility
        "jq",
        "anew",
    ]

    banner(
        "FERRAMENTAS DISPONÍVEIS"
    )

    available = 0
    missing = 0

    for tool in tools:

        path = shutil.which(
            tool
        )

        if path:

            available += 1

            print(
                f"[OK]       {tool:<20} {path}"
            )

        else:

            missing += 1

            print(
                f"[AUSENTE]  {tool:<20}"
            )

    print()

    log(
        f"[TOOLS] disponíveis={available} "
        f"ausentes={missing}"
    )

    print()


# ============================================================
# STATUS DO PIPELINE
# ============================================================

def pipeline_status():

    banner(
        "CHECKPOINT STATUS"
    )

    for stage in [
        "01_subdomains",
        "02_dns",
        "03_ips",
        "04_ports",
        "05_services",
        "06_http",
        "07_technologies",
        "08_urls",
        "09_endpoints",
        "10_files",
        "11_directories",
        "12_vulnerabilities",
        "13_consolidation",
    ]:

        status = stage_status(
            stage
        )

        if status is None:
            status = "NOT_STARTED"

        print(
            f"{stage:<24} {status}"
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

    log(
        "Modelo: execução sequencial"
    )

    log(
        "Checkpoint: individual por ferramenta"
    )

    log(
        "Wordlists: referência direta, sem cópia"
    )

    log(
        "Port scan: somente IPs resolvidos"
    )

    log(
        "HTTP pipeline: somente hosts vivos"
    )

    tool_status()

    pipeline_status()

    prepare_wordlist_references()

    # ========================================================
    # PIPELINE SEQUENCIAL
    # ========================================================

    stages = [
        (
            "01_subdomains",
            stage_subdomains
        ),
        (
            "02_dns",
            stage_dns
        ),
        (
            "03_ips",
            stage_ips
        ),
        (
            "04_ports",
            stage_ports
        ),
        (
            "05_services",
            stage_services
        ),
        (
            "06_http",
            stage_http
        ),
        (
            "07_technologies",
            stage_technologies
        ),
        (
            "08_urls",
            stage_urls
        ),
        (
            "09_endpoints",
            stage_endpoints
        ),
        (
            "10_files",
            stage_files
        ),
        (
            "11_directories",
            stage_directories
        ),
        (
            "12_vulnerabilities",
            stage_vulnerabilities
        ),
        (
            "13_consolidation",
            stage_consolidation
        ),
    ]

    for stage_name, function in stages:

        if STOP_REQUESTED:
            break

        if stage_done(stage_name):

            log(
                f"[SKIP] {stage_name} -> DONE"
            )

            continue

        banner(
            f"INICIANDO ETAPA {stage_name}"
        )

        success = function()

        if STOP_REQUESTED:
            break

        if not success:

            log(
                f"[STOP] {stage_name} não foi concluída."
            )

            log(
                "O pipeline não avançará para a próxima "
                "etapa até esta etapa ser concluída."
            )

            break

        log(
            f"[COMPLETE] {stage_name}"
        )

    # ========================================================
    # FINAL
    # ========================================================

    save_checkpoint()

    banner(
        "DEEP RECON — FINAL"
    )

    log(
        f"TARGET:     {TARGET}"
    )

    log(
        f"OUTPUT:     {BASE_DIR}"
    )

    log(
        f"REPORT:     {REPORT}"
    )

    log(
        f"CHECKPOINT: {CHECKPOINT}"
    )

    if STOP_REQUESTED:

        log(
            "STATUS: INTERRUPTED"
        )

        log(
            "A próxima execução retomará pelo checkpoint."
        )

    elif stage_done(
        "13_consolidation"
    ):

        log(
            "STATUS: COMPLETED"
        )

    else:

        log(
            "STATUS: PAUSED / INCOMPLETE"
        )

        log(
            "Execute novamente para retomar."
        )


if __name__ == "__main__":
    main()
