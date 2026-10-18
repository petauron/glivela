#!/usr/bin/env python3
"""Destructive only to a new, explicitly marked disposable Linux guest.

Run with prepared Glivela bundle, official core archive and the retained legacy
fixture executable. No Center enrollment, production data or public listener.
"""
import hashlib
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import threading
import time
import zipfile

ROOT = Path("/opt/glivela-cutover-lab")
STATE = Path("/var/lib/glivela-cutover-lab")
BACKUPS = Path("/var/lib/glivela-cutover-lab-backups")
WORKER = "glivela-lab-xray.service"
UNIT = Path("/etc/systemd/system") / WORKER
SOURCE_HASH = "8195d909f1109b8f3d99eefe401a3c451d7bf4af71f24d3815420f77e5dd2a40"


def command(*args, check=True, timeout=40):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"command failed: {args[0:3]}: {result.stderr[-1500:]}")
    return result


def write(path, data, mode=0o600):
    path.write_text(data)
    path.chmod(mode)


def document(path, data):
    write(path, json.dumps(data, sort_keys=True))


def active(unit):
    return command("systemctl", "is-active", "--quiet", unit, check=False).returncode == 0


def check(condition, detail):
    if not condition:
        raise RuntimeError(detail)


def entry_request():
    result = command("ip", "netns", "exec", "glivela-lab-entry", "curl", "--silent",
                     "--show-error", "--fail", "--max-time", "8", "--noproxy", "",
                     "--proxy", "socks5://100.64.0.8:1080", "--resolve",
                     "exit.example.test:4433:8.8.4.4", "--cacert", str(ROOT / "cert.pem"),
                     "https://exit.example.test:4433/exit")
    check(result.stdout.strip() == "8.8.8.8", "TLS path did not retain the selected source")


def configure_worker(extra=""):
    text = ("[Unit]\nDescription=Disposable Glivela lab worker\n[Service]\n"
            "Type=simple\nUser=glivela-lab-xray\n"
            f"LoadCredential=configuration:{STATE}/config.json\n"
            f"ExecStart={ROOT}/glivela-bundle/xray run -format json -config %d/configuration\n"
            f"{extra}Restart=no\n")
    write(UNIT, text, 0o644)
    document(ROOT / "installation.json", {"version": 1, "services": {"xray": {
        "unit": WORKER, "user": "glivela-lab-xray", "sha256": hashlib.sha256(text.encode()).hexdigest()}}})
    command("systemctl", "daemon-reload")


def backup():
    response = command(str(ROOT / "glivela-bundle/glivela"), "backup-legacy-landing",
                       "-node-id", "node-example", "-directory", str(BACKUPS))
    result = json.loads(response.stdout)
    check(result["status"] == "backup-only", "backup claimed migration success")
    return result["checkpoint"]


def switch_args(checkpoint):
    return [str(ROOT / "glivela-bundle/glivela"), "switch-legacy-landing", "-config",
            str(ROOT / "node.json"), "-node-id", "node-example", "-checkpoint", checkpoint]


def phase():
    return json.loads((STATE / "legacy-cutover.json").read_text())["phase"]


def restore_old_fixture():
    command("systemctl", "stop", WORKER, check=False)
    command(str(ROOT / "legacy-fixture"), "prepare", str(ROOT / "legacy-plan.json"))
    # Only the new test instance's owned state is reset between scenarios.
    # Recovery checkpoints and the original legacy installation remain intact.
    for item in STATE.iterdir():
        check(item.is_file() and not item.is_symlink(), "unexpected test state resource")
        item.unlink()
    entry_request()


class ExitHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        data = self.client_address[0].encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass


def main():
    check(os.geteuid() == 0 and Path("/run/glivela-54-disposable-lab").is_file(),
          "explicitly authorized disposable root guest required")
    check(Path("/run/systemd/system").is_dir(), "real systemd required")
    for path in [STATE, BACKUPS, Path("/etc/vastora-landing"), Path("/var/lib/vastora"), UNIT]:
        check(not path.exists() and not path.is_symlink(), "refusing an existing installation")
    check((ROOT / "legacy-fixture").is_file(), "retained legacy fixture required")
    archive = ROOT / "xray.zip"
    check(hashlib.sha256(archive.read_bytes()).hexdigest() == SOURCE_HASH, "official archive differs")
    bundle = ROOT / "glivela-bundle"
    with zipfile.ZipFile(archive) as source:
        (bundle / "xray").write_bytes(source.read("xray"))
    (bundle / "xray").chmod(0o755)
    xray_hash = hashlib.sha256((bundle / "xray").read_bytes()).hexdigest()
    document(bundle / "runtime.json", {"version": "isolated-test", "commit": os.environ["GLIVELA_TEST_COMMIT"],
        "os": "linux", "architecture": "amd64", "xray": {"version": "26.7.28",
        "sha256": xray_hash, "sourceArchiveSHA256": SOURCE_HASH}})
    for path in [STATE, BACKUPS]:
        path.mkdir(mode=0o700)
    command("useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "glivela-lab-xray")
    command("ip", "link", "add", "mesh-lab", "type", "veth", "peer", "name", "entry-lab")
    command("ip", "netns", "add", "glivela-lab-entry")
    command("ip", "link", "set", "entry-lab", "netns", "glivela-lab-entry")
    command("ip", "address", "add", "100.64.0.8/32", "dev", "mesh-lab")
    command("ip", "link", "set", "mesh-lab", "up")
    command("ip", "-n", "glivela-lab-entry", "address", "add", "100.64.0.9/32", "dev", "entry-lab")
    command("ip", "-n", "glivela-lab-entry", "link", "set", "entry-lab", "up")
    command("ip", "-n", "glivela-lab-entry", "link", "set", "lo", "up")
    command("ip", "-n", "glivela-lab-entry", "route", "add", "100.64.0.8/32", "dev", "entry-lab")
    command("ip", "route", "add", "100.64.0.9/32", "dev", "mesh-lab")
    command("ip", "link", "add", "egress-lab", "type", "dummy")
    command("ip", "link", "set", "egress-lab", "up")
    for address in ["8.8.8.8/32", "8.8.4.4/32"]:
        command("ip", "address", "add", address, "dev", "egress-lab")
    command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=exit.example.test", "-addext", "subjectAltName=DNS:exit.example.test",
            "-keyout", str(ROOT / "key.pem"), "-out", str(ROOT / "cert.pem"))
    (ROOT / "key.pem").chmod(0o600)
    target = http.server.HTTPServer(("8.8.4.4", 4433), ExitHandler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(ROOT / "cert.pem", ROOT / "key.pem")
    target.socket = tls.wrap_socket(target.socket, server_side=True)
    threading.Thread(target=target.serve_forever, daemon=True).start()
    document(ROOT / "legacy-plan.json", {"revision": 7, "address": "100.64.0.8", "egressIp": "8.8.8.8",
        "sources": [{"address": "100.64.0.9"}]})
    configure_worker()
    document(ROOT / "node.json", {"mode": "node", "directory": str(STATE),
        "certificate": str(ROOT / "cert.pem"), "key": str(ROOT / "key.pem"), "ca": str(ROOT / "cert.pem"),
        "controller": "https://127.0.0.1:7443", "xray": {"installation": str(ROOT / "installation.json"),
        "service": "xray", "interface": "mesh-lab"}})
    command("systemctl", "mask", "vastora-agent.service")
    command(str(ROOT / "legacy-fixture"), "prepare", str(ROOT / "legacy-plan.json"))
    exercise_cutover(bundle, target)


def exercise_cutover(bundle, target):
    entry_request()
    results = {"legacyTLS": True}
    # A deliberately failing start exercises the actual service-failure path.
    configure_worker("ExecStartPre=/usr/bin/false\n")
    failed = command(*switch_args(backup()), check=False)
    check(failed.returncode != 0 and phase() == "rolled-back", "failed start was not rolled back")
    check(active("vastora-landing.service") and not active(WORKER), "failed switch left wrong worker running")
    entry_request()
    results["startFailureRestoredTLS"] = True
    restore_old_fixture()
    configure_worker()
    response = command(*switch_args(backup()))
    check(json.loads(response.stdout)["status"] == "awaiting-routes", "local cutover falsely claimed acceptance")
    check(phase() == "awaiting-routes" and active(WORKER) and not active("vastora-landing.service"),
          "successful local cutover state differs")
    check(command("systemctl", "is-enabled", "vastora-landing.service", check=False).stdout.strip() == "disabled",
          "old service could reclaim the listener at boot")
    entry_request()
    results["xrayTLSAndSelectedExit"] = True
    # Stop the owned new worker before restoring the old fixture for a second
    # independent scenario. Its rules are scoped to its UID and may coexist.
    restore_old_fixture()
    configure_worker("ExecStartPost=/usr/bin/sleep 20\n")
    child = subprocess.Popen(switch_args(backup()), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise RuntimeError("switch ended before interruption boundary")
            pid = command("systemctl", "show", WORKER, "--property=MainPID", "--value").stdout.strip()
            if pid.isdigit() and int(pid) > 0 and (STATE / "legacy-cutover.json").exists() and phase() == "pending":
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("candidate did not reach the pending activation boundary")
        child.kill()
        child.wait(timeout=5)
        recovered = command(str(bundle / "glivela"), "-config", str(ROOT / "node.json"), check=False, timeout=40)
        check(recovered.returncode != 0 and phase() == "rolled-back", "interrupted migration resumed as accepted")
        check(active("vastora-landing.service") and not active(WORKER), "interruption did not restore exclusive old runtime")
        entry_request()
        results["sigkillRecoveryRestoredTLS"] = True
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
    target.shutdown()
    document(ROOT / "results.json", results)
    print(json.dumps(results, sort_keys=True))


if __name__ == "__main__":
    main()
