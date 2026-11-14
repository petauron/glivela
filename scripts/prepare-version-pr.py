#!/usr/bin/env python3
"""Run the existing pinned Release Please bundle with a maintainer Git login."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

REPOSITORY = "petauron/glivela"
ACTION_SHA = "45996ed1f6d02564a971a2fa1b5860e934307cf7"
BUNDLE_FILES = {'action.js': ('f4a102e2ed79b0c79b78df61566945ecf717759f', 59), 'commit.hbs': ('3b2cd68534637a1879ec2b5e9d8dfea589d85137', 1194), 'commit1.hbs': ('641c2f377774274d6854208ad90d02574565dde0', 670), 'commit2.hbs': ('641c2f377774274d6854208ad90d02574565dde0', 670), 'esprima.js': ('593021f5e3ed174a5037bd2c4b52dd7cffc3b851', 122126), 'footer.hbs': ('dca482f281686f481823e6f4e66aac7ed6ce4dd7', 111), 'footer1.hbs': ('e69de29bb2d1d6434b8b29ae775ad8c2e48c5391', 0), 'header.hbs': ('49f56073d89b9016ca52ad2b278d513a578d4495', 173), 'header1.hbs': ('d7efc8fbc60158889dc51d2bc1d98b66366ad5cf', 171), 'header2.hbs': ('a4d6ec439e7a5fc08f44c3c74393ffe238c26081', 216), 'index.js': ('e05257adc9edcba5e5326418591c0a1ede12feab', 4303242), 'module.js': ('a1329e396188386c55afbd5c62e7185fb425045e', 585), 'template.hbs': ('2c1349a6cfbf50eec858a89897d435bae96f4973', 115), 'template1.hbs': ('3b194f06aa08cb25b938c3339c6e1c82bb333ff2', 302), 'template2.hbs': ('3b194f06aa08cb25b938c3339c6e1c82bb333ff2', 302)}


def main():
    if os.environ.get("GITHUB_ACTIONS"):
        raise RuntimeError("Run on the maintainer workstation, not in Actions")
    root = Path(__file__).resolve().parents[1]
    workflow = (root / ".github/workflows/release-please.yml").read_text()
    if f"googleapis/release-please-action@{ACTION_SHA}" not in workflow:
        raise RuntimeError("Review and align the helper pin with the release workflow")
    node_version = subprocess.check_output(["node", "--version"], text=True).strip()
    if int(node_version.lstrip("v").split(".")[0]) < 24:
        raise RuntimeError("Existing Node.js 24 or newer is required")
    credential = subprocess.run(
        ["git", "credential", "fill"],
        input="protocol=https\nhost=github.com\n\n", text=True,
        capture_output=True, check=True,
    )
    fields = dict(line.split("=", 1) for line in credential.stdout.splitlines() if "=" in line)
    token = fields.get("password")
    if not token:
        raise RuntimeError("No existing GitHub credential; no credential was created")

    def api(path):
        request = urllib.request.Request(
            f"https://api.github.com/{path}",
            headers={"Authorization": f"Bearer {token}",
                     "Accept": "application/vnd.github+json", "User-Agent": "glivela-maintainer-release"},
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)

    user = api("user")
    repo = api(f"repos/{REPOSITORY}")
    if user.get("type") != "User" or not repo.get("permissions", {}).get("push"):
        raise RuntimeError("An existing maintainer user with repository write access is required")
    print(f"Maintainer: {user['login']}; repository: {REPOSITORY}; target: main", flush=True)
    # Do not inherit INPUT_* overrides, CI tokens, or Action debug settings.
    environment = {key: value for key, value in os.environ.items()
                   if key in {"PATH", "HOME", "TMPDIR", "SYSTEMROOT", "LANG", "LC_ALL",
                              "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "SSL_CERT_FILE",
                              "NODE_EXTRA_CA_CERTS"}}
    with tempfile.TemporaryDirectory(prefix="glivela-version-pr-") as temporary:
        directory = Path(temporary)
        program = directory / "index.js"
        for name, (expected_digest, expected_size) in BUNDLE_FILES.items():
            url = f"https://raw.githubusercontent.com/googleapis/release-please-action/{ACTION_SHA}/dist/{name}"
            with urllib.request.urlopen(url, timeout=60) as response:
                content = response.read(expected_size + 1)
            digest = hashlib.sha1(f"blob {len(content)}\0".encode() + content).hexdigest()
            if len(content) != expected_size or digest != expected_digest:
                raise RuntimeError(f"Pinned Release Please bundle integrity mismatch: {name}")
            (directory / name).write_bytes(content)
        output = directory / "output"
        output.touch(mode=0o600)
        environment.update({"INPUT_TOKEN": token, "INPUT_REPO-URL": REPOSITORY,
                            "INPUT_TARGET-BRANCH": "main", "INPUT_SKIP-GITHUB-RELEASE": "true",
                            "INPUT_SKIP-GITHUB-PULL-REQUEST": "false", "GITHUB_OUTPUT": str(output)})
        result = subprocess.run(["node", str(program)], cwd=root, env=environment,
                                text=True, capture_output=True, timeout=1200)
        if result.returncode:
            diagnostic = (result.stdout + result.stderr).replace(token, "[REDACTED]")
            print(diagnostic[-6000:], file=sys.stderr)
            raise RuntimeError("Release Please failed; inspect the existing PR before retrying")
        values = output.read_text()
        match = re.search(r"^prs<<[^\n]+\n([^\n]+)\n", values, re.MULTILINE)
        if match:
            for pr in json.loads(match.group(1)):
                print(f"Version PR: https://github.com/{REPOSITORY}/pull/{pr['number']}")
        else:
            print("No version PR changed; inspect existing PRs and releasable commits.")
        print("No merge, release publication, catalog update or deployment was performed.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError, urllib.error.URLError) as error:
        # Never print credential-helper output or a subprocess environment.
        print(f"Version PR preparation stopped: {error}", file=sys.stderr)
        sys.exit(1)
