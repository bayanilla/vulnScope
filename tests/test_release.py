"""The ready-made image's compose file (compose.release.yaml) must run the same container as compose.yaml.

compose.release.yaml is what analysts download from a GitHub release. It differs from compose.yaml only in
where the image comes from: ghcr.io instead of a local build. Everything else (folders, port binding,
read-only root, dropped capabilities, environment) must stay identical, so a change to one file that is
forgotten in the other fails here.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGE_KEYS = re.compile(r"^    (image|build|pull_policy):")


def service_lines(name: str) -> list[str]:
    text = (ROOT / name).read_text(encoding="utf-8")
    body = text[text.index("\nname: vulnscope") :].splitlines()
    out, skipping = [], False
    for line in body:
        if line.startswith("name: ") or line.startswith("# Its own project name"):
            continue  # the release file runs as its own project (tested below)
        if IMAGE_KEYS.match(line):
            skipping = True  # also skip the key's own indented lines (build: / context: .)
            continue
        if skipping and line.startswith("      "):
            continue
        skipping = False
        out.append(line)
    return out


class ReleaseComposeTests(unittest.TestCase):
    def test_same_service_apart_from_image(self) -> None:
        self.assertEqual(service_lines("compose.yaml"), service_lines("compose.release.yaml"))

    def test_release_compose_pulls_and_never_builds(self) -> None:
        text = (ROOT / "compose.release.yaml").read_text(encoding="utf-8")
        self.assertIn("image: ${VULNSCOPE_IMAGE:-ghcr.io/bayanilla/vulnscope-max:latest}", text)
        self.assertNotIn("build:", text)
        self.assertNotIn("pull_policy: never", text)

    def test_release_compose_is_its_own_project(self) -> None:
        # Same project name = same container: `up` in one folder would replace the other folder's container.
        def name(f: str) -> str:
            return re.search(r"^name: (\S+)", (ROOT / f).read_text(encoding="utf-8"), re.M).group(1)
        self.assertEqual(name("compose.yaml"), "vulnscope")
        self.assertEqual(name("compose.release.yaml"), "vulnscope-release")

    def test_default_port_avoids_8080_on_the_host(self) -> None:
        # 8080 is Burp Suite's and OWASP ZAP's default. The container side stays 8080 (Dockerfile EXPOSE, healthcheck).
        for f in ("compose.yaml", "compose.release.yaml"):
            text = (ROOT / f).read_text(encoding="utf-8")
            self.assertIn('"127.0.0.1:${VULNSCOPE_PORT:-8765}:8080"', text, f)
            self.assertIn('VULNSCOPE_PUBLIC_PORT: "${VULNSCOPE_PORT:-8765}"', text, f)
        self.assertRegex((ROOT / ".env.example").read_text(encoding="utf-8"), r"(?m)^VULNSCOPE_PORT=8765$")

    def test_env_example_does_not_pick_an_image(self) -> None:
        # A VULNSCOPE_IMAGE line in .env.example would override the ghcr.io default for everyone who copies it.
        text = (ROOT / ".env.example").read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"^VULNSCOPE_IMAGE=", text, re.M))

    def test_release_files_exist(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        for path in ("compose.release.yaml", ".env.example", "scripts/docker/LOAD-release.txt"):
            self.assertIn(path, workflow)
            self.assertTrue((ROOT / path).is_file(), path)
        self.assertIn("uses: ./.github/workflows/ci.yml", workflow)


if __name__ == "__main__":
    unittest.main()
