"""Tool subprocess runners.

LocalRunner executes tools directly on the host (default, MVP behavior).
DockerRunner executes CLI tools inside the pinned toolchain container with
a hardened flag set — this is the network-layer backstop story from the
roadmap: ScopeGuard is the policy, the sandbox is the enforcement.

True egress allowlisting (only scoped IPs + model API reachable from the
container) is configured at the lab/infrastructure level; see README.
"""

from __future__ import annotations

import subprocess

from .config import SafetyConfig
from .tools.base import LocalRunner, ToolError, set_runner


class DockerRunner:
    def __init__(self, image: str, memory: str = "2g", pids_limit: int = 1024):
        self.image = image
        self.memory = memory
        self.pids_limit = pids_limit

    def run(self, cmd: list[str], timeout: int = 600, stdin: str | None = None) -> subprocess.CompletedProcess:
        full = [
            "docker", "run", "--rm",
            "--network", "bridge",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--memory", self.memory,
            "--pids-limit", str(self.pids_limit),
            self.image,
            *cmd,
        ]
        try:
            return subprocess.run(
                full,
                input=stdin,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError as exc:
            raise ToolError(
                "docker not found on PATH but safety.runner is 'docker'; "
                "install Docker or set safety.runner: local"
            ) from exc
        except subprocess.TimeoutExpired:
            raise ToolError(f"containerized command timed out after {timeout}s: {' '.join(cmd)}") from None


def configure_runner(safety: SafetyConfig) -> str:
    """Install the configured runner globally for all Tool.shell() calls."""
    if safety.runner == "docker":
        set_runner(DockerRunner(safety.docker_image))
        return f"docker ({safety.docker_image})"
    set_runner(LocalRunner())
    return "local"
