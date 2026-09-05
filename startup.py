#!/usr/bin/env python3
"""Prepare the local Bitcoin Math Lab development environment."""
from __future__ import annotations

import argparse
import json
import os
import shlex
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from src.database.bitcoin_core_rpc import BitcoinCoreRPC, BitcoinCoreRPCError


@dataclass(frozen=True, slots=True)
class StartupConfig:
    ssh_host: str = "192.168.0.108"
    ssh_user: str = "greg"
    remote_bin_dir: str = "/mnt/bitcoin/Core/bitcoin-25.0/bin"
    remote_data_dir: str = "/mnt/bitcoin/Bitcoin"
    local_rpc_host: str = "127.0.0.1"
    local_rpc_port: int = 18332
    remote_rpc_host: str = "127.0.0.1"
    remote_rpc_port: int = 8332
    state_dir: Path = Path.home() / ".bitclone"
    rpc_timeout: float = 10.0
    core_start_timeout: int = 120
    service_start_timeout: float = 60.0
    backend_dir: Path = Path(__file__).resolve().parent.parent / "backend"
    frontend_dir: Path = Path(__file__).resolve().parent.parent / "frontend"
    backend_port: int = 8000
    frontend_port: int = 4200

    @property
    def ssh_target(self) -> str:
        return f"{self.ssh_user}@{self.ssh_host}"

    @property
    def control_socket(self) -> Path:
        return self.state_dir / "skyscraper-ssh.sock"

    @property
    def local_cookie(self) -> Path:
        return self.state_dir / "skyscraper.cookie"

    @property
    def remote_cookie(self) -> str:
        return f"{self.remote_data_dir}/.cookie"

    @property
    def forwarding_spec(self) -> str:
        return (
            f"{self.local_rpc_host}:{self.local_rpc_port}:"
            f"{self.remote_rpc_host}:{self.remote_rpc_port}"
        )

    @property
    def rpc_url(self) -> str:
        return f"http://{self.local_rpc_host}:{self.local_rpc_port}"


def _run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=True, **kwargs)


def _port_is_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def ensure_ssh_master(config: StartupConfig) -> None:
    """Create or reuse one authenticated SSH control connection."""
    config.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(config.state_dir, 0o700)
    check = subprocess.run(
        [
            "ssh",
            "-S", str(config.control_socket),
            "-O", "check",
            config.ssh_target,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if check.returncode == 0:
        return
    config.control_socket.unlink(missing_ok=True)
    _run([
        "ssh",
        "-M",
        "-S", str(config.control_socket),
        "-fN",
        "-o", "ControlPersist=yes",
        "-o", "ServerAliveInterval=30",
        "-o", "ServerAliveCountMax=3",
        config.ssh_target,
    ])


def start_bitcoin_core(config: StartupConfig) -> None:
    """Start bitcoind when needed and wait until its RPC server is ready."""
    cli = shlex.quote(f"{config.remote_bin_dir}/bitcoin-cli")
    daemon = shlex.quote(f"{config.remote_bin_dir}/bitcoind")
    data_dir = shlex.quote(config.remote_data_dir)
    command = (
        f"{cli} -datadir={data_dir} getblockchaininfo >/dev/null 2>&1 || "
        f"{daemon} -datadir={data_dir} -daemon; "
        f"{cli} -datadir={data_dir} -rpcwait "
        f"-rpcclienttimeout={config.core_start_timeout} getblockchaininfo >/dev/null"
    )
    _run([
        "ssh",
        "-S", str(config.control_socket),
        config.ssh_target,
        command,
    ])


def refresh_cookie(config: StartupConfig) -> None:
    """Copy Core's current cookie atomically and restrict its permissions."""
    temporary_cookie = config.local_cookie.with_suffix(".cookie.tmp")
    temporary_cookie.unlink(missing_ok=True)
    try:
        _run([
            "scp",
            "-o", f"ControlPath={config.control_socket}",
            f"{config.ssh_target}:{config.remote_cookie}",
            str(temporary_cookie),
        ])
        os.chmod(temporary_cookie, 0o600)
        os.replace(temporary_cookie, config.local_cookie)
    finally:
        temporary_cookie.unlink(missing_ok=True)


def ensure_rpc_tunnel(config: StartupConfig) -> None:
    """Add the local RPC forwarding rule to the SSH master when absent."""
    if not _port_is_open(config.local_rpc_host, config.local_rpc_port):
        _run([
            "ssh",
            "-S", str(config.control_socket),
            "-O", "forward",
            "-L", config.forwarding_spec,
            config.ssh_target,
        ])
    deadline = time.monotonic() + config.rpc_timeout
    while time.monotonic() < deadline:
        if _port_is_open(config.local_rpc_host, config.local_rpc_port):
            return
        time.sleep(0.1)
    raise TimeoutError(
        f"RPC tunnel did not open on {config.local_rpc_host}:{config.local_rpc_port}"
    )


def diagnose(config: StartupConfig) -> dict:
    """Return live Bitcoin Core chain information through the tunnel."""
    return BitcoinCoreRPC(
        url=config.rpc_url,
        cookie_file=config.local_cookie,
        timeout=config.rpc_timeout,
    ).get_blockchain_info()


def run_startup(
        config: StartupConfig,
        diagnostic: Callable[[StartupConfig], dict] = diagnose,
) -> dict:
    ensure_ssh_master(config)
    start_bitcoin_core(config)
    refresh_cookie(config)
    ensure_rpc_tunnel(config)
    return diagnostic(config)


def _start_detached_service(
    *,
    name: str,
    command: list[str],
    working_directory: Path,
    host: str,
    port: int,
    state_dir: Path,
    timeout: float,
    environment: dict[str, str] | None = None,
) -> dict[str, object]:
    """Start a development service in the background and wait for its port."""
    url = f"http://{host}:{port}"
    if _port_is_open(host, port):
        return {"status": "already running", "url": url}
    if not working_directory.is_dir():
        raise FileNotFoundError(f"{name} directory not found: {working_directory}")

    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    log_path = state_dir / f"{name}.log"
    pid_path = state_dir / f"{name}.pid"
    with log_path.open("ab") as log:
        process = subprocess.Popen(
            command,
            cwd=working_directory,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    pid_path.write_text(f"{process.pid}\n", encoding="utf-8")

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _port_is_open(host, port):
            return {
                "status": "started",
                "url": url,
                "pid": process.pid,
                "log": str(log_path),
            }
        return_code = process.poll()
        if return_code is not None:
            raise RuntimeError(
                f"{name} exited with status {return_code}; see {log_path}"
            )
        time.sleep(0.2)
    raise TimeoutError(
        f"{name} did not open {url} within {timeout:g} seconds; see {log_path}"
    )


def start_product_services(config: StartupConfig) -> dict[str, dict[str, object]]:
    """Start the backend and frontend development servers when needed."""
    backend_executable = config.backend_dir / ".venv" / "bin" / "uvicorn"
    backend_environment = os.environ.copy()
    backend_environment.update(
        {
            "BML_CORE_RPC_URL": config.rpc_url,
            "BML_CORE_RPC_COOKIE": str(config.local_cookie),
        }
    )
    backend = _start_detached_service(
        name="backend",
        command=[
            str(backend_executable),
            "bml_backend.app:app",
            "--reload",
            "--host",
            config.local_rpc_host,
            "--port",
            str(config.backend_port),
        ],
        working_directory=config.backend_dir,
        host=config.local_rpc_host,
        port=config.backend_port,
        state_dir=config.state_dir,
        timeout=config.service_start_timeout,
        environment=backend_environment,
    )
    frontend = _start_detached_service(
        name="frontend",
        command=[
            "npm",
            "start",
            "--",
            "--host",
            config.local_rpc_host,
            "--port",
            str(config.frontend_port),
        ],
        working_directory=config.frontend_dir,
        host=config.local_rpc_host,
        port=config.frontend_port,
        state_dir=config.state_dir,
        timeout=config.service_start_timeout,
    )
    return {"backend": backend, "frontend": frontend}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare Bitcoin Core connectivity and start the Bitcoin Math Lab "
            "development applications."
        ),
    )
    parser.add_argument("--ssh-host", default="192.168.0.108")
    parser.add_argument("--ssh-user", default="greg")
    parser.add_argument("--remote-bin-dir", default="/mnt/bitcoin/Core/bitcoin-25.0/bin")
    parser.add_argument("--remote-data-dir", default="/mnt/bitcoin/Bitcoin")
    parser.add_argument("--local-rpc-port", type=int, default=18332)
    parser.add_argument("--state-dir", type=Path, default=Path.home() / ".bitclone")
    parser.add_argument("--rpc-timeout", type=float, default=10.0)
    parser.add_argument("--core-start-timeout", type=int, default=120)
    parser.add_argument("--service-start-timeout", type=float, default=60.0)
    parser.add_argument(
        "--backend-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "backend",
    )
    parser.add_argument(
        "--frontend-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "frontend",
    )
    parser.add_argument("--backend-port", type=int, default=8000)
    parser.add_argument("--frontend-port", type=int, default=4200)
    parser.add_argument(
        "--infrastructure-only",
        action="store_true",
        help="prepare Bitcoin Core and its RPC tunnel without starting the product applications",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    config = StartupConfig(
        ssh_host=args.ssh_host,
        ssh_user=args.ssh_user,
        remote_bin_dir=args.remote_bin_dir,
        remote_data_dir=args.remote_data_dir,
        local_rpc_port=args.local_rpc_port,
        state_dir=args.state_dir.expanduser(),
        rpc_timeout=args.rpc_timeout,
        core_start_timeout=args.core_start_timeout,
        service_start_timeout=args.service_start_timeout,
        backend_dir=args.backend_dir.expanduser().resolve(),
        frontend_dir=args.frontend_dir.expanduser().resolve(),
        backend_port=args.backend_port,
        frontend_port=args.frontend_port,
    )
    try:
        info = run_startup(config)
        services = {} if args.infrastructure_only else start_product_services(config)
    except (
        subprocess.CalledProcessError,
        BitcoinCoreRPCError,
        OSError,
        RuntimeError,
        TimeoutError,
    ) as error:
        print(f"BitClone startup failed: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {"bitcoin_core": info, "services": services},
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
