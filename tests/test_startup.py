import os
import subprocess
from unittest.mock import MagicMock, patch

import startup


def _config(tmp_path):
    return startup.StartupConfig(state_dir=tmp_path)


def test_run_startup_orders_connection_core_cookie_tunnel_and_diagnostic(tmp_path):
    config = _config(tmp_path)
    events = []

    with (
        patch("startup.ensure_ssh_master", side_effect=lambda candidate: events.append("ssh")),
        patch("startup.start_bitcoin_core", side_effect=lambda candidate: events.append("core")),
        patch("startup.refresh_cookie", side_effect=lambda candidate: events.append("cookie")),
        patch("startup.ensure_rpc_tunnel", side_effect=lambda candidate: events.append("tunnel")),
    ):
        result = startup.run_startup(
            config,
            diagnostic=lambda candidate: events.append("diagnostic") or {"blocks": 959327},
        )

    assert events == ["ssh", "core", "cookie", "tunnel", "diagnostic"]
    assert result == {"blocks": 959327}


def test_ensure_ssh_master_reuses_existing_control_connection(tmp_path):
    config = _config(tmp_path)
    with (
        patch("startup.subprocess.run", return_value=subprocess.CompletedProcess([], 0)) as run,
        patch("startup._run") as checked_run,
    ):
        startup.ensure_ssh_master(config)

    assert run.call_args.args[0][-3:] == ["-O", "check", config.ssh_target]
    checked_run.assert_not_called()
    assert oct(config.state_dir.stat().st_mode & 0o777) == "0o700"


def test_ensure_ssh_master_removes_stale_socket_and_starts_master(tmp_path):
    config = _config(tmp_path)
    config.state_dir.mkdir(exist_ok=True)
    config.control_socket.write_text("stale", encoding="utf-8")
    with (
        patch("startup.subprocess.run", return_value=subprocess.CompletedProcess([], 1)),
        patch("startup._run") as checked_run,
    ):
        startup.ensure_ssh_master(config)

    assert not config.control_socket.exists()
    command = checked_run.call_args.args[0]
    assert command[:4] == ["ssh", "-M", "-S", str(config.control_socket)]
    assert "-fN" in command


def test_start_bitcoin_core_uses_known_remote_paths_and_waits_for_rpc(tmp_path):
    config = _config(tmp_path)
    with patch("startup._run") as run:
        startup.start_bitcoin_core(config)

    command = run.call_args.args[0]
    remote_command = command[-1]
    assert command[:3] == ["ssh", "-S", str(config.control_socket)]
    assert "/mnt/bitcoin/Core/bitcoin-25.0/bin/bitcoind" in remote_command
    assert "-datadir=/mnt/bitcoin/Bitcoin" in remote_command
    assert "-rpcwait" in remote_command
    assert "-rpcclienttimeout=120" in remote_command


def test_refresh_cookie_is_atomic_and_sets_private_permissions(tmp_path):
    config = _config(tmp_path)
    config.state_dir.mkdir(exist_ok=True)

    def fake_run(command, **kwargs):
        temporary_path = command[-1]
        with open(temporary_path, "w", encoding="utf-8") as stream:
            stream.write("__cookie__:secret")
        return subprocess.CompletedProcess(command, 0)

    with patch("startup._run", side_effect=fake_run):
        startup.refresh_cookie(config)

    assert config.local_cookie.read_text(encoding="utf-8") == "__cookie__:secret"
    assert os.stat(config.local_cookie).st_mode & 0o777 == 0o600
    assert not config.local_cookie.with_suffix(".cookie.tmp").exists()


def test_tunnel_is_added_only_when_local_port_is_closed(tmp_path):
    config = _config(tmp_path)
    with (
        patch("startup._port_is_open", side_effect=[False, True]),
        patch("startup._run") as run,
    ):
        startup.ensure_rpc_tunnel(config)

    command = run.call_args.args[0]
    assert command[:3] == ["ssh", "-S", str(config.control_socket)]
    assert command[-3:] == ["-L", config.forwarding_spec, config.ssh_target]


def test_start_product_services_starts_backend_then_frontend(tmp_path):
    config = startup.StartupConfig(
        state_dir=tmp_path,
        backend_dir=tmp_path / "backend",
        frontend_dir=tmp_path / "frontend",
    )
    started = []

    with patch(
        "startup._start_detached_service",
        side_effect=lambda **kwargs: started.append(kwargs) or {"status": "started"},
    ):
        result = startup.start_product_services(config)

    assert result == {
        "backend": {"status": "started"},
        "frontend": {"status": "started"},
    }
    assert [service["name"] for service in started] == ["backend", "frontend"]
    assert started[0]["command"][:2] == [
        str(config.backend_dir / ".venv" / "bin" / "uvicorn"),
        "bml_backend.app:app",
    ]
    assert started[0]["environment"]["BML_CORE_RPC_URL"] == config.rpc_url
    assert started[0]["environment"]["BML_CORE_RPC_COOKIE"] == str(config.local_cookie)
    assert started[1]["command"][:2] == ["npm", "start"]


def test_detached_service_reuses_an_open_port(tmp_path):
    with patch("startup._port_is_open", return_value=True):
        result = startup._start_detached_service(
            name="frontend",
            command=["npm", "start"],
            working_directory=tmp_path,
            host="127.0.0.1",
            port=4200,
            state_dir=tmp_path,
            timeout=1,
        )

    assert result == {"status": "already running", "url": "http://127.0.0.1:4200"}


def test_main_reports_diagnostic_json(tmp_path, capsys):
    info = {"chain": "main", "blocks": 959327, "initialblockdownload": False}
    services = {
        "backend": {"status": "started", "url": "http://127.0.0.1:8000"},
        "frontend": {"status": "started", "url": "http://127.0.0.1:4200"},
    }
    with (
        patch("startup.run_startup", return_value=info),
        patch("startup.start_product_services", return_value=services),
    ):
        assert startup.main(["--state-dir", str(tmp_path)]) == 0

    output = capsys.readouterr().out
    assert '"blocks": 959327' in output
    assert '"initialblockdownload": false' in output
    assert '"http://127.0.0.1:4200"' in output


def test_main_can_prepare_infrastructure_without_starting_apps(tmp_path):
    with (
        patch("startup.run_startup", return_value={"chain": "main"}),
        patch("startup.start_product_services") as start_services,
    ):
        assert (
            startup.main(
                [
                    "--state-dir",
                    str(tmp_path),
                    "--infrastructure-only",
                ]
            )
            == 0
        )

    start_services.assert_not_called()
