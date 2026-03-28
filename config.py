"""
config.py — Load and validate config.toml using Python 3.11+ tomllib (stdlib).
Resolves the config path correctly whether running as a script or PyInstaller .exe.
"""

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    import tomllib          # Python 3.11+ stdlib
except ImportError:
    import tomli as tomllib  # backport for Python < 3.11 (pip install tomli)


def config_path() -> Path:
    """Return the path to config.toml next to the executable (or script during dev)."""
    if getattr(sys, "frozen", False):
        # Running as PyInstaller .exe — config.toml lives next to the .exe
        return Path(sys.executable).parent / "config.toml"
    return Path(__file__).parent / "config.toml"


def db_path() -> Path:
    """Return the path to edi_router.db next to the executable (or script during dev)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent / "edi_router.db"
    return Path(__file__).parent / "edi_router.db"


@dataclass
class ConnectionConfig:
    protocol: str               # "sftp" or "ftp"
    host: str
    port: int
    username: str
    password: str
    remote_path: str
    poll_interval_seconds: int
    verify_host_key: bool


@dataclass
class SMTPConfig:
    host: str
    port: int
    username: str
    password: str
    from_address: str
    use_ssl: bool


@dataclass
class RoutingConfig:
    ops_manager: str
    edi_team: str
    wms_team: str
    team_lead: str


@dataclass
class AppConfig:
    connection: ConnectionConfig
    smtp: SMTPConfig
    routing: RoutingConfig


def load_config(path: Optional[Path] = None) -> AppConfig:
    """Load config.toml and return a validated AppConfig."""
    target = path or config_path()

    if not target.exists():
        raise FileNotFoundError(
            f"config.toml not found at {target}\n"
            "Copy config.toml next to the executable and fill in your credentials."
        )

    with open(target, "rb") as f:
        raw = tomllib.load(f)

    conn = raw.get("connection", {})
    smtp = raw.get("smtp", {})
    routing = raw.get("routing", {})

    protocol = conn.get("protocol", "sftp").lower()
    if protocol not in ("sftp", "ftp"):
        raise ValueError(f"[connection] protocol must be 'sftp' or 'ftp', got: {protocol!r}")

    return AppConfig(
        connection=ConnectionConfig(
            protocol=protocol,
            host=conn.get("host", ""),
            port=int(conn.get("port", 22)),
            username=conn.get("username", ""),
            password=conn.get("password", ""),
            remote_path=conn.get("remote_path", "/edi/inbound"),
            poll_interval_seconds=int(conn.get("poll_interval_seconds", 300)),
            verify_host_key=bool(conn.get("verify_host_key", False)),
        ),
        smtp=SMTPConfig(
            host=smtp.get("host", ""),
            port=int(smtp.get("port", 587)),
            username=smtp.get("username", ""),
            password=smtp.get("password", ""),
            from_address=smtp.get("from_address", ""),
            use_ssl=bool(smtp.get("use_ssl", False)),
        ),
        routing=RoutingConfig(
            ops_manager=routing.get("ops_manager", ""),
            edi_team=routing.get("edi_team", ""),
            wms_team=routing.get("wms_team", ""),
            team_lead=routing.get("team_lead", ""),
        ),
    )


if __name__ == "__main__":
    cfg = load_config()
    print(f"Connection:  {cfg.connection.protocol.upper()} → {cfg.connection.host}:{cfg.connection.port}")
    print(f"Remote path: {cfg.connection.remote_path}")
    print(f"Poll every:  {cfg.connection.poll_interval_seconds}s")
    print(f"SMTP:        {cfg.smtp.host}:{cfg.smtp.port} (SSL={cfg.smtp.use_ssl})")
    print(f"From:        {cfg.smtp.from_address}")
    print(f"Routing:")
    print(f"  ops_manager: {cfg.routing.ops_manager or '(not set)'}")
    print(f"  edi_team:    {cfg.routing.edi_team or '(not set)'}")
    print(f"  wms_team:    {cfg.routing.wms_team or '(not set)'}")
    print(f"  team_lead:   {cfg.routing.team_lead or '(not set)'}")
