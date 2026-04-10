import pytest
from leetha.capture.remote.ssh import (
    parse_ssh_url,
    build_capture_commands,
    SSHCaptureConfig,
)


def test_parse_ssh_url_basic():
    cfg = parse_ssh_url("ssh://user@host")
    assert cfg.user == "user"
    assert cfg.host == "host"
    assert cfg.port == 22


def test_parse_ssh_url_with_port():
    cfg = parse_ssh_url("ssh://admin@192.168.1.1:2222")
    assert cfg.user == "admin"
    assert cfg.host == "192.168.1.1"
    assert cfg.port == 2222


def test_parse_ssh_url_invalid_scheme():
    with pytest.raises(ValueError, match="must start with ssh://"):
        parse_ssh_url("http://user@host")


def test_parse_ssh_url_missing_user():
    with pytest.raises(ValueError, match="user"):
        parse_ssh_url("ssh://host")


def test_build_capture_commands():
    cmds = build_capture_commands("eth0")
    assert len(cmds) == 3
    assert "tcpdump" in cmds[0]
    assert "dumpcap" in cmds[1]
    assert "tshark" in cmds[2]
    assert "-i eth0" in cmds[0] or "eth0" in cmds[0]


def test_build_capture_commands_interface_any():
    cmds = build_capture_commands("any")
    assert all("any" in cmd for cmd in cmds)
