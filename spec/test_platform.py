import sys
from pathlib import Path
from leetha.platform import PLATFORM, is_root, has_capture_privilege, get_home_dir, has_live_terminal, set_promiscuous, get_routes

class TestPlatformDetection:
    def test_platform_is_valid_string(self):
        assert PLATFORM in ("linux", "macos", "windows")

    def test_platform_matches_sys(self):
        if sys.platform == "linux":
            assert PLATFORM == "linux"
        elif sys.platform == "darwin":
            assert PLATFORM == "macos"
        elif sys.platform == "win32":
            assert PLATFORM == "windows"

class TestIsRoot:
    def test_returns_bool(self):
        assert isinstance(is_root(), bool)

class TestHasCapturePrivilege:
    def test_returns_bool(self):
        assert isinstance(has_capture_privilege(), bool)

class TestGetHomeDir:
    def test_returns_path(self):
        assert isinstance(get_home_dir(), Path)

    def test_path_exists(self):
        assert get_home_dir().exists()

class TestHasLiveTerminal:
    def test_returns_bool(self):
        assert isinstance(has_live_terminal(), bool)

class TestSetPromiscuous:
    def test_returns_bool_for_fake_interface(self):
        result = set_promiscuous("nonexistent0")
        assert isinstance(result, bool)

class TestGetRoutes:
    def test_returns_list(self):
        result = get_routes()
        assert isinstance(result, list)
