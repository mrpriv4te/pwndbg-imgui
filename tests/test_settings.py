import json
import os

import pytest

from pwndbg_imgui.settings import Settings


@pytest.fixture(autouse=True)
def config_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    return tmp_path / "pwndbg-imgui"


def test_defaults_when_no_file():
    assert Settings()["theme"] == Settings.DEFAULTS["theme"]


def test_round_trip(config_home):
    s = Settings()
    s["theme"] = "Other"
    s.save()
    assert Settings()["theme"] == "Other"
    assert not any(p.suffix == ".tmp" for p in config_home.iterdir())


def test_saved_file_is_merged_over_defaults(config_home):
    config_home.mkdir(parents=True)
    (config_home / "settings.json").write_text(json.dumps({"theme": "Old"}))
    s = Settings()
    assert s["theme"] == "Old"
    assert s["io_raw"] == Settings.DEFAULTS["io_raw"]  # a key added after that file was written


def test_corrupt_file_falls_back_to_defaults(config_home):
    config_home.mkdir(parents=True)
    (config_home / "settings.json").write_text("{not json")
    assert Settings()["theme"] == Settings.DEFAULTS["theme"]


def test_defaults_are_not_shared_between_instances():
    Settings()["views"].append("x")
    assert Settings()["views"] == []
    assert Settings.DEFAULTS["views"] == []


def test_histories_are_capped():
    s = Settings()
    s["console_history"] = [str(i) for i in range(600)]
    s["io_history"] = [str(i) for i in range(300)]
    s.save()
    s = Settings()
    assert s["console_history"][0] == "100" and len(s["console_history"]) == 500
    assert len(s["io_history"]) == 200


def test_per_binary_settings_keyed_by_absolute_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    s = Settings()
    s.binary("./chall")["args"] = "AAAA"
    assert s.binary(os.path.join(tmp_path, "chall"))["args"] == "AAAA"
    assert s.binary(None) is s.binary(None)
