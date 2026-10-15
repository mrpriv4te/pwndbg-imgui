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


# -- two instances (two GUI windows) saving the same file ----------------------------

def test_two_windows_keep_each_others_changes():
    a, b = Settings(), Settings()
    a["theme"] = "A theme"
    a.save()
    b["ui_size"] = 20.0
    b.save()  # must not revert a's theme with the value b loaded at startup
    s = Settings()
    assert (s["theme"], s["ui_size"]) == ("A theme", 20.0)


def test_same_key_last_writer_wins():
    a, b = Settings(), Settings()
    a["theme"] = "A"
    a.save()
    b["theme"] = "B"
    b.save()
    assert Settings()["theme"] == "B"


def test_nested_dicts_merge_per_key():
    a, b = Settings(), Settings()
    a["pwndbg_config"]["context-stack-lines"] = 20
    a.binary("/x/chall")["args"] = "AAAA"
    a.save()
    b["pwndbg_config"]["show-flags"] = True
    b.binary("/x/chall")["bps"] = [{"kind": "break", "where": "main"}]
    b.save()
    s = Settings()
    assert s["pwndbg_config"]["context-stack-lines"] == 20 and s["pwndbg_config"]["show-flags"] is True
    assert s.binary("/x/chall") == {"args": "AAAA", "bps": [{"kind": "break", "where": "main"}]}


def test_deleting_a_key_is_saved():
    s = Settings()
    s["pwndbg_config"].update({"a": 1, "b": 2})  # on top of the shipped defaults
    s.save()
    s = Settings()
    s["pwndbg_config"].clear()  # "clear saved config" in the Config pane
    s.save()
    assert Settings()["pwndbg_config"] == {}


def test_histories_from_both_windows_are_kept():
    a, b = Settings(), Settings()
    a["console_history"] = a["console_history"] + ["a1", "a2"]
    a.save()
    b["console_history"] = b["console_history"] + ["b1"]
    b.save()
    a["console_history"] = a["console_history"] + ["a3"]  # appended after a's first save
    a.save()
    assert Settings()["console_history"] == ["a1", "a2", "b1", "a3"]


def test_save_without_changes_does_not_write(config_home):
    s = Settings()
    s.save()
    assert not (config_home / "settings.json").exists()
    s["theme"] = "X"
    s.save()
    mtime = os.stat(config_home / "settings.json").st_mtime_ns
    s.save()
    assert os.stat(config_home / "settings.json").st_mtime_ns == mtime


def test_unknown_keys_from_a_newer_version_are_kept(config_home):
    config_home.mkdir(parents=True, exist_ok=True)
    (config_home / "settings.json").write_text(json.dumps({"future_option": 1}))
    s = Settings()
    s["theme"] = "X"
    s.save()
    assert json.loads((config_home / "settings.json").read_text())["future_option"] == 1


def test_shipped_pwndbg_defaults_apply_until_the_user_has_saved_their_own(config_home):
    assert Settings()["pwndbg_config"]["show-compact-regs"] == "hardcut"
    config_home.mkdir(parents=True, exist_ok=True)
    (config_home / "settings.json").write_text(json.dumps({"pwndbg_config": {"show-flags": "off"}}))
    assert Settings()["pwndbg_config"] == {"show-flags": "off"}  # a saved config replaces them
