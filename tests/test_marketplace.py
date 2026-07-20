"""Marketplace tests: marketplace.json is valid JSON, has required fields, and each
plugin's relative source path exists."""
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MARKETPLACE = os.path.join(ROOT, ".claude-plugin", "marketplace.json")


def _load():
    with open(MARKETPLACE, "r", encoding="utf-8") as fh:
        return json.load(fh)


def test_marketplace_is_valid_json():
    data = _load()
    assert isinstance(data, dict)


def test_required_fields_present():
    data = _load()
    assert isinstance(data.get("name"), str) and data["name"]
    owner = data.get("owner")
    assert isinstance(owner, dict), "owner must be an object, not a string"
    assert owner.get("name"), "owner.name is required"
    assert isinstance(data.get("plugins"), list) and data["plugins"], "plugins array required"


def test_marketplace_name_differs_from_plugin():
    data = _load()
    names = {p["name"] for p in data["plugins"]}
    assert data["name"] not in names, "marketplace name should differ from plugin names"


def test_plugin_entries_have_name_and_source():
    data = _load()
    for entry in data["plugins"]:
        assert entry.get("name"), "each plugin needs a name"
        assert entry.get("source"), "each plugin needs a source"
        assert entry.get("description"), "each plugin needs a description"


def test_plugin_relative_source_paths_exist():
    data = _load()
    for entry in data["plugins"]:
        source = entry["source"]
        if isinstance(source, str):  # relative-path source
            path = os.path.normpath(os.path.join(ROOT, source))
            assert os.path.isdir(path), f"plugin source path missing: {source}"
            manifest = os.path.join(path, ".claude-plugin", "plugin.json")
            assert os.path.isfile(manifest), f"plugin.json missing under {source}"
