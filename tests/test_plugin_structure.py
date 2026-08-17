"""Plugin structure tests: plugin.json exists and matches the marketplace entry, SKILL.md
exists at the expected path, and the skill directory layout is correct."""
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN_DIR = os.path.join(ROOT, "plugins", "llm-zap-dast")
PLUGIN_JSON = os.path.join(PLUGIN_DIR, ".claude-plugin", "plugin.json")
SKILL = os.path.join(PLUGIN_DIR, "skills", "dast", "SKILL.md")


def test_plugin_json_exists_and_valid():
    assert os.path.isfile(PLUGIN_JSON)
    with open(PLUGIN_JSON, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    assert data["name"] == "llm-zap-dast"
    assert data.get("description")
    assert isinstance(data.get("author"), dict), "author must be an object"
    assert data["author"].get("name")
    assert data.get("repository")
    assert data.get("license")


def test_plugin_name_matches_marketplace():
    with open(PLUGIN_JSON, "r", encoding="utf-8") as fh:
        plugin = json.load(fh)
    with open(os.path.join(ROOT, ".claude-plugin", "marketplace.json"), "r", encoding="utf-8") as fh:
        market = json.load(fh)
    entry_names = {p["name"] for p in market["plugins"]}
    assert plugin["name"] in entry_names


def test_skill_md_exists():
    assert os.path.isfile(SKILL)


def test_skill_frontmatter():
    with open(SKILL, "r", encoding="utf-8") as fh:
        text = fh.read()
    assert text.startswith("---"), "SKILL.md must start with YAML frontmatter"
    front = text.split("---", 2)[1]
    assert "disable-model-invocation: true" in front, "manual-only invocation required"
    assert "description:" in front


def test_skill_directory_name_drives_command():
    # Command name is /llm-zap-dast:dast — 'dast' comes from the directory name.
    assert os.path.isdir(os.path.join(PLUGIN_DIR, "skills", "dast"))


def test_references_and_templates_present():
    ref = os.path.join(PLUGIN_DIR, "skills", "dast", "references")
    tpl = os.path.join(PLUGIN_DIR, "skills", "dast", "templates")
    # All nine references, authentication.md included: it is the authority for step 2.5 and
    # was the one file this list forgot, so the authenticated half of the plugin could have
    # gone missing from a release with the suite still green.
    for name in ("methodology.md", "safety-policy.md", "source-analysis.md",
                 "zap-integration.md", "scenario-testing.md", "redaction.md",
                 "report-format.md", "config-init.md", "authentication.md"):
        assert os.path.isfile(os.path.join(ref, name)), f"missing reference {name}"
    for name in ("dast-config.example.yaml", "target-map.example.md",
                 "scenario-list.example.md", "report.example.md",
                 "authentication.example.md"):
        assert os.path.isfile(os.path.join(tpl, name)), f"missing template {name}"


def test_scripts_present():
    scripts = os.path.join(PLUGIN_DIR, "scripts")
    for name in ("check_environment.py", "validate_config.py", "redact.py", "zap_control.py",
                 "zap_auth.py"):
        assert os.path.isfile(os.path.join(scripts, name)), f"missing script {name}"


def test_every_reference_and_template_is_linked_from_the_skill():
    """A file nothing points at is a file the run never opens.

    SKILL.md is the flow controller and reaches the detail through links; references link
    each other. authentication.example.md was reachable from nothing at all.
    """
    skill_dir = os.path.join(PLUGIN_DIR, "skills", "dast")
    corpus = ""
    for sub in ("", "references", "templates"):
        d = os.path.join(skill_dir, sub)
        for name in os.listdir(d):
            if name.endswith(".md"):
                with open(os.path.join(d, name), encoding="utf-8") as fh:
                    corpus += fh.read()
    for sub in ("references", "templates"):
        for name in sorted(os.listdir(os.path.join(skill_dir, sub))):
            if not name.endswith((".md", ".yaml")):
                continue
            assert name in corpus, f"{sub}/{name} is referenced by no other file"


def test_manifests_not_holding_extra_dirs():
    # .claude-plugin must contain only the manifest, not skills/scripts.
    cp = os.path.join(PLUGIN_DIR, ".claude-plugin")
    entries = set(os.listdir(cp))
    assert entries == {"plugin.json"}, f"unexpected entries in .claude-plugin: {entries}"
