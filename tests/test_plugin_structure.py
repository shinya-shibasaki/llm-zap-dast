"""Plugin structure tests: plugin.json exists and matches the marketplace entry, SKILL.md
exists at the expected path, and the skill directory layout is correct."""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN_DIR = os.path.join(ROOT, "plugins", "llm-zap-dast")
sys.path.insert(0, os.path.join(PLUGIN_DIR, "scripts"))
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
                 "report-format.md", "config-init.md", "authentication.md",
                 "sast-handoff.md"):
        assert os.path.isfile(os.path.join(ref, name)), f"missing reference {name}"
    for name in ("dast-config.example.yaml", "target-map.example.md",
                 "scenario-list.example.md", "report.example.md",
                 "authentication.example.md"):
        assert os.path.isfile(os.path.join(tpl, name)), f"missing template {name}"


def test_scripts_present():
    scripts = os.path.join(PLUGIN_DIR, "scripts")
    for name in ("check_environment.py", "validate_config.py", "validate_sast_config.py",
                 "redact.py", "zap_control.py", "zap_auth.py"):
        assert os.path.isfile(os.path.join(scripts, name)), f"missing script {name}"


def _skill_names():
    skills_dir = os.path.join(PLUGIN_DIR, "skills")
    return sorted(n for n in os.listdir(skills_dir)
                  if os.path.isfile(os.path.join(skills_dir, n, "SKILL.md")))


def test_both_skills_are_present():
    assert set(_skill_names()) == {"dast", "sast"}, _skill_names()


def test_every_skill_is_manual_only():
    """Both skills are expensive and consequential — DAST sends attacks, SAST fans out to
    six subagents. Neither may start because a prompt sounded related.
    """
    for skill in _skill_names():
        with open(os.path.join(PLUGIN_DIR, "skills", skill, "SKILL.md"), encoding="utf-8") as fh:
            text = fh.read()
        assert text.startswith("---"), f"skills/{skill}/SKILL.md needs YAML frontmatter"
        front = text.split("---", 2)[1]
        assert "disable-model-invocation: true" in front, f"{skill}: manual-only required"
        assert "description:" in front, f"{skill}: description required"
        assert f"name: {skill}" in front, f"{skill}: frontmatter name must match the directory"


def test_every_reference_and_template_is_linked_from_its_skill():
    """A file nothing points at is a file the run never opens.

    SKILL.md is the flow controller and reaches the detail through links; references link
    each other. authentication.example.md was reachable from nothing at all.
    """
    for skill in _skill_names():
        skill_dir = os.path.join(PLUGIN_DIR, "skills", skill)
        corpus = ""
        for sub in ("", "references", "templates"):
            d = os.path.join(skill_dir, sub)
            if not os.path.isdir(d):
                continue
            for name in os.listdir(d):
                if name.endswith(".md"):
                    with open(os.path.join(d, name), encoding="utf-8") as fh:
                        corpus += fh.read()
        for sub in ("references", "templates"):
            d = os.path.join(skill_dir, sub)
            if not os.path.isdir(d):
                continue
            for name in sorted(os.listdir(d)):
                if not name.endswith((".md", ".yaml")):
                    continue
                assert name in corpus, f"{skill}/{sub}/{name} is referenced by no other file"


def test_sast_references_present():
    ref = os.path.join(PLUGIN_DIR, "skills", "sast", "references")
    for name in ("safety-policy.md", "profiling.md", "attack-map.md", "method.md",
                 "severity-cvss.md", "report-format.md", "config-init.md"):
        assert os.path.isfile(os.path.join(ref, name)), f"missing sast reference {name}"
    tpl = os.path.join(PLUGIN_DIR, "skills", "sast", "templates")
    assert os.path.isfile(os.path.join(tpl, "report.example.md"))


# Which reference each skill hands to a subagent. The parent holds the safety rules but the
# child is what reads the material, so every one of these files has to point back at both
# layers on its own.
_SUBAGENT_READS = {
    "sast": ("profiling.md", "attack-map.md", "method.md"),
    # DAST delegates the SAST-artefact extraction (step 2). Its child reads a TRANSCRIPT of
    # target-derived text and its output drives packets the parent sends, so it needs the same
    # double path even though DAST runs most of its steps in the parent.
    "dast": ("sast-handoff.md",),
}


def test_subagent_contract_is_reachable_by_the_files_subagents_read():
    """The safety rules live with the parent, but the child is what reads the material. Each
    reference a subagent opens has to point back at them, so a parent that forgets to paste
    the contract is not the only thing standing between the target and an unguarded agent.
    """
    for skill, names in _SUBAGENT_READS.items():
        ref = os.path.join(PLUGIN_DIR, "skills", skill, "references")
        with open(os.path.join(ref, "safety-policy.md"), encoding="utf-8") as fh:
            assert "サブエージェント契約" in fh.read(), (
                f"{skill}: verbatim contract block is missing")
        for name in names:
            with open(os.path.join(ref, name), encoding="utf-8") as fh:
                text = fh.read()
            assert "safety-core.md" in text and "safety-policy.md" in text, (
                f"{skill}/{name} is read by a subagent and must send it to both safety "
                f"layers first")


def test_dast_subagent_contract_forbids_sending_and_deciding_safety():
    """The DAST child's risk shape is the inverse of the SAST child's: it does not read the
    target, it reads a document about the target, and what it writes decides where the parent
    aims. So the contract has to forbid sending, forbid ruling on safety, and say that the
    artefact's own prose (which really does address downstream agents in the imperative) is
    data. A contract that only forbade reading would leave all three open.
    """
    p = os.path.join(PLUGIN_DIR, "skills", "dast", "references", "safety-policy.md")
    with open(p, encoding="utf-8") as fh:
        text = fh.read()
    block = text.split("サブエージェント契約", 1)[1].split("```", 2)[1]
    assert "送信しない" in block, "the child must be told not to touch the network"
    assert "安全の判断をしない" in block, "8A/8B/8C rulings belong to the parent and step 0"
    assert "指示ではない" in block, "artefact prose must be declared data, not instructions"
    assert "縮退させない" in block, "the child must escalate mismatches instead of tidying them"


def test_bundled_asvs_standard_is_the_unmodified_upstream_file():
    """The SAST skill transcribes requirement IDs and wording from this CSV rather than from
    memory, so a truncated or edited copy would silently corrupt every report. The digest is
    the upstream v5.0.0 file; NOTICE states the same value as the provenance claim, and the
    two must not drift apart.
    """
    import hashlib

    csv = os.path.join(PLUGIN_DIR, "standards",
                       "OWASP_Application_Security_Verification_Standard_5.0.0_en.csv")
    assert os.path.isfile(csv), "bundled ASVS 5.0 CSV is missing"
    with open(csv, "rb") as fh:
        digest = hashlib.md5(fh.read()).hexdigest()
    assert digest == "a4f93cd757d92095b2dc3b068fb50ce4", (
        "bundled ASVS CSV no longer matches the upstream v5.0.0 file; if this is an "
        "intentional update, refresh NOTICE (provenance, digest, size) in the same commit"
    )
    with open(os.path.join(PLUGIN_DIR, "NOTICE"), encoding="utf-8") as fh:
        notice = fh.read()
    assert digest in notice, "NOTICE must record the digest it claims provenance for"


def test_third_party_licensing_files_ship_with_the_plugin():
    """The plugin directory is what gets distributed; the repo-root LICENSE does not travel
    with it. CC BY-SA 4.0 content (the ASVS CSV) requires attribution to reach the recipient.
    """
    for name in ("LICENSE", "NOTICE"):
        assert os.path.isfile(os.path.join(PLUGIN_DIR, name)), f"missing {name} in the plugin"
    with open(os.path.join(PLUGIN_DIR, "NOTICE"), encoding="utf-8") as fh:
        notice = fh.read()
    assert "CC BY-SA 4.0" in notice, "NOTICE must name the ASVS license"
    assert "OWASP" in notice, "NOTICE must attribute OWASP"


def test_manifests_not_holding_extra_dirs():
    # .claude-plugin must contain only the manifest, not skills/scripts.
    cp = os.path.join(PLUGIN_DIR, ".claude-plugin")
    entries = set(os.listdir(cp))
    assert entries == {"plugin.json"}, f"unexpected entries in .claude-plugin: {entries}"


def test_shared_safety_core_exists_and_is_read_by_every_skill():
    """The safety authority is two layers. A skill that only reads its own safety-policy.md
    would silently miss the common rules — which is exactly how a split authority fails.
    """
    core = os.path.join(PLUGIN_DIR, "references", "safety-core.md")
    assert os.path.isfile(core), "shared references/safety-core.md is missing"

    skills_dir = os.path.join(PLUGIN_DIR, "skills")
    for skill in sorted(os.listdir(skills_dir)):
        skill_md = os.path.join(skills_dir, skill, "SKILL.md")
        if not os.path.isfile(skill_md):
            continue
        with open(skill_md, encoding="utf-8") as fh:
            text = fh.read()
        assert "safety-core.md" in text, f"skills/{skill}/SKILL.md must read safety-core.md"
        assert "safety-policy.md" in text, (
            f"skills/{skill}/SKILL.md must read its own safety-policy.md")


def test_safety_core_does_not_duplicate_the_dast_specific_axes():
    """Common layer holds what applies to both skills. The 8A/8B/8C destruction axes are a
    DAST concept; copying them up would put the same rule in two authorities.
    """
    with open(os.path.join(PLUGIN_DIR, "references", "safety-core.md"), encoding="utf-8") as fh:
        core = fh.read()
    for dast_only in ("allowed_hosts", "8A", "8B", "8C", "Active Scan"):
        assert dast_only not in core, (
            f"{dast_only!r} is DAST-specific and belongs in skills/dast/references/safety-policy.md")


def test_sast_init_does_not_pin_the_semgrep_packs():
    """--init records what is in effect; it must not freeze the rule selection. Packs are
    chosen per run from the detected languages, so a pinned list would outlive the language
    mix it was derived from — and the run would keep scanning with a stale selection.
    """
    with open(os.path.join(PLUGIN_DIR, "skills", "sast", "references", "config-init.md"),
              encoding="utf-8") as fh:
        doc = fh.read()
    assert "固定しない" in doc, "config-init.md must say the packs stay unpinned"
    assert "# configs:" in doc, "the generated file must leave configs commented out"


def _dast_ref(name):
    p = os.path.join(PLUGIN_DIR, "skills", "dast", "references", name)
    with open(p, encoding="utf-8") as fh:
        return fh.read()


def test_step6_definition_of_done_covers_every_entry_not_just_high_and_medium():
    """Priority orders the work; it must not decide what gets worked on.

    SAST severities flow into the priority column, so if the DoD only bound "high/medium"
    then lowering a priority would drop an entry from the scan without any config change —
    target-derived data quietly shrinking the scope. The mirror of the existing ban on
    raising destructive/availability flags to fill the matrix.
    """
    text = _dast_ref("scenario-testing.md")
    dod = text.split("完了条件（DoD）", 1)[1][:600]
    assert "全エントリ" in dod
    assert "優先度 高／中" not in dod
    assert "順序" in dod, "the doc must say priority is ordering, not selection"


def test_step1_is_not_replaced_by_the_attack_map():
    """The stop table treats a degraded SAST run as "record and continue". That is only sound
    while step 1 still enumerates the attack surface itself — otherwise the SAST run's own
    narrowing becomes the DAST denominator's narrowing, and the report looks normal anyway.
    Both halves of that reasoning have to stay in the tree.
    """
    skill = os.path.join(PLUGIN_DIR, "skills", "dast", "SKILL.md")
    with open(skill, encoding="utf-8") as fh:
        assert "置換ではなく補強" in fh.read()
    assert "置換すると" in _dast_ref("safety-policy.md"), (
        "safety-policy must say why the continue-on-degradation rule depends on step 1")


def test_sast_artefact_reading_is_a_two_file_allowlist():
    """Not "read the run directory". The directory also holds run.log (semgrep output, command
    lines) and whatever a human dropped in later; a real run had a spreadsheet of answers
    sitting next to the reports. Naming the two files is not enough — a rule that named them
    and then said "read the directory" would still pass. The distinction itself has to be
    stated, so the assertions below track the sentence that draws it.
    """
    policy = _dast_ref("safety-policy.md")
    assert "attack-map.md" in policy and "report-04.md" in policy
    assert "ファイル単位の allowlist であって" in policy, (
        "the rule must say file-level allowlist, not just the word allowlist")
    assert "「そのディレクトリを読む」ではありません" in policy, (
        "the rule must reject directory-level reading explicitly")
    assert "run.log" in policy, "the excluded files should be named, not implied"
    assert "`sast.yaml` も読みません" in policy, (
        "reading the SAST config would reintroduce the dependency the design removed")


def test_sast_pointer_and_report_form_are_checked_by_the_validator():
    """safety-core.md §8: the layer that enforces a rule has to be named in the skill's own
    safety-policy, and the rule itself has to live somewhere other than prompt discipline.
    The pointer's value comes from a file inside the target repository and decides what the
    run opens, so a prompt-only check is the wrong layer for it.
    """
    policy = _dast_ref("safety-policy.md")
    layers = policy.split("安全がどこで担保されるか", 1)[1]
    assert "sast.report" in layers and "latest.json" in layers, (
        "validate_config's SAST checks must be listed among the enforcement layers")
    import validate_config as vc
    assert vc._repo_relative_error("~/x") is not None
    assert vc._repo_relative_error("../x") is not None
    assert vc._repo_relative_error("reports/sast/x") is None
