"""Configuration loading for redteam-agents."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .hostnorm import normalize_domain_list


@dataclass
class ProviderConfig:
    provider: str  # openai_compatible | anthropic
    base_url: str
    api_key_env: str
    model: str
    timeout: int = 240


@dataclass
class LLMConfig:
    hosted: ProviderConfig
    local: ProviderConfig
    roles: dict[str, str] = field(default_factory=dict)  # role -> hosted|local


@dataclass
class ScopeConfig:
    allow_domains: list[str] = field(default_factory=list)
    allow_cidrs: list[str] = field(default_factory=list)
    allow_subdomains: bool = True
    allow_private: bool = False
    rate_limit_per_host_per_min: int = 60


@dataclass
class SafetyConfig:
    max_agent_steps: int = 25
    observation_max_chars: int = 6000
    require_confirmation_for_active: bool = True
    business_logic: bool = False       # Phase 2.4: workflow_step/race_burst
                                       # refuse to run until the operator
                                       # opts in here (per-step/per-burst
                                       # confirmation still applies after)
    artifacts_dir: str = "./artifacts"
    mode: str = "live"                # live | record | replay (fixture modes)
    cassette_dir: str = "./cassettes"
    runner: str = "local"             # local | docker
    docker_image: str = "redteam-toolchain:latest"
    checks_dir: str = "./checks"      # custom check plugins (see README)


@dataclass
class IntelConfig:
    """Third-party CVE intel (NVD / EPSS / CISA KEV).

    These calls send target-derived product/version keywords to third-party
    APIs — set enabled: false when fingerprints must not leave the machine.
    """
    enabled: bool = True
    nvd_api_key_env: str = ""         # optional NVD API key env var name
    cache_ttl_hours: int = 24


SEVERITIES = ("critical", "high", "medium", "low", "info")

IDENTITY_KINDS = ("form", "cookie", "bearer", "apikey")


@dataclass
class IdentityConfig:
    """One test identity (Phase 2.1). Secrets are referenced by ENV VAR
    NAME only — config files, findings, reports and audit logs never carry
    the values; the redaction pass (redteam.redact) scrubs them on exit.

    kind:
      form   — POST login_url with username/password fields, keep the
               session cookie jar (optionally verified via verify_url/marker)
      cookie — static session cookie string (cookie_env holds "name=value")
      bearer — Authorization: Bearer <token_env>
      apikey — <header_name>: <token_env>  (default header X-API-Key)
    """
    name: str
    kind: str
    # form login
    login_url: str = ""
    username_env: str = ""
    password_env: str = ""
    username_field: str = "email"
    password_field: str = "password"
    extra_fields: dict[str, str] = field(default_factory=dict)  # field name -> literal
    verify_url: str = ""        # optional post-login check
    verify_marker: str = ""     # response must contain this to count as logged in
    # static credential kinds
    cookie_env: str = ""
    token_env: str = ""
    header_name: str = ""       # apikey only; default X-API-Key
    logout_url: str = ""        # optional; session-lifecycle logout probe


@dataclass
class NucleiConfig:
    """Template-scan policy — enforced in code, not by prompt.

    severity_floor: lowest severity ever scanned (requested filters are clamped;
      a request entirely below the floor fails loudly instead of scanning more).
    tags_include: universe of template tags agents may request (empty = all).
    tags_exclude: never scanned — 'dos' is hard-coded on top of this
      (catalog section 22 is permanently excluded).
    template_dir + expected_commit: pinned template checkout; the tool refuses
      to scan when HEAD does not match the reviewed pin.
    update_policy: 'manual' only — templates are updated when a human reviews
      the change, never auto-latest.
    """
    severity_floor: str = "info"
    tags_include: list[str] = field(default_factory=list)
    tags_exclude: list[str] = field(default_factory=lambda: ["dos", "fuzz"])
    template_dir: str = ""
    expected_commit: str = ""
    update_policy: str = "manual"


@dataclass
class RepoConfig:
    """Repo/SCA mode policy (Phase 3.1: catalog sections 13, 24, 12/15).

    path_allowlist: repository roots the scanner may open (resolved with
      symlinks followed; containment is checked in redteam.repo — empty list
      means any absolute path the operator passes on the CLI is accepted, the
      operator IS the authorization for a local checkout).
    osv_online: osv-scanner sends package NAMES+VERSIONS to the OSV API —
      same third-party-disclosure philosophy as intel.enabled; set false for
      offline scanning against the local OSV database.
    exclude: directories no scanner descends into (.git, node_modules, ...).
    """
    path_allowlist: list[str] = field(default_factory=list)
    osv_online: bool = True
    exclude: list[str] = field(default_factory=lambda: [
        ".git", "node_modules", "vendor", "venv", ".venv",
        "__pycache__", "dist", "build", ".tox", ".mypy_cache",
    ])


@dataclass
class K8sConfig:
    """Container/Kubernetes module (catalog section 15).

    Each tool registers only when its input is set; every schema is
    argument-free, so the model cannot redirect them. kubeaudit talks to
    the cluster API read-only through the supplied kubeconfig.
    """
    image: str = ""           # trivy target image
    lint_dir: str = ""        # kube-linter target directory
    kubeconfig: str = ""      # kubeaudit target (cluster API, read-only)
    context: str = ""         # kubeconfig context (default/current)


@dataclass
class AIConfig:
    """AI/LLM endpoint module (catalog section 19).

    endpoint must also be inside scope — probes pass the ScopeGuard like
    any other target. auth_env names an ENV VAR that must be set at load
    time (fail closed: probing unauthenticated when auth was configured
    could fabricate an exposure finding). The token is registered with the
    redactor the moment the tool is constructed.
    """
    endpoint: str = ""        # base URL of the AI system under test
    auth_env: str = ""        # env var NAME holding its bearer token
    model: str = ""           # model id for prompt_probe (server may ignore)
    timeout: int = 60


@dataclass
class CloudConfig:
    """Cloud posture module (catalog section 7).

    org_hints: organization/product names -> derived storage-bucket
      candidates; every URL passes the scope guard before the request.
    report_path + report_kind ('prowler'|'scout'): a LOCAL scanner report
      parsed offline — the cloud itself is not re-checked this run, and
      the report path never becomes an LLM argument.
    """
    org_hints: list[str] = field(default_factory=list)
    report_path: str = ""
    report_kind: str = ""
    timeout: int = 20


@dataclass
class ADConfig:
    """Active Directory module (catalog section 17).

    collect: explicit operator gate for ad_collect (passive
      bloodhound-python LDAP/Global-Catalog reads against dc_ip/domain;
      ambient Kerberos credentials only — this config never carries
      usernames or passwords).
    analyze_report: operator-supplied BloodHound graph for ad_analyze
      (attack-path analysis; paths are reported, never executed).
    """
    collect: bool = False
    dc_ip: str = ""
    domain: str = ""
    analyze_report: str = ""
    max_depth: int = 8


@dataclass
class MobileConfig:
    """Mobile artifact module (catalog section 14) — all offline:
    paths to the operator's AndroidManifest.xml / APK / decompiled tree."""
    manifest_path: str = ""
    apk_path: str = ""
    decompiled_dir: str = ""


@dataclass
class AppConfig:
    llm: LLMConfig
    scope: ScopeConfig
    safety: SafetyConfig
    intel: IntelConfig = field(default_factory=IntelConfig)
    nuclei: NucleiConfig = field(default_factory=NucleiConfig)
    repo: RepoConfig = field(default_factory=RepoConfig)
    identities: list[IdentityConfig] = field(default_factory=list)
    k8s: K8sConfig = field(default_factory=K8sConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    cloud: CloudConfig = field(default_factory=CloudConfig)
    ad: ADConfig = field(default_factory=ADConfig)
    mobile: MobileConfig = field(default_factory=MobileConfig)


def _provider(data: dict, name: str) -> ProviderConfig:
    missing = [k for k in ("provider", "base_url", "model") if k not in data]
    if missing:
        raise ValueError(f"llm.{name} is missing keys: {missing}")
    return ProviderConfig(
        provider=data["provider"],
        base_url=data["base_url"].rstrip("/"),
        api_key_env=data.get("api_key_env", ""),
        model=data["model"],
        timeout=int(data.get("timeout", 240)),
    )


def _identity(data: dict) -> IdentityConfig:
    if not isinstance(data, dict):
        raise ValueError(f"identities entries must be mappings, got {data!r}")
    name = str(data.get("name", "")).strip()
    if not name:
        raise ValueError("each identity needs a non-empty 'name'")
    kind = str(data.get("kind", "")).strip().lower()
    if kind not in IDENTITY_KINDS:
        raise ValueError(
            f"identity {name!r}: kind must be one of {IDENTITY_KINDS}, got {kind!r}"
        )
    ident = IdentityConfig(
        name=name,
        kind=kind,
        login_url=str(data.get("login_url", "")),
        username_env=str(data.get("username_env", "")),
        password_env=str(data.get("password_env", "")),
        username_field=str(data.get("username_field", "email")),
        password_field=str(data.get("password_field", "password")),
        extra_fields={str(k): str(v) for k, v in (data.get("extra_fields") or {}).items()},
        verify_url=str(data.get("verify_url", "")),
        verify_marker=str(data.get("verify_marker", "")),
        cookie_env=str(data.get("cookie_env", "")),
        token_env=str(data.get("token_env", "")),
        header_name=str(data.get("header_name", "")),
        logout_url=str(data.get("logout_url", "")),
    )
    if kind == "form":
        missing = [k for k in ("login_url", "username_env", "password_env")
                   if not getattr(ident, k)]
        if missing:
            raise ValueError(f"identity {name!r} (form): missing {missing}")
        if not ident.login_url.startswith(("http://", "https://")):
            raise ValueError(f"identity {name!r}: login_url must be http(s)")
    elif kind == "cookie" and not ident.cookie_env:
        raise ValueError(f"identity {name!r} (cookie): missing cookie_env")
    elif kind in ("bearer", "apikey") and not ident.token_env:
        raise ValueError(f"identity {name!r} ({kind}): missing token_env")
    if kind == "apikey" and not ident.header_name:
        ident.header_name = "X-API-Key"
    if (ident.verify_url or ident.verify_marker) and not (
            ident.verify_url and ident.verify_marker):
        raise ValueError(
            f"identity {name!r}: verify_url and verify_marker must be set together"
        )
    if ident.logout_url and not ident.logout_url.startswith(("http://", "https://")):
        raise ValueError(f"identity {name!r}: logout_url must be http(s)")
    return ident


def load_config(path: str | Path) -> AppConfig:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))

    llm_raw = raw.get("llm") or {}
    if "hosted" not in llm_raw or "local" not in llm_raw:
        raise ValueError("config must define llm.hosted and llm.local")

    llm = LLMConfig(
        hosted=_provider(llm_raw["hosted"], "hosted"),
        local=_provider(llm_raw["local"], "local"),
        roles=dict(llm_raw.get("roles") or {}),
    )

    scope_raw = raw.get("scope") or {}
    scope = ScopeConfig(
        allow_domains=normalize_domain_list(scope_raw.get("allow_domains", [])),
        allow_cidrs=list(scope_raw.get("allow_cidrs", [])),
        allow_subdomains=bool(scope_raw.get("allow_subdomains", True)),
        allow_private=bool(scope_raw.get("allow_private", False)),
        rate_limit_per_host_per_min=int(scope_raw.get("rate_limit_per_host_per_min", 60)),
    )

    safety_raw = raw.get("safety") or {}
    safety = SafetyConfig(
        max_agent_steps=int(safety_raw.get("max_agent_steps", 25)),
        observation_max_chars=int(safety_raw.get("observation_max_chars", 6000)),
        require_confirmation_for_active=bool(safety_raw.get("require_confirmation_for_active", True)),
        business_logic=bool(safety_raw.get("business_logic", False)),
        artifacts_dir=safety_raw.get("artifacts_dir", "./artifacts"),
        mode=str(safety_raw.get("mode", "live")),
        cassette_dir=str(safety_raw.get("cassette_dir", "./cassettes")),
        runner=str(safety_raw.get("runner", "local")),
        docker_image=str(safety_raw.get("docker_image", "redteam-toolchain:latest")),
        checks_dir=str(safety_raw.get("checks_dir", "./checks")),
    )
    if safety.mode not in ("live", "record", "replay"):
        raise ValueError(f"safety.mode must be live|record|replay, got {safety.mode!r}")
    if safety.runner not in ("local", "docker"):
        raise ValueError(f"safety.runner must be local|docker, got {safety.runner!r}")

    intel_raw = raw.get("intel") or {}
    intel = IntelConfig(
        enabled=bool(intel_raw.get("enabled", True)),
        nvd_api_key_env=str(intel_raw.get("nvd_api_key_env", "")),
        cache_ttl_hours=int(intel_raw.get("cache_ttl_hours", 24)),
    )

    nuc_raw = raw.get("nuclei") or {}
    nuclei = NucleiConfig(
        severity_floor=str(nuc_raw.get("severity_floor", "info")).lower(),
        tags_include=[str(t).strip().lower() for t in nuc_raw.get("tags_include", [])],
        tags_exclude=[str(t).strip().lower() for t in nuc_raw.get("tags_exclude",
                                                                   ["dos", "fuzz"])],
        template_dir=str(nuc_raw.get("template_dir", "")),
        expected_commit=str(nuc_raw.get("expected_commit", "")),
        update_policy=str(nuc_raw.get("update_policy", "manual")).lower(),
    )
    if nuclei.severity_floor not in SEVERITIES:
        raise ValueError(
            f"nuclei.severity_floor must be one of {SEVERITIES}, "
            f"got {nuclei.severity_floor!r}"
        )
    if nuclei.update_policy != "manual":
        raise ValueError(
            "nuclei.update_policy supports 'manual' only — template updates are "
            "reviewed by a human (auto-latest is deliberately not implemented); "
            f"got {nuclei.update_policy!r}"
        )

    identities_raw = raw.get("identities") or []
    identities = [_identity(entry) for entry in identities_raw]
    seen: set[str] = set()
    for ident in identities:
        if ident.name in seen:
            raise ValueError(f"duplicate identity name: {ident.name!r}")
        seen.add(ident.name)

    repo_raw = raw.get("repo") or {}
    repo = RepoConfig(
        path_allowlist=[str(p) for p in (repo_raw.get("path_allowlist") or [])],
        osv_online=bool(repo_raw.get("osv_online", True)),
        exclude=[str(e) for e in (repo_raw.get("exclude") or RepoConfig().exclude)],
    )

    k8s_raw = raw.get("k8s") or {}
    k8s = K8sConfig(
        image=str(k8s_raw.get("image", "")),
        lint_dir=str(k8s_raw.get("lint_dir", "")),
        kubeconfig=str(k8s_raw.get("kubeconfig", "")),
        context=str(k8s_raw.get("context", "")),
    )

    ai_raw = raw.get("ai") or {}
    ai = AIConfig(
        endpoint=str(ai_raw.get("endpoint", "")).rstrip("/"),
        auth_env=str(ai_raw.get("auth_env", "")),
        model=str(ai_raw.get("model", "")),
        timeout=int(ai_raw.get("timeout", 60)),
    )
    if ai.endpoint and not ai.endpoint.startswith(("http://", "https://")):
        raise ValueError(f"ai.endpoint must be http(s), got {ai.endpoint!r}")
    if ai.auth_env and not os.environ.get(ai.auth_env):
        raise ValueError(
            f"ai.auth_env names {ai.auth_env!r} but that environment "
            "variable is not set — refusing to run the AI probes "
            "unauthenticated when auth was configured"
        )

    cloud_raw = raw.get("cloud") or {}
    cloud = CloudConfig(
        org_hints=[str(h) for h in (cloud_raw.get("org_hints") or [])],
        report_path=str(cloud_raw.get("report_path", "")),
        report_kind=str(cloud_raw.get("report_kind", "")).lower(),
        timeout=int(cloud_raw.get("timeout", 20)),
    )
    if bool(cloud.report_path) != bool(cloud.report_kind):
        raise ValueError(
            "cloud.report_path and cloud.report_kind must be set together "
            f"(got path={cloud.report_path!r} kind={cloud.report_kind!r})"
        )
    if cloud.report_kind and cloud.report_kind not in ("prowler", "scout"):
        raise ValueError(
            f"cloud.report_kind must be prowler|scout, got {cloud.report_kind!r}"
        )

    ad_raw = raw.get("ad") or {}
    ad = ADConfig(
        collect=bool(ad_raw.get("collect", False)),
        dc_ip=str(ad_raw.get("dc_ip", "")),
        domain=str(ad_raw.get("domain", "")),
        analyze_report=str(ad_raw.get("analyze_report", "")),
        max_depth=int(ad_raw.get("max_depth", 8)),
    )
    if ad.collect and not (ad.dc_ip and ad.domain):
        raise ValueError("ad.collect requires ad.dc_ip and ad.domain")

    mobile_raw = raw.get("mobile") or {}
    mobile = MobileConfig(
        manifest_path=str(mobile_raw.get("manifest_path", "")),
        apk_path=str(mobile_raw.get("apk_path", "")),
        decompiled_dir=str(mobile_raw.get("decompiled_dir", "")),
    )

    return AppConfig(llm=llm, scope=scope, safety=safety, intel=intel,
                     nuclei=nuclei, repo=repo, identities=identities,
                     k8s=k8s, ai=ai, cloud=cloud, ad=ad, mobile=mobile)


def resolve_api_key(cfg: ProviderConfig) -> str:
    """Read the API key from the environment variable named in config."""
    if not cfg.api_key_env:
        return ""
    return os.environ.get(cfg.api_key_env, "")
