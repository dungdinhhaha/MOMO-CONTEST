"""Outbound, read-only GitHub Actions or GitLab CI collector for PathGuard.

Run beside the customer's CI/CD system. Provider credentials remain in the
process environment; only selected execution metadata reaches PathGuard.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from collectors.aws_config_aggregator_upload import (
    MAX_BUNDLE_BYTES, SCHEMA_VERSION, backend_request, connector_token, strip_sensitive_fields,
)


MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_RUNS = 100
MAX_JOBS_PER_RUN = 100
REF = re.compile(r"[A-Za-z0-9._:-]{3,128}\Z")
GITHUB_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def timestamp(value, fallback=None):
    if not value:
        return fallback
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return fallback
        return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    except (ValueError, TypeError):
        return fallback


def load_config(path):
    raw = Path(path).read_bytes()
    if len(raw) > 64 * 1024:
        raise ValueError("CI/CD connector config exceeds 64 KiB")
    value = json.loads(raw)
    allowed = {"schema_version", "connection_id", "provider", "repository", "service",
               "environment", "workflow_names", "deploy_job_names", "backend_url",
               "credential_file", "state_file"}
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValueError("CI/CD connector config contains unsupported fields")
    if value.get("schema_version") != "pathguard.cicd-connector.v1":
        raise ValueError("Unsupported CI/CD connector config schema")
    if value.get("provider") not in {"github_actions", "gitlab_ci"}:
        raise ValueError("provider must be github_actions or gitlab_ci")
    for field in ("connection_id", "repository", "service", "environment", "backend_url", "credential_file", "state_file"):
        if not isinstance(value.get(field), str) or not value[field].strip():
            raise ValueError(f"{field} is required")
    if not REF.fullmatch(value["connection_id"]):
        raise ValueError("connection_id has an invalid format")
    if value["provider"] == "github_actions" and not GITHUB_REPOSITORY.fullmatch(value["repository"]):
        raise ValueError("GitHub repository must be owner/name")
    for field in ("workflow_names", "deploy_job_names"):
        rows = value.get(field, [])
        if not isinstance(rows, list) or any(not isinstance(item, str) or not item.strip() for item in rows):
            raise ValueError(f"{field} must be a string array")
        value[field] = rows
    parsed = urllib.parse.urlparse(value["backend_url"])
    if (parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1"})):
        raise ValueError("backend_url must use HTTPS, except loopback development")
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("backend_url must not contain credentials or query strings")
    base = Path(path).resolve().parent
    for field in ("credential_file", "state_file"):
        target = Path(value[field]).expanduser()
        value[field] = str((base / target).resolve() if not target.is_absolute() else target.resolve())
    value["backend_url"] = value["backend_url"].rstrip("/")
    return value


def provider_get(url, provider, token, *, opener=None):
    expected = "api.github.com" if provider == "github_actions" else "gitlab.com"
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != expected:
        raise ValueError("CI/CD provider URL is outside the selected provider")
    headers = {"Accept": "application/json", "User-Agent": "PathGuard-CICD-Connector/1"}
    if provider == "github_actions":
        headers["X-GitHub-Api-Version"] = "2022-11-28"
        if token:
            headers["Authorization"] = f"Bearer {token}"
    else:
        headers["PRIVATE-TOKEN"] = token
    request = urllib.request.Request(url, headers=headers)
    client = opener or urllib.request.build_opener(NoRedirect)
    try:
        with client.open(request, timeout=20) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        raise ValueError(f"CI/CD provider returned HTTP {error.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise ValueError(f"CI/CD provider request failed ({type(error).__name__})") from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("CI/CD provider response exceeds 2 MiB")
    return json.loads(raw)


def collect_github(config, token, fetch=provider_get):
    repo = config["repository"]
    root = f"https://api.github.com/repos/{repo}"
    response = fetch(f"{root}/actions/runs?per_page={MAX_RUNS}&page=1", "github_actions", token)
    runs = response.get("workflow_runs")
    if not isinstance(runs, list):
        raise ValueError("GitHub Actions response has no workflow_runs array")
    selected = [run for run in runs if not config["workflow_names"]
                or run.get("name") in config["workflow_names"]]
    entries = []
    for run in selected[:MAX_RUNS]:
        if not isinstance(run, dict) or run.get("id") is None:
            continue
        matched = []
        if config["deploy_job_names"]:
            jobs_response = fetch(f"{root}/actions/runs/{run['id']}/jobs?per_page={MAX_JOBS_PER_RUN}",
                                  "github_actions", token)
            jobs = jobs_response.get("jobs", [])
            matched = [job for job in jobs if job.get("name") in config["deploy_job_names"]]
        started = timestamp(run.get("run_started_at") or run.get("created_at"))
        if not started:
            continue
        entries.append({"run_id": str(run["id"]), "provider": "github_actions",
                        "repository": repo, "workflow": run.get("name"), "service": config["service"],
                        "environment": config["environment"],
                        "mapping_source": "connector_config",
                        "started_at": started, "updated_at": timestamp(run.get("updated_at"), started),
                        "status": run.get("status"), "conclusion": run.get("conclusion"),
                        "commit_sha": run.get("head_sha"), "branch": run.get("head_branch"),
                        "actor": (run.get("actor") or {}).get("login"),
                        "run_url": run.get("html_url"),
                        "deployment_job_observed": bool(matched),
                        "deployment_jobs": [{"name": job.get("name"), "status": job.get("status"),
                                             "conclusion": job.get("conclusion"),
                                             "started_at": timestamp(job.get("started_at")),
                                             "completed_at": timestamp(job.get("completed_at"))}
                                            for job in matched[:20]],
                        "runtime_version_verified": False,
                        "provenance": "live_provider_api"})
    return entries, {"provider": "github_actions", "repository": repo,
                     "runs_scanned": len(runs), "runs_selected": len(selected),
                     "page_limit": 1, "truncated": len(runs) == MAX_RUNS or len(selected) > MAX_RUNS,
                     "deployment_job_names_configured": bool(config["deploy_job_names"])}


def collect_gitlab(config, token, fetch=provider_get):
    project = urllib.parse.quote(config["repository"], safe="")
    root = f"https://gitlab.com/api/v4/projects/{project}"
    runs = fetch(f"{root}/pipelines?per_page={MAX_RUNS}&page=1", "gitlab_ci", token)
    if not isinstance(runs, list):
        raise ValueError("GitLab CI response must be an array")
    entries = []
    for run in runs[:MAX_RUNS]:
        if not isinstance(run, dict) or run.get("id") is None:
            continue
        if config["workflow_names"] and run.get("name") not in config["workflow_names"]:
            continue
        matched = []
        if config["deploy_job_names"]:
            jobs = fetch(f"{root}/pipelines/{run['id']}/jobs?per_page={MAX_JOBS_PER_RUN}",
                         "gitlab_ci", token)
            if not isinstance(jobs, list):
                raise ValueError("GitLab jobs response must be an array")
            matched = [job for job in jobs if job.get("name") in config["deploy_job_names"]]
        started = timestamp(run.get("started_at") or run.get("created_at"))
        if not started:
            continue
        entries.append({"run_id": str(run["id"]), "provider": "gitlab_ci",
                        "repository": config["repository"], "workflow": run.get("name") or "pipeline",
                        "service": config["service"], "environment": config["environment"],
                        "mapping_source": "connector_config", "started_at": started,
                        "updated_at": timestamp(run.get("updated_at"), started),
                        "status": run.get("status"), "conclusion": run.get("status"),
                        "commit_sha": run.get("sha"), "branch": run.get("ref"),
                        "run_url": run.get("web_url"), "deployment_job_observed": bool(matched),
                        "deployment_jobs": [{"name": job.get("name"), "status": job.get("status"),
                                             "started_at": timestamp(job.get("started_at")),
                                             "completed_at": timestamp(job.get("finished_at"))}
                                            for job in matched[:20]],
                        "runtime_version_verified": False,
                        "provenance": "live_provider_api"})
    return entries, {"provider": "gitlab_ci", "repository": config["repository"],
                     "runs_scanned": len(runs), "page_limit": 1, "truncated": len(runs) == MAX_RUNS,
                     "deployment_job_names_configured": bool(config["deploy_job_names"])}


def build_bundle(config, entries, source_coverage):
    now = datetime.now(timezone.utc)
    stamp = now.isoformat(timespec="seconds").replace("+00:00", "Z")
    records = []
    for row in entries:
        key = f"cicd/{config['provider']}/{config['repository']}/{row['run_id']}"
        cleaned = strip_sensitive_fields(row, [])
        digest = hashlib.sha256(json.dumps(cleaned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        records.append({"id": "cicd-" + digest, "evidence_type": "cicd-run",
                        "resource_key": key[:512], "observed_at": row["updated_at"], "payload": cleaned})
    coverage_key = f"cicd/{config['connection_id']}/coverage/{stamp}"
    records.append({"id": "cicd-coverage-" + hashlib.sha256(coverage_key.encode()).hexdigest(),
                    "evidence_type": "cicd-source-coverage", "resource_key": coverage_key,
                    "observed_at": stamp,
                    "payload": {**source_coverage, "connection_id": config["connection_id"],
                                "service": config["service"], "environment": config["environment"],
                                "limitations": ["Connector configuration supplies service/environment mapping.",
                                                "A successful pipeline is not proof of an authorized hotfix or running version."]}})
    bundle = {"schema_version": SCHEMA_VERSION, "source_type": "CI_CD",
              "connection_id": config["connection_id"], "collected_at": stamp,
              "records": records,
              "coverage": {"status": "partial", "window_start": (now - timedelta(seconds=1)).isoformat(timespec="seconds").replace("+00:00", "Z"),
                           "window_end": stamp}}
    if len(json.dumps(bundle, ensure_ascii=False, separators=(",", ":")).encode()) > MAX_BUNDLE_BYTES:
        raise ValueError("CI/CD evidence bundle exceeds 2 MiB")
    return bundle


def sync_once(config, fetch=provider_get, upload=backend_request):
    token = os.environ.get("PATHGUARD_CICD_API_TOKEN", "").strip()
    if not token and config["provider"] != "github_actions":
        raise ValueError("PATHGUARD_CICD_API_TOKEN is required for GitLab CI")
    if config["provider"] == "github_actions":
        entries, source_coverage = collect_github(config, token, fetch)
    else:
        entries, source_coverage = collect_gitlab(config, token, fetch)
    state_path = Path(config["state_file"])
    try:
        state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
    except (OSError, ValueError):
        state = {}
    seen = state.get("seen", {}) if state.get("connection_id") == config["connection_id"] else {}
    changed = [row for row in entries if seen.get(row["run_id"]) != row["updated_at"]]
    # Coverage is sent even when no run changed, so missing source history is visible.
    bundle = build_bundle(config, changed, source_coverage)
    connector = connector_token(config["backend_url"], config["connection_id"],
                                Path(config["credential_file"]), expected_type="CI_CD")
    response = upload(config["backend_url"], "/api/v1/evidence/bundles", bundle, connector)
    if response.get("recordCount") != len(bundle["records"]):
        raise ValueError("PathGuard did not acknowledge all CI/CD evidence records")
    next_seen = {row["run_id"]: row["updated_at"] for row in entries}
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps({"connection_id": config["connection_id"], "seen": next_seen},
                                     separators=(",", ":")), encoding="utf-8")
    return {"bundle_id": response.get("bundleId"), "new_or_updated_runs": len(changed),
            "runs_scanned": source_coverage["runs_scanned"],
            "truncated": source_coverage["truncated"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--interval", type=int, default=0,
                        help="Poll interval in seconds; 0 runs once")
    args = parser.parse_args()
    try:
        if args.interval and args.interval < 60:
            raise ValueError("Polling interval must be at least 60 seconds")
        config = load_config(args.config)
        while True:
            print(json.dumps(sync_once(config)), flush=True)
            if not args.interval:
                return 0
            time.sleep(args.interval)
    except Exception as error:
        print(f"CI/CD sync failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
