import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from collectors import cicd_connector as cicd


class CiCdConnectorTest(unittest.TestCase):
    def config(self, directory, provider="github_actions"):
        path = Path(directory) / "config.json"
        path.write_text(json.dumps({
            "schema_version": "pathguard.cicd-connector.v1",
            "connection_id": "github-wallet-prod", "provider": provider,
            "repository": "team/wallet", "service": "wallet-api",
            "environment": "production", "workflow_names": ["Deploy"],
            "deploy_job_names": ["deploy-prod"], "backend_url": "https://pathguard.example",
            "credential_file": "credential.token", "state_file": "state.json",
        }), encoding="utf-8")
        return cicd.load_config(path)

    def test_github_run_requires_matching_deploy_job(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(directory)

            def fetch(url, provider, token):
                if url.endswith("/jobs?per_page=100"):
                    return {"jobs": [{"name": "deploy-prod", "status": "completed",
                                      "conclusion": "success", "started_at": "2026-11-25T01:03:00Z",
                                      "completed_at": "2026-11-25T01:04:00Z"}]}
                return {"workflow_runs": [{"id": 42, "name": "Deploy",
                                          "run_started_at": "2026-11-25T01:00:00Z",
                                          "updated_at": "2026-11-25T01:04:00Z",
                                          "status": "completed", "conclusion": "success",
                                          "head_sha": "abc", "actor": {"login": "engineer"}}]}

            entries, coverage = cicd.collect_github(config, "provider-token", fetch)
            self.assertEqual(len(entries), 1)
            self.assertTrue(entries[0]["deployment_job_observed"])
            self.assertFalse(entries[0]["runtime_version_verified"])
            self.assertEqual(coverage["runs_scanned"], 1)
            bundle = cicd.build_bundle(config, entries, coverage)
            self.assertEqual(bundle["source_type"], "CI_CD")
            self.assertEqual(bundle["records"][0]["payload"]["commit_sha"], "abc")

    def test_sync_is_incremental_and_tenant_credential_is_external(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(directory)
            config["deploy_job_names"] = []
            sent = []

            def fetch(url, provider, token):
                self.assertEqual(token, "provider-token")
                return {"workflow_runs": [{"id": 42, "name": "Deploy",
                                          "created_at": "2026-11-25T01:00:00Z",
                                          "updated_at": "2026-11-25T01:04:00Z",
                                          "status": "completed", "conclusion": "success"}]}

            def upload(url, path, bundle, token):
                self.assertEqual(token, "connector-token")
                self.assertNotIn("provider-token", json.dumps(bundle))
                sent.append(bundle)
                return {"bundleId": "bundle", "recordCount": len(bundle["records"])}

            with patch.dict(os.environ, {"PATHGUARD_CICD_API_TOKEN": "provider-token"}), \
                 patch.object(cicd, "connector_token", return_value="connector-token"):
                first = cicd.sync_once(config, fetch, upload)
                second = cicd.sync_once(config, fetch, upload)
            self.assertEqual(first["new_or_updated_runs"], 1)
            self.assertEqual(second["new_or_updated_runs"], 0)
            self.assertEqual(len(sent[0]["records"]), 2)
            self.assertEqual(len(sent[1]["records"]), 1)

    def test_gitlab_pipeline_correlates_only_named_deploy_job(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(directory, provider="gitlab_ci")
            config["workflow_names"] = []

            def fetch(url, provider, token):
                self.assertEqual(provider, "gitlab_ci")
                if "/jobs?" in url:
                    return [{"name": "unit-test", "status": "success"},
                            {"name": "deploy-prod", "status": "success",
                             "started_at": "2026-11-25T02:00:00Z",
                             "finished_at": "2026-11-25T02:02:00Z"}]
                return [{"id": 77, "created_at": "2026-11-25T01:59:00Z",
                         "updated_at": "2026-11-25T02:02:00Z", "status": "success",
                         "sha": "def", "ref": "main"}]

            entries, coverage = cicd.collect_gitlab(config, "provider-token", fetch)
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["deployment_jobs"][0]["name"], "deploy-prod")
            self.assertTrue(entries[0]["deployment_job_observed"])
            self.assertFalse(coverage["truncated"])

    def test_config_rejects_embedded_provider_token(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"schema_version": "pathguard.cicd-connector.v1",
                                        "provider": "github_actions", "api_token": "unsafe"}),
                            encoding="utf-8")
            with self.assertRaises(ValueError):
                cicd.load_config(path)

    def test_public_github_can_sync_without_provider_token(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(directory)
            config["workflow_names"] = []
            config["deploy_job_names"] = []
            seen = []

            def fetch(url, provider, token):
                seen.append((provider, token))
                return {"workflow_runs": []}

            with patch.dict(os.environ, {"PATHGUARD_CICD_API_TOKEN": ""}), \
                 patch.object(cicd, "connector_token", return_value="connector-token"):
                result = cicd.sync_once(config, fetch,
                    lambda url, path, bundle, token: {"bundleId": "bundle-1",
                                                     "recordCount": len(bundle["records"])})
            self.assertEqual(result["runs_scanned"], 0)
            self.assertEqual(seen, [("github_actions", "")])


if __name__ == "__main__":
    unittest.main()
