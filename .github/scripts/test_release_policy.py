import json
import unittest
import urllib.error
from unittest.mock import patch

import release_policy as policy
from check_scan import check

SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64
RUN = {"event": "push", "conclusion": "success", "head_branch": "main",
       "head_repository": {"full_name": "project-jelly/authgate"},
       "path": ".github/workflows/ci.yml", "head_sha": SHA}


class ReleasePolicy(unittest.TestCase):
    def test_only_successful_trusted_main_ci(self):
        self.assertEqual(policy.validate_run(RUN, "project-jelly/authgate", SHA), SHA)
        for field, values in {
            "event": ["pull_request", "workflow_dispatch"],
            "conclusion": ["failure", "cancelled", "skipped", None],
            "head_branch": ["feature"],
            "head_repository": [{"full_name": "attacker/authgate"}],
            "path": [".github/workflows/other.yml"],
            "head_sha": ["main"],
        }.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    policy.validate_run({**RUN, field: value}, "project-jelly/authgate", SHA)

    def test_superseded_ci_skips(self):
        self.assertIsNone(policy.validate_run(RUN, "project-jelly/authgate", "c" * 40))

    def test_stable_version(self):
        self.assertEqual(policy.version_tag("1.2.3\n"), "v1.2.3")
        for value in ["01.2.3", "1.2.3-rc1", "v1.2.3", "1.2.3\n1.2.4"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                policy.version_tag(value)

    def test_version_state_and_incomplete_release_recovery(self):
        tag = {"object": {"sha": SHA}}
        for responses, expected in [([None], True), ([tag, {"id": 1}], False), ([tag, None], True)]:
            with patch.object(policy, "optional_api", side_effect=responses):
                self.assertEqual(policy.unpublished("v1.2.3", SHA), expected)
        with patch.object(policy, "optional_api", side_effect=[tag, None]), self.assertRaises(ValueError):
            policy.unpublished("v1.2.3", "c" * 40)

    def test_api_errors_are_not_absence(self):
        for code in [403, 429, 500]:
            error = urllib.error.HTTPError("url", code, "error", {}, None)
            with patch.object(policy, "api", side_effect=error), self.assertRaises(urllib.error.HTTPError):
                policy.optional_api("git/ref/tags/v1.2.3")

    def test_promotes_scanned_index_without_building(self):
        with patch.object(policy, "existing_digest", return_value=None), patch.object(policy.subprocess, "run") as run, patch.object(
                policy.subprocess, "check_output", return_value=json.dumps({"digest": DIGEST})):
            policy.promote("ghcr.io/project-jelly/authgate", DIGEST, "v1.2.3")
        self.assertEqual(run.call_args.args[0], [
            "docker", "buildx", "imagetools", "create", "--prefer-index=false",
            "--tag", "ghcr.io/project-jelly/authgate:v1.2.3",
            "--tag", "ghcr.io/project-jelly/authgate:latest",
            "ghcr.io/project-jelly/authgate@" + DIGEST])

    def test_promotion_rejects_mutable_or_changed_digest(self):
        with self.assertRaises(ValueError):
            policy.promote("image", "latest", "v1.2.3")
        with patch.object(policy, "existing_digest", return_value=None), patch.object(policy.subprocess, "run"), patch.object(
                policy.subprocess, "check_output", return_value='{"digest":"wrong"}'), self.assertRaises(ValueError):
            policy.promote("image", DIGEST, "v1.2.3")

    def test_registry_absence_is_narrow_and_errors_fail_closed(self):
        image = "ghcr.io/project-jelly/authgate"
        result = policy.subprocess.CompletedProcess([], 1, "", f"ERROR: {image}:v1.2.3: not found\n")
        with patch.object(policy.subprocess, "run", return_value=result):
            self.assertIsNone(policy.existing_digest(image, "v1.2.3"))
        for error in ["credential helper not found", "host not found", "unauthorized", "timeout", "manifest unknown from another image"]:
            result.stderr = error
            with self.subTest(error=error), patch.object(policy.subprocess, "run", return_value=result), self.assertRaises(ValueError):
                policy.existing_digest(image, "v1.2.3")

    def test_existing_version_digest_is_immutable(self):
        with patch.object(policy, "existing_digest", return_value="sha256:" + "c" * 64), patch.object(
                policy.subprocess, "run") as run, self.assertRaises(ValueError):
            policy.promote("image", DIGEST, "v1.2.3")
        run.assert_not_called()

    def test_existing_version_requires_signed_source(self):
        repository = "https://github.com/project-jelly/authgate"
        statement = {"predicateType": policy.PREDICATE_TYPE, "predicate": {
            "source": {"repository": repository, "commit": SHA},
            "ci": {"runId": "123", "runAttempt": "1"},
            "workflow": {"ref": "project-jelly/authgate/.github/workflows/release.yml@refs/heads/main", "commit": SHA},
            "invocation": {"id": repository + "/actions/runs/456/attempts/1", "event": "workflow_run", "runnerEnvironment": "github-hosted"}}}

        policy.verify_existing([{"verificationResult": {"statement": statement}}], repository, SHA)
        statement["predicate_type"] = statement.pop("predicateType")
        policy.verify_existing([{"verificationResult": {"statement": statement}}], repository, SHA)
        statement["predicateType"] = "conflict"
        with self.assertRaises(ValueError):
            policy.verify_existing([{"verificationResult": {"statement": statement}}], repository, SHA)
        del statement["predicateType"]
        for results, revision in [([statement], SHA), ([{"verificationResult": {"statement": statement}}], "c" * 40)]:
            with self.assertRaises(ValueError):
                policy.verify_existing(results, repository, revision)


    def test_existing_evidence_requires_ci_and_workflow_context(self):
        repository = "https://github.com/project-jelly/authgate"
        statement = {"predicate_type": policy.PREDICATE_TYPE, "predicate": {
            "source": {"repository": repository, "commit": SHA}}}
        with self.assertRaises(ValueError):
            policy.verify_existing([{"verificationResult": {"statement": statement}}], repository, SHA)



class ScanPolicy(unittest.TestCase):
    def test_clean_and_low_findings(self):
        check({"SchemaVersion": 2, "Results": []})
        check({"SchemaVersion": 2, "Results": [{"Vulnerabilities": [{"Severity": "LOW"}]}]})

    def test_missing_and_invalid_report_fail(self):
        for report in [None, {}, {"SchemaVersion": 2}, {"SchemaVersion": 2, "Results": "invalid"}]:
            with self.subTest(report=report), self.assertRaises(ValueError):
                check(report)

    def test_malformed_findings_fail(self):
        for result in [None, {"Secrets": "bad"}, {"Secrets": [{}]}, {"Vulnerabilities": [None]}]:
            with self.subTest(result=result), self.assertRaises(ValueError):
                check({"SchemaVersion": 2, "Results": [result]})

    def test_secrets_and_unfixed_vulnerabilities_fail(self):
        for key in ["Secrets", "Vulnerabilities"]:
            for severity in ["HIGH", "CRITICAL"]:
                with self.subTest(key=key, severity=severity), self.assertRaises(ValueError):
                    check({"SchemaVersion": 2, "Results": [{key: [{"Severity": severity}]}]})


if __name__ == "__main__":
    unittest.main()
