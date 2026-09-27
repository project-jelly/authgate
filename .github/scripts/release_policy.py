"""Fail closed on untrusted CI events; publish only an unpublished stable version."""
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request


def api(path):
    request = urllib.request.Request(
        f"https://api.github.com/repos/{os.environ['GITHUB_REPOSITORY']}/{path}",
        headers={"Authorization": f"Bearer {os.environ['GH_TOKEN']}",
                 "Accept": "application/vnd.github+json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def optional_api(path):
    try:
        return api(path)
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        return None


def unpublished(version, revision):
    tag = optional_api(f"git/ref/tags/{version}")
    if tag is None:
        return True
    if optional_api(f"releases/tags/{version}") is not None:
        return False
    if tag["object"]["sha"] != revision:
        raise ValueError("An incomplete release tag belongs to a different revision")
    return True


def validate_run(run, repository, current_main):
    if (run.get("event") != "push" or run.get("conclusion") != "success"
            or run.get("head_branch") != "main"
            or run.get("head_repository", {}).get("full_name") != repository
            or run.get("path") != ".github/workflows/ci.yml"):
        raise ValueError("Release requires this repository's successful main push CI")
    revision = run["head_sha"]
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Invalid CI revision")
    return revision if revision == current_main else None


def version_tag(raw):
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", raw.strip()):
        raise ValueError("VERSION must contain a stable semantic version")
    return "v" + raw.strip()


def existing_digest(image, version):
    result = subprocess.run(
        ["docker", "buildx", "imagetools", "inspect", f"{image}:{version}",
         "--format", "{{json .Manifest}}"], capture_output=True, text=True)
    if result.returncode:
        message = result.stderr.lower()
        if re.search(r"(?m)^error: " + re.escape(f"{image}:{version}") + r": (?:not found|manifest unknown)$", message.strip()):
            return None
        raise ValueError(f"Cannot resolve existing release image: {result.stderr}")
    digest = json.loads(result.stdout)["digest"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("Invalid existing release digest")
    return digest


def verify_existing(results, repository, revision):
    for result in results:
        statement = result.get("verificationResult", {}).get("statement", {})
        definition = statement.get("predicate", {}).get("buildDefinition", {})
        source = definition.get("externalParameters", {}).get("source", {})
        dependencies = definition.get("resolvedDependencies", [])
        if (statement.get("predicateType") == "https://slsa.dev/provenance/v1"
                and source == {"repository": repository, "commit": revision}
                and {"uri": f"git+{repository}@{revision}", "digest": {"gitCommit": revision}} in dependencies):
            return
    raise ValueError("Existing version image has no verified provenance for this source")


def promote(image, digest, version):
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("Promotion requires an immutable image digest")
    if version_tag(version.removeprefix("v")) != version:
        raise ValueError("Invalid release tag")
    existing = existing_digest(image, version)
    if existing is not None and existing != digest:
        raise ValueError("Refusing to replace an existing version image with another digest")
    subprocess.run(["docker", "buildx", "imagetools", "create", "--prefer-index=false",
                    "--tag", f"{image}:{version}", "--tag", f"{image}:latest",
                    f"{image}@{digest}"], check=True)
    for tag in (version, "latest"):
        manifest = json.loads(subprocess.check_output(
            ["docker", "buildx", "imagetools", "inspect", f"{image}:{tag}",
             "--format", "{{json .Manifest}}"], text=True))
        if manifest["digest"] != digest:
            raise ValueError(f"Promotion changed the scanned digest: {tag}")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "existing":
        digest = existing_digest(os.environ["IMAGE"], os.environ["VERSION"])
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.write(f"digest={digest or ''}\n")
        return
    if len(sys.argv) > 1 and sys.argv[1] == "verify-existing":
        with open(sys.argv[2], encoding="utf-8") as stream:
            verify_existing(json.load(stream),
                            f"https://github.com/{os.environ['GITHUB_REPOSITORY']}",
                            os.environ["RELEASE_SHA"])
        return
    if len(sys.argv) > 1 and sys.argv[1] == "finish":
        version, revision = os.environ["VERSION"], os.environ["REVISION"]
        tag = optional_api(f"git/ref/tags/{version}")
        if tag and tag["object"]["sha"] != revision:
            raise ValueError("Release tag changed during publication")
        if not tag:
            subprocess.run(["gh", "api", "--method", "POST",
                            f"repos/{os.environ['GITHUB_REPOSITORY']}/git/refs",
                            "-f", f"ref=refs/tags/{version}", "-f", f"sha={revision}"], check=True)
        if optional_api(f"releases/tags/{version}") is None:
            subprocess.run(["gh", "release", "create", version, "--verify-tag",
                            "--generate-notes", "--title", version], check=True)
        return
    if len(sys.argv) > 1 and sys.argv[1] == "promote":
        promote(os.environ["IMAGE"], os.environ["DIGEST"], os.environ["VERSION"])
        return
    with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as stream:
        event = json.load(stream)
    run = api(f"actions/runs/{event['workflow_run']['id']}")
    revision = validate_run(run, os.environ["GITHUB_REPOSITORY"], api("commits/main")["sha"])
    eligible = False
    version = ""
    if revision:
        raw = subprocess.check_output(["git", "show", f"{revision}:VERSION"], text=True)
        version = version_tag(raw)
        eligible = unpublished(version, revision)
        if not eligible:
            print(f"{version} already published; skipping publication")
    else:
        print("CI belongs to an older main revision; skipping publication")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
        stream.write(f"eligible={str(eligible).lower()}\nrevision={revision or ''}\nversion={version}\n")


if __name__ == "__main__":
    main()
