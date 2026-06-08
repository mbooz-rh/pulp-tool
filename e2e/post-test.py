#!/usr/bin/env python3
"""Clean up test repositories and distributions in Pulp after e2e tests."""

import argparse
import json
import subprocess
import sys
from pathlib import Path

RPM_REPOS = {
    "aarch64": ["test.3-1.0.0-1.aarch64.rpm"],
    "noarch": ["test.3-1.0.0-1.noarch.rpm"],
    "x86_64": ["test.3-1.0.0-1.x86_64.rpm"],
    "test-build-files/rpms": ["test.4-1.0.0-1.x86_64.rpm"],
    "test-build-123/rpms": ["test.0-1.0.0-1.aarch64.rpm", "test.0-1.0.0-1.noarch.rpm", "test.0-1.0.0-1.x86_64.rpm"],
    "test-build-456/rpms": ["test.1-1.0.0-1.aarch64.rpm", "test.1-1.0.0-1.noarch.rpm", "test.1-1.0.0-1.x86_64.rpm"],
    "test-build-456/rpms-signed": [],
    "test-repo": ["duck-0.6-1.noarch.rpm"],
    "test-repo-json": ["duck-0.8-1.noarch.rpm", "giraffe-0.67-2.noarch.rpm"],
    "test-upload-results/rpms": ["test.2-1.0.0-1.noarch.rpm"],
}

FILE_REPOS = {
    "test-build-files/artifacts": ["pulp_results.json", "test.md"],
    "test-build-files/logs": ["x86_64/build.log"],
    "test-build-files/sbom": ["sbom.json"],
    "test-build-123/artifacts": ["pulp_results.json"],
    "test-build-456/sbom": ["sbom.json"],
    "test-build-789/artifacts": ["pulp_results.json"],
    "test-upload-results/artifacts": ["pulp_results.json"],
}


def verify_content(config_path: Path, repo_type: str, name: str, expected_content: list[str]) -> bool:
    """Verify that a repository contains expected content.

    Args:
        config_path: Path to Pulp CLI config file
        repo_type: Type of repository ("rpm" or "file")
        name: Name of the repository to verify
        expected_content: List of location_href (rpm) or relative_path (file) values

    Returns:
        True if all expected content is present, False otherwise
    """
    cmd = [
        "pulp",
        "--config",
        str(config_path),
        repo_type,
        "repository",
        "content",
        "list",
        "--repository",
        name,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(
            f"Error: Failed to list content for {repo_type} repository '{name}': {result.stderr}",
            file=sys.stderr,
        )
        return False

    try:
        content_list = json.loads(result.stdout)

        if not isinstance(content_list, list):
            print(
                f"Error: Unexpected response format for repository '{name}'",
                file=sys.stderr,
            )
            return False

        content_key = "relative_path" if repo_type == "file" else "location_href"

        content_values = {
            item.get(content_key) for item in content_list if isinstance(item, dict) and content_key in item
        }

        expected_set = set(expected_content)
        missing = [value for value in expected_content if value not in content_values]
        extra = [value for value in content_values if value not in expected_set]

        if missing:
            print(
                f"Error: Repository '{name}' missing expected content: {missing}",
                file=sys.stderr,
            )
            print(
                f"Found {content_key} values: {content_values}",
                file=sys.stderr,
            )
            return False

        if extra:
            print(
                f"Error: Repository '{name}' contains unexpected content: {extra}",
                file=sys.stderr,
            )
            print(
                f"Expected {content_key} values: {expected_set}",
                file=sys.stderr,
            )
            return False

        print(f"✓ Repository '{name}' contains all expected content (no extra content)")
        return True

    except json.JSONDecodeError as e:
        print(
            f"Error: Failed to parse JSON response for repository '{name}': {e}",
            file=sys.stderr,
        )
        return False


def verify_repos(config_path: Path) -> int:
    """Verify all test repositories contain expected content.

    Args:
        config_path: Path to Pulp CLI config file

    Returns:
        Exit code (0 for success, 1 if any failures occurred)
    """
    print("=== Verifying repository content ===\n")
    failures = 0

    for repo_name, expected_content in RPM_REPOS.items():
        if not verify_content(config_path, "rpm", repo_name, expected_content):
            failures += 1

    for repo_name, expected_content in FILE_REPOS.items():
        if not verify_content(config_path, "file", repo_name, expected_content):
            failures += 1

    total_repos = len(RPM_REPOS) + len(FILE_REPOS)
    verified = total_repos - failures

    print(f"\n=== Verification complete: {verified}/{total_repos} repositories verified ===")

    return 1 if failures > 0 else 0


def destroy_resource(config_path: Path, repo_type: str, resource: str, name: str, dry_run: bool = False) -> bool:
    """Destroy a Pulp repository or distribution.

    Args:
        config_path: Path to Pulp CLI config file
        repo_type: Type of repository ("rpm" or "file")
        resource: Resource type ("repository" or "distribution")
        name: Name of the resource to destroy
        dry_run: If True, only print what would be destroyed without executing

    Returns:
        True if successful (or if dry-run), False otherwise
    """
    cmd = [
        "pulp",
        "--config",
        str(config_path),
        repo_type,
        resource,
        "destroy",
        "--name",
        name,
    ]

    if dry_run:
        print(f"[DRY RUN] Would destroy {repo_type} {resource}: {name}")
        return True

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(
            f"Warning: Failed to destroy {repo_type} {resource} '{name}': {result.stderr}",
            file=sys.stderr,
        )
        return False
    return True


def cleanup_repos(config_path: Path, dry_run: bool = False) -> int:
    """Clean up all test repositories and distributions.

    Args:
        config_path: Path to Pulp CLI config file
        dry_run: If True, only show what would be destroyed without executing

    Returns:
        Exit code (0 for success, 1 if any failures occurred)
    """
    if dry_run:
        print("=== DRY RUN MODE: No resources will be destroyed ===\n")
    else:
        print("=== Cleaning up test resources ===\n")

    total_resources = (len(RPM_REPOS) + len(FILE_REPOS)) * 2  # repos + distributions
    current = 0
    failures = 0
    if not dry_run:
        for repo in RPM_REPOS.keys():
            current += 1
            print(f"[{current}/{total_resources}] Destroying rpm repository: {repo}")
            if not destroy_resource(config_path, "rpm", "repository", repo, dry_run):
                failures += 1

            current += 1
            print(f"[{current}/{total_resources}] Destroying rpm distribution: {repo}")
            if not destroy_resource(config_path, "rpm", "distribution", repo, dry_run):
                failures += 1

        for repo in FILE_REPOS.keys():
            current += 1
            print(f"[{current}/{total_resources}] Destroying file repository: {repo}")
            if not destroy_resource(config_path, "file", "repository", repo, dry_run):
                failures += 1

            current += 1

            print(f"[{current}/{total_resources}] Destroying file distribution: {repo}")
            if not destroy_resource(config_path, "file", "distribution", repo, dry_run):
                failures += 1

        # Cleanup abandoned packages and files
        print("Cleaning up orphaned content.")
        cmd = ["pulp", "--config", str(config_path), "orphan", "cleanup"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(
                f"Warning: Failed to cleanup orphaned content: {result.stderr}",
                file=sys.stderr,
            )
            failures += 1

    if dry_run:
        print(f"\n=== DRY RUN COMPLETE: {total_resources} resources would be destroyed ===")
    else:
        success = total_resources - failures
        print(f"\n=== Cleanup complete: {success}/{total_resources} resources destroyed successfully ===")

    return 1 if failures > 0 else 0


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Clean up test repositories in Pulp",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--config",
        type=Path,
        required=True,
        help="Path to Pulp CLI config file (cli.toml)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be destroyed without actually destroying anything",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Destroy repositories even if verification fails",
    )
    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()

    if not args.config.exists():
        print(f"Error: Config file not found: {args.config}", file=sys.stderr)
        return 1

    config_path = args.config.resolve()

    verify_result = verify_repos(config_path)
    if verify_result != 0 and not args.force:
        print("\nVerification failed. Skipping cleanup. Use --force to cleanup anyway.", file=sys.stderr)
        return verify_result

    if verify_result != 0 and args.force:
        print("\nVerification failed, but --force specified. Proceeding with cleanup...\n")

    return cleanup_repos(config_path, dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
