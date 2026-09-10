import os
import shlex
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SYNC_SCRIPT = REPO_ROOT / ".github" / "scripts" / "sync_upstream.sh"


class SyncUpstreamTest(unittest.TestCase):
    def run_git(self, cwd, *args, check=True):
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            text=True,
            capture_output=True,
        )
        if check and result.returncode != 0:
            self.fail(
                f"git {' '.join(args)} failed with {result.returncode}:\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
        return result

    def commit_file(self, repo, relative_path, content, message):
        path = Path(repo) / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        self.run_git(repo, "add", relative_path)
        self.run_git(repo, "commit", "-m", message)

    def create_repositories(self, root):
        seed = root / "seed"
        seed.mkdir()
        self.run_git(seed, "init", "-b", "master")
        self.run_git(seed, "config", "user.name", "test")
        self.run_git(seed, "config", "user.email", "test@example.com")
        self.commit_file(
            seed,
            "tv/iptv4.m3u",
            "#EXTM3U\n#EXTINF:-1,Base\nhttps://base.example/live.m3u8\n",
            "base source",
        )
        self.commit_file(
            seed,
            ".github/workflows/protected.yml",
            "protected source workflow\n",
            "protected workflow",
        )
        self.commit_file(
            seed,
            "tools/starflow/protected.txt",
            "protected converter\n",
            "protected converter",
        )
        self.commit_file(
            seed,
            ".github/scripts/protected.sh",
            "protected sync script\n",
            "protected sync script",
        )

        origin = root / "origin.git"
        upstream = root / "upstream.git"
        self.run_git(root, "clone", "--bare", str(seed), str(origin))
        self.run_git(root, "clone", "--bare", str(seed), str(upstream))

        checkout = root / "checkout"
        racer = root / "racer"
        upstream_work = root / "upstream-work"
        self.run_git(root, "clone", str(origin), str(checkout))
        self.run_git(root, "clone", str(origin), str(racer))
        self.run_git(root, "clone", str(upstream), str(upstream_work))
        for repo in (checkout, racer, upstream_work):
            self.run_git(repo, "config", "user.name", "test")
            self.run_git(repo, "config", "user.email", "test@example.com")
        return origin, upstream, checkout, racer, upstream_work

    def update_upstream(self, upstream_work):
        self.commit_file(
            upstream_work,
            "tv/iptv4.m3u",
            "#EXTM3U\n#EXTINF:-1,Updated\nhttps://updated.example/live.m3u8\n",
            "upstream source update",
        )
        self.commit_file(
            upstream_work,
            ".github/workflows/upstream-only.yml",
            "must not replace protected files\n",
            "upstream protected change",
        )
        self.commit_file(
            upstream_work,
            ".github/scripts/upstream-only.sh",
            "must not replace protected scripts\n",
            "upstream protected script change",
        )
        self.run_git(upstream_work, "push", "origin", "master")

    def update_upstream_script_only(self, upstream_work):
        self.commit_file(
            upstream_work,
            ".github/scripts/upstream-only.sh",
            "must not replace protected scripts\n",
            "upstream protected script change",
        )
        self.run_git(upstream_work, "push", "origin", "master")

    def update_remote(self, racer):
        self.commit_file(
            racer,
            "remote-state.txt",
            "remote branch advanced\n",
            "remote branch update",
        )

    def run_sync(self, checkout, upstream, output_file):
        environment = os.environ.copy()
        environment.update(
            {
                "UPSTREAM_REPO": "vbskycn/iptv",
                "UPSTREAM_BRANCH": "master",
                "FORCE_REBUILD": "false",
                "TARGET_BRANCH": "master",
                "UPSTREAM_URL": str(upstream),
                "GITHUB_OUTPUT": str(output_file),
            }
        )
        return subprocess.run(
            ["bash", str(SYNC_SCRIPT)],
            cwd=checkout,
            env=environment,
            text=True,
            capture_output=True,
        )

    def assert_published_tree(self, origin, root):
        verified = root / "verified"
        self.run_git(root, "clone", str(origin), str(verified))
        self.assertIn("https://updated.example/live.m3u8", (verified / "tv/iptv4.m3u").read_text(encoding="utf-8"))
        self.assertEqual((verified / "remote-state.txt").read_text(encoding="utf-8"), "remote branch advanced\n")
        self.assertEqual((verified / ".github/workflows/protected.yml").read_text(encoding="utf-8"), "protected source workflow\n")
        self.assertEqual((verified / "tools/starflow/protected.txt").read_text(encoding="utf-8"), "protected converter\n")
        self.assertEqual((verified / ".github/scripts/protected.sh").read_text(encoding="utf-8"), "protected sync script\n")
        self.assertFalse((verified / ".github/workflows/upstream-only.yml").exists())
        self.assertFalse((verified / ".github/scripts/upstream-only.sh").exists())

    def test_sync_rebases_stale_checkout_onto_latest_remote_before_push(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            origin, upstream, checkout, racer, upstream_work = self.create_repositories(root)
            self.update_upstream(upstream_work)
            self.update_remote(racer)
            self.run_git(racer, "push", "origin", "master")

            output_file = root / "github-output.txt"
            result = self.run_sync(checkout, upstream, output_file)

            self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
            self.assertIn("changed=true", output_file.read_text(encoding="utf-8"))
            self.assert_published_tree(origin, root)

    def test_sync_retries_when_remote_moves_during_push(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            origin, upstream, checkout, racer, upstream_work = self.create_repositories(root)
            self.update_upstream(upstream_work)
            self.update_remote(racer)

            marker = root / "race-triggered"
            hook = checkout / ".git/hooks/pre-push"
            hook.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                f"marker={shlex.quote(str(marker))}\n"
                'if [ ! -e "$marker" ]; then\n'
                '  touch "$marker"\n'
                f"  git -C {shlex.quote(str(racer))} push origin master\n"
                "fi\n",
                encoding="utf-8",
            )
            hook.chmod(hook.stat().st_mode | stat.S_IXUSR)

            output_file = root / "github-output.txt"
            result = self.run_sync(checkout, upstream, output_file)

            self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
            self.assertIn("远端分支已更新", result.stdout)
            self.assert_published_tree(origin, root)

    def test_sync_skips_when_only_protected_or_target_only_files_differ(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            origin, upstream, checkout, _racer, upstream_work = self.create_repositories(root)
            self.update_upstream(upstream_work)

            first_output = root / "first-output.txt"
            first_result = self.run_sync(checkout, upstream, first_output)
            self.assertEqual(first_result.returncode, 0, msg=first_result.stdout + first_result.stderr)

            second_output = root / "second-output.txt"
            second_result = self.run_sync(checkout, upstream, second_output)

            self.assertEqual(second_result.returncode, 0, msg=second_result.stdout + second_result.stderr)
            self.assertEqual(second_output.read_text(encoding="utf-8"), "changed=false\n")

    def test_sync_skips_upstream_changes_only_in_protected_scripts(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            _origin, upstream, checkout, _racer, upstream_work = self.create_repositories(root)
            self.update_upstream_script_only(upstream_work)

            output_file = root / "github-output.txt"
            result = self.run_sync(checkout, upstream, output_file)

            self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
            self.assertEqual(output_file.read_text(encoding="utf-8"), "changed=false\n")
            self.assertFalse((checkout / ".git/MERGE_HEAD").exists())

    def test_sync_ignores_a_target_only_commit_after_previous_sync(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            origin, upstream, checkout, _racer, upstream_work = self.create_repositories(root)
            self.update_upstream(upstream_work)

            first_output = root / "first-output.txt"
            first_result = self.run_sync(checkout, upstream, first_output)
            self.assertEqual(first_result.returncode, 0, msg=first_result.stdout + first_result.stderr)

            target_only = root / "target-only"
            self.run_git(root, "clone", str(origin), str(target_only))
            self.run_git(target_only, "config", "user.name", "test")
            self.run_git(target_only, "config", "user.email", "test@example.com")
            self.commit_file(
                target_only,
                "target-only.txt",
                "must not trigger an upstream rebuild\n",
                "target-only update",
            )
            self.run_git(target_only, "push", "origin", "master")

            second_output = root / "second-output.txt"
            second_result = self.run_sync(checkout, upstream, second_output)

            self.assertEqual(second_result.returncode, 0, msg=second_result.stdout + second_result.stderr)
            self.assertEqual(second_output.read_text(encoding="utf-8"), "changed=false\n")
            self.assertFalse((checkout / ".git/MERGE_HEAD").exists())


if __name__ == "__main__":
    unittest.main()
