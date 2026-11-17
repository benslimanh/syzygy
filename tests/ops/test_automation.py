"""Offline CI/CD contract tests. No real cluster/registry or signing key used."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
IMAGE = 'ghcr.io/benslimanh/syzygy@sha256:' + 'a' * 64
spec = importlib.util.spec_from_file_location('tools', ROOT / 'scripts/ci/tools.py')
tools = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tools)


class ToolIntegrity(unittest.TestCase):
    def test_checksum_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            tools.verified_binary(b'tampered', {'sha256': '0' * 64, 'member': ''})

    def test_valid_binary(self):
        content = b'example executable'
        self.assertEqual(tools.verified_binary(content, {
            'sha256': hashlib.sha256(content).hexdigest(), 'member': ''}), content)

    def test_archive_extracts_only_selected_member(self):
        blob = io.BytesIO()
        with tarfile.open(fileobj=blob, mode='w:gz') as archive:
            for name, data in [('../../escape', b'bad'), ('tool', b'good')]:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        data = blob.getvalue()
        self.assertEqual(tools.verified_binary(data, {
            'sha256': hashlib.sha256(data).hexdigest(), 'member': 'tool'}), b'good')

    def test_symlink_member_rejected(self):
        blob = io.BytesIO()
        with tarfile.open(fileobj=blob, mode='w:gz') as archive:
            member = tarfile.TarInfo('tool')
            member.type = tarfile.SYMTYPE
            member.linkname = '/etc/passwd'
            archive.addfile(member)
        data = blob.getvalue()
        with self.assertRaises(ValueError):
            tools.verified_binary(data, {
                'sha256': hashlib.sha256(data).hexdigest(), 'member': 'tool'})

    def test_all_tools_have_immutable_checksums(self):
        lock = json.loads((ROOT / 'scripts/ci/tools.lock.json').read_text())
        for spec in lock.values():
            self.assertRegex(spec['sha256'], r'^[a-f0-9]{64}$')
            self.assertTrue(spec['url'].startswith('https://'))
            self.assertNotIn('/latest/', spec['url'])


MOCK = r'''#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['MOCK_LOG'], 'a') as log:
    log.write(json.dumps([name] + args) + '\n')
if name == 'cosign':
    raise SystemExit(int(os.environ.get('VERIFY_FAIL', 0)))
if name == 'helm':
    if args[0] == 'list':
        if os.environ.get('LIST_FAIL'): raise SystemExit(1)
        print('[]' if os.environ.get('FIRST_INSTALL') else '[{"name":"syzygy"}]')
    elif args[0] == 'history':
        print('[{"revision":4,"status":"deployed"},{"revision":3,"status":"superseded"}]')
    elif args[0] == 'upgrade':
        raise SystemExit(int(os.environ.get('UPGRADE_FAIL', 0)))
    elif args[0] == 'rollback':
        raise SystemExit(int(os.environ.get('ROLLBACK_FAIL', 0)))
elif name == 'kubectl':
    if 'port-forward' in args: time.sleep(60)
    elif os.environ.get('NAMESPACE_FAIL'): raise SystemExit(1)
elif name == 'curl':
    if not os.environ.get('SMOKE_FAIL'): print('ok')
    else: raise SystemExit(22)
'''


class DeploymentContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        for tool in ['helm', 'kubectl', 'cosign', 'curl']:
            file = self.base / tool
            file.write_text(MOCK)
            file.chmod(0o755)
        # Avoid a fifteen-second wait in deliberate failure tests.
        file = self.base / 'sleep'
        file.write_text('#!/bin/sh\nexit 0\n')
        file.chmod(0o755)
        self.log = self.base / 'calls.jsonl'

    def run_deploy(self, image=IMAGE, **flags):
        env = dict(os.environ, PATH=str(self.base) + ':' + os.environ['PATH'],
                   MOCK_LOG=str(self.log),
                   COSIGN_CERTIFICATE_IDENTITY='https://github.com/benslimanh/syzygy/.github/workflows/release.yml@refs/tags/v0.1.0')
        env.update(flags)
        result = subprocess.run(['bash', str(ROOT / 'scripts/ops/deploy.sh'), image],
                                cwd=ROOT, env=env, capture_output=True, text=True, timeout=15)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        return result, calls

    def test_mutable_tag_rejected_before_cluster_access(self):
        result, calls = self.run_deploy('ghcr.io/benslimanh/syzygy:latest')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])

    def test_signature_failure_prevents_mutation(self):
        result, calls = self.run_deploy(VERIFY_FAIL='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([x[0] for x in calls], ['cosign'])

    def test_namespace_error_prevents_mutation(self):
        result, calls = self.run_deploy(NAMESPACE_FAIL='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(x[:2] == ['helm', 'upgrade'] for x in calls))

    def test_api_error_is_not_treated_as_new_install(self):
        result, calls = self.run_deploy(LIST_FAIL='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(x[:2] == ['helm', 'upgrade'] for x in calls))

    def test_upgrade_uses_atomic_readiness_rollback(self):
        result, calls = self.run_deploy(UPGRADE_FAIL='1')
        self.assertNotEqual(result.returncode, 0)
        upgrade = next(x for x in calls if x[:2] == ['helm', 'upgrade'])
        self.assertIn('--atomic', upgrade)
        self.assertIn('--wait', upgrade)
        self.assertIn('image.digest=sha256:' + 'a' * 64, upgrade)
        self.assertFalse(any(x[:2] == ['helm', 'rollback'] for x in calls))

    def test_failed_smoke_rolls_back_previous_revision(self):
        result, calls = self.run_deploy(SMOKE_FAIL='1')
        self.assertNotEqual(result.returncode, 0)
        rollback = next(x for x in calls if x[:2] == ['helm', 'rollback'])
        self.assertEqual(rollback[2:4], ['syzygy', '4'])

    def test_failed_first_install_is_uninstalled(self):
        result, calls = self.run_deploy(SMOKE_FAIL='1', FIRST_INSTALL='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(any(x[:2] == ['helm', 'uninstall'] for x in calls))

    def test_failed_rollback_is_not_hidden(self):
        result, calls = self.run_deploy(SMOKE_FAIL='1', ROLLBACK_FAIL='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(any(x[:2] == ['helm', 'rollback'] for x in calls))

    def test_healthy_deployment_does_not_rollback(self):
        result, calls = self.run_deploy()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(x[:2] in (['helm', 'rollback'], ['helm', 'uninstall']) for x in calls))
        self.assertIn('https://token.actions.githubusercontent.com', calls[0])


@unittest.skipUnless(shutil.which('helm'), 'helm not installed')
class ChartContract(unittest.TestCase):
    def render(self, *args):
        return subprocess.check_output(['helm', 'template', 'test', str(ROOT / 'helm/syzygy'), *args], text=True)

    def test_local_mode_needs_no_tls_secret(self):
        rendered = self.render('-f', str(ROOT / 'ops/helm/local-values.yaml'))
        self.assertNotIn('secretName:', rendered)
        self.assertNotIn('targetPort: https', rendered)
        self.assertIn('"-T","0"', rendered)

    def test_digest_takes_precedence_over_tag(self):
        rendered = self.render('--set-string', 'image.digest=sha256:' + 'a' * 64,
                               '--set-string', 'image.tag=ignored')
        self.assertIn('@sha256:' + 'a' * 64, rendered)
        self.assertNotIn(':ignored', rendered)

    def test_tls_secret_uses_kubernetes_key_names(self):
        rendered = self.render()
        self.assertIn('/certs/tls.crt', rendered)
        self.assertIn('/certs/tls.key', rendered)


class ReleaseValidation(unittest.TestCase):
    def test_invalid_tags_rejected(self):
        for tag in ['latest', 'v1.2', 'v1.2.3;echo bad', '../v1.2.3']:
            result = subprocess.run(['bash', str(ROOT / 'scripts/release/package.sh'), tag],
                                    cwd=ROOT, capture_output=True)
            self.assertNotEqual(result.returncode, 0)

    def test_version_mismatch_rejected(self):
        result = subprocess.run(['bash', str(ROOT / 'scripts/release/package.sh'), 'v999.0.0'],
                                cwd=ROOT, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'Tag does not match', result.stderr)


if __name__ == '__main__':
    unittest.main()
