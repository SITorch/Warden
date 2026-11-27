#!/usr/bin/env python3
"""Regression tests for stable SBOM component identity and checksum attribution."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_sbom_identity as csi  # noqa: E402


CRATES = "registry+https://github.com/rust-lang/crates.io-index"


def lock_text(packages: list[dict[str, str]]) -> str:
    lines = ["# test lock\n", "version = 4\n"]
    for package in packages:
        lines.append("[[package]]\n")
        lines.append(f'name = "{package["name"]}"\n')
        lines.append(f'version = "{package["version"]}"\n')
        lines.append(f'source = "{package.get("source", CRATES)}"\n')
        lines.append(f'checksum = "{package["checksum"]}"\n')
    return "".join(lines)


def spdx_text(packages: list[dict]) -> str:
    return json.dumps(
        {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "name": "test-sbom",
            "packages": packages,
            "relationships": [],
        },
        indent=2,
    )


def crate(
    spdx_id: str,
    name: str,
    version: str,
    checksum: str | None,
    *,
    purl: str | None = None,
    download: str = CRATES,
    algorithms: tuple[str, ...] = ("SHA256",),
) -> dict:
    package = {
        "SPDXID": spdx_id,
        "name": name,
        "versionInfo": version,
        "downloadLocation": download,
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl or f"pkg:cargo/{name}@{version}",
            }
        ],
    }
    if checksum is not None:
        package["checksums"] = [
            {"algorithm": algorithm, "checksumValue": checksum} for algorithm in algorithms
        ]
    return package


def codes(report: dict) -> set[str]:
    return {issue["code"] for issue in report["issues"]}


class SbomIdentityTests(unittest.TestCase):
    def verify_in_temp(
        self,
        packages: list[dict],
        locked: list[dict[str, str]],
        artifacts: list[str] | None = None,
    ) -> tuple[dict, dict, Path, Path]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        sbom_path = root / "sbom.spdx.json"
        lock_path = root / "Cargo.lock"
        sbom_path.write_text(spdx_text(packages), encoding="utf-8")
        lock_path.write_text(lock_text(locked), encoding="utf-8")
        document, report = csi.verify(sbom_path, lock_path, csi.load_artifacts(artifacts or [], sbom_path))
        return document, report, sbom_path, lock_path

    def test_same_package_name_different_versions_are_distinct(self) -> None:
        old = "1" * 64
        new = "2" * 64
        locked = [
            {"name": "bitflags", "version": "1.3.2", "checksum": old},
            {"name": "bitflags", "version": "2.13.2", "checksum": new},
        ]
        packages = [
            crate("SPDXRef-b1", "bitflags", "1.3.2", old),
            crate("SPDXRef-b2", "bitflags", "2.13.2", new),
        ]
        _document, report, _sbom, _lock = self.verify_in_temp(packages, locked)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["issue_count"], 0)

        swapped = [
            crate("SPDXRef-b1", "bitflags", "1.3.2", new),
            crate("SPDXRef-b2", "bitflags", "2.13.2", old),
        ]
        _document, report, _sbom, _lock = self.verify_in_temp(swapped, locked)
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(len(report["issues"]), 2)
        identities = [issue["identity"] for issue in report["issues"]]
        self.assertTrue(any("cargo:bitflags@1.3.2" in value for value in identities))
        self.assertTrue(any("cargo:bitflags@2.13.2" in value for value in identities))

    def test_same_name_and_version_in_different_ecosystems(self) -> None:
        checksum = "3" * 64
        locked = [{"name": "foo", "version": "1.0.0", "checksum": checksum}]
        packages = [
            crate("SPDXRef-cargo", "foo", "1.0.0", checksum),
            crate(
                "SPDXRef-npm",
                "foo",
                "1.0.0",
                "4" * 64,
                purl="pkg:npm/foo@1.0.0",
                download="NOASSERTION",
            ),
        ]
        _document, report, _sbom, _lock = self.verify_in_temp(packages, locked)
        self.assertEqual(report["status"], "FAIL")
        npm_issues = [issue for issue in report["issues"] if issue.get("spdx_id") == "SPDXRef-npm"]
        self.assertEqual(len(npm_issues), 1)
        self.assertEqual(npm_issues[0]["code"], "NO_AUTHORITATIVE_CHECKSUM")
        self.assertIn("npm:foo@1.0.0", npm_issues[0]["identity"])

    def test_different_purls_with_qualifiers_are_distinct(self) -> None:
        checksum = "5" * 64
        locked = [{"name": "foo", "version": "1.0.0", "checksum": checksum}]
        packages = [
            crate("SPDXRef-default", "foo", "1.0.0", checksum),
            crate(
                "SPDXRef-fork",
                "foo",
                "1.0.0",
                "6" * 64,
                purl="pkg:cargo/foo@1.0.0?repository_url=https%3A%2F%2Fexample.invalid%2Ffork",
            ),
        ]
        _document, report, _sbom, _lock = self.verify_in_temp(packages, locked)
        self.assertEqual(report["status"], "FAIL")
        fork_issues = [issue for issue in report["issues"] if issue.get("spdx_id") == "SPDXRef-fork"]
        self.assertEqual(len(fork_issues), 1)
        self.assertEqual(fork_issues[0]["code"], "NO_AUTHORITATIVE_CHECKSUM")
        self.assertIn("repository_url=https://example.invalid/fork", fork_issues[0]["identity"])

    def test_duplicate_components_are_reported(self) -> None:
        checksum = "7" * 64
        locked = [{"name": "foo", "version": "1.0.0", "checksum": checksum}]
        packages = [
            crate("SPDXRef-one", "foo", "1.0.0", checksum),
            crate("SPDXRef-two", "foo", "1.0.0", checksum),
        ]
        _document, report, _sbom, _lock = self.verify_in_temp(packages, locked)
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("DUPLICATE_COMPONENT_IDENTITY", codes(report))

    def test_missing_versions_and_purls_are_not_silently_name_keyed(self) -> None:
        checksum = "8" * 64
        locked = [{"name": "foo", "version": "1.0.0", "checksum": checksum}]
        no_version = {
            "SPDXID": "SPDXRef-no-version",
            "name": "foo",
            "downloadLocation": "NOASSERTION",
            "checksums": [{"algorithm": "SHA256", "checksumValue": checksum}],
        }
        registry_no_version = crate("SPDXRef-registry", "foo", "", checksum)
        registry_no_version["externalRefs"] = []
        _document, report, _sbom, _lock = self.verify_in_temp(
            [no_version, registry_no_version], locked
        )
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(len([i for i in report["issues"] if i["code"] == "INCOMPLETE_IDENTITY"]), 1)
        self.assertEqual(
            len([i for i in report["issues"] if i["code"] == "UNVERIFIED_LOCAL_COMPONENT"]), 1
        )

    def test_missing_checksum_is_reported(self) -> None:
        checksum = "9" * 64
        locked = [{"name": "foo", "version": "1.0.0", "checksum": checksum}]
        _document, report, _sbom, _lock = self.verify_in_temp(
            [crate("SPDXRef-foo", "foo", "1.0.0", None)], locked
        )
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("MISSING_CHECKSUM", codes(report))

    def test_multiple_algorithms_are_not_flattened(self) -> None:
        checksum = "a" * 64
        locked = [{"name": "foo", "version": "1.0.0", "checksum": checksum}]
        package = crate(
            "SPDXRef-foo",
            "foo",
            "1.0.0",
            checksum,
            algorithms=("SHA256", "SHA512"),
        )
        package["checksums"][1]["checksumValue"] = "b" * 128
        document, report, sbom_path, lock_path = self.verify_in_temp([package], locked)
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("UNVERIFIED_CHECKSUM_ALGORITHM", codes(report))
        with self.assertRaises(csi.IdentityError):
            csi.repair(document, report, lock_path, {})

    def test_correct_association_repairs_all_original_mismatch_cases(self) -> None:
        original = [
            ("bitflags", "1.3.2", "b" * 64),
            ("bitflags", "2.13.2", "c" * 64),
            ("hashbrown", "0.15.5", "d" * 64),
            ("hashbrown", "0.17.1", "e" * 64),
            ("syn", "2.0.119", "f" * 64),
            ("syn", "3.0.6", "a" * 64),
            ("thiserror", "1.0.69", "9" * 64),
            ("thiserror", "2.0.21", "8" * 64),
            ("thiserror-impl", "1.0.69", "7" * 64),
            ("thiserror-impl", "2.0.21", "6" * 64),
        ]
        locked = [
            {"name": name, "version": version, "checksum": checksum}
            for name, version, checksum in original
        ]
        # Five older duplicates carry the newer version's checksum.
        wrong = {
            ("bitflags", "1.3.2"): "c" * 64,
            ("hashbrown", "0.15.5"): "e" * 64,
            ("syn", "2.0.119"): "a" * 64,
            ("thiserror", "1.0.69"): "8" * 64,
            ("thiserror-impl", "1.0.69"): "6" * 64,
        }
        packages = [
            crate(
                f"SPDXRef-{index}",
                name,
                version,
                wrong.get((name, version), checksum),
            )
            for index, (name, version, checksum) in enumerate(original)
        ]
        document, report, sbom_path, lock_path = self.verify_in_temp(packages, locked)
        self.assertEqual(report["status"], "FAIL")
        mismatches = [i for i in report["issues"] if i["code"] == "CHECKSUM_MISMATCH"]
        self.assertEqual(len(mismatches), 5)

        repaired = csi.repair(document, report, lock_path, {})
        self.assertEqual(int(repaired.pop("__repair_count__")), 5)
        sbom_path.write_text(json.dumps(repaired, indent=2), encoding="utf-8")
        _document, after, _sbom, _lock = self.verify_in_temp(packages, locked)
        # Reuse the repaired document to prove the exact repaired bytes verify.
        sbom_path.write_text(json.dumps(repaired, indent=2), encoding="utf-8")
        after_document, after_report = csi.verify(sbom_path, lock_path, {})
        self.assertEqual(after_report["status"], "PASS")
        self.assertEqual(after_document["spdxVersion"], "SPDX-2.3")

    def test_deterministic_output_with_reordered_inputs(self) -> None:
        checksum = "d" * 64
        locked = [
            {"name": "foo", "version": "1.0.0", "checksum": checksum},
            {"name": "bar", "version": "2.0.0", "checksum": "e" * 64},
        ]
        first = [
            crate("SPDXRef-foo", "foo", "1.0.0", checksum),
            crate("SPDXRef-bar", "bar", "2.0.0", "e" * 64),
        ]
        second = list(reversed(first))
        _document, report_one, sbom_path, lock_path = self.verify_in_temp(first, locked)
        rendered_one = json.dumps(report_one, sort_keys=True)
        sbom_path.write_text(spdx_text(second), encoding="utf-8")
        _document, report_two, _sbom, _lock = self.verify_in_temp(second, locked, artifacts=[])
        report_two["sbom"] = report_one["sbom"]
        report_two["lock"] = report_one["lock"]
        self.assertEqual(json.dumps(report_two, sort_keys=True), rendered_one)

    def test_local_artifact_checksum_is_verified_from_explicit_mapping(self) -> None:
        payload = b"exact shipped object bytes\n"
        expected = hashlib.sha256(payload).hexdigest()
        local = {
            "SPDXID": "SPDXRef-object",
            "name": "warden.bpf.o",
            "downloadLocation": "NOASSERTION",
            "checksums": [{"algorithm": "SHA256", "checksumValue": expected}],
        }
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        artifact = root / "warden.bpf.o"
        artifact.write_bytes(payload)
        sbom_path = root / "sbom.spdx.json"
        lock_path = root / "Cargo.lock"
        sbom_path.write_text(spdx_text([local]), encoding="utf-8")
        lock_path.write_text(lock_text([]), encoding="utf-8")
        _document, report = csi.verify(
            sbom_path,
            lock_path,
            csi.load_artifacts([f"SPDXRef-object={artifact}"], sbom_path),
        )
        self.assertEqual(report["status"], "PASS")

        local["checksums"][0]["checksumValue"] = "f" * 64
        sbom_path.write_text(spdx_text([local]), encoding="utf-8")
        _document, report = csi.verify(
            sbom_path,
            lock_path,
            csi.load_artifacts([f"SPDXRef-object={artifact}"], sbom_path),
        )
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("CHECKSUM_MISMATCH", codes(report))


if __name__ == "__main__":
    unittest.main()
