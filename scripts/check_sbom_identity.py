#!/usr/bin/env python3
"""Verify SPDX component identity and checksum attribution.

The WARDEN Alpha SBOM is a static SPDX 2.3 document.  Its Cargo package
checksums come from Cargo.lock, and its shipped eBPF object checksum comes from
the object file itself.  This checker keys both sources by a stable component
identity -- ecosystem, PURL name/version/qualifiers, and source -- never by
package name alone.  That is what distinguishes two versions of the same crate
or the same name in two ecosystems.

No checksum is invented: every authoritative value is read from Cargo.lock or
computed from an explicitly mapped local artifact.  ``--repair`` only replaces
checksums for components whose stable identity resolved to one of those
authoritative sources.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote


CARGO_ECOSYSTEM = "cargo"

BLOCKING_CODES = {
    "INCOMPLETE_IDENTITY",
    "DUPLICATE_COMPONENT_IDENTITY",
    "NO_AUTHORITATIVE_CHECKSUM",
    "CHECKSUM_MISMATCH",
    "MISSING_CHECKSUM",
    "UNVERIFIED_CHECKSUM_ALGORITHM",
    "MALFORMED_CHECKSUM",
    "CONFLICTING_CHECKSUMS",
}


@dataclass(frozen=True, order=True)
class Identity:
    """A stable identity for one component, independent of display name."""

    ecosystem: str
    name: str
    version: str = ""
    qualifiers: tuple[tuple[str, str], ...] = ()
    source: str = ""

    def text(self) -> str:
        qualifiers = "&".join(f"{unquote(k)}={unquote(v)}" for k, v in self.qualifiers)
        base = f"{self.ecosystem}:{self.name}@{self.version}"
        if qualifiers:
            base = f"{base}?{qualifiers}"
        return f"{base}|source={self.source}" if self.source else base

    __str__ = text


@dataclass(frozen=True)
class Authoritative:
    checksums: dict[str, str]
    origin: str


class IdentityError(ValueError):
    pass


def _normalise_algorithm(value: str) -> str:
    algorithm = value.strip().upper()
    # Cargo.lock calls its value a bare checksum; it is SHA-256.
    if algorithm in {"SHA256", "SHA-256"}:
        return "SHA256"
    return algorithm


def parse_purl(value: str) -> tuple[str, str, str, str, tuple[tuple[str, str], ...], str]:
    """Parse the subset of purl syntax WARDEN's SBOM uses.

    Returns (ecosystem, namespace, name, version, qualifiers, subpath).
    """

    if not value.startswith("pkg:"):
        raise IdentityError(f"not a purl: {value!r}")
    body = value[4:]

    subpath = ""
    if "#" in body:
        body, subpath = body.split("#", 1)
        subpath = unquote(subpath)

    query = ""
    if "?" in body:
        body, query = body.split("?", 1)
    qualifiers = tuple(sorted(parse_qsl(query, keep_blank_values=True)))

    ecosystem, separator, remainder = body.partition("/")
    if not separator or not ecosystem:
        raise IdentityError(f"purl is missing ecosystem or name: {value!r}")

    namespace = ""
    if "/" in remainder:
        namespace, remainder = remainder.rsplit("/", 1)
        namespace = unquote(namespace)

    name, at, version = remainder.rpartition("@")
    if not at:
        name, version = remainder, ""
    name = unquote(name)
    version = unquote(version)

    if not name:
        raise IdentityError(f"purl is missing name: {value!r}")
    return unquote(ecosystem), namespace, name, version, qualifiers, subpath


def _purls(package: dict[str, Any]) -> list[str]:
    refs = package.get("externalRefs") or []
    return [
        ref["referenceLocator"]
        for ref in refs
        if isinstance(ref, dict)
        and str(ref.get("referenceType", "")).lower() == "purl"
        and isinstance(ref.get("referenceLocator"), str)
    ]


def _source_from_qualifiers(qualifiers: tuple[tuple[str, str], ...]) -> str:
    for key, value in qualifiers:
        if key in {"repository_url", "source", "download_url"}:
            return value
    return ""


def identity_of(package: dict[str, Any]) -> Identity:
    """Derive a stable identity from PURL, ecosystem, version and source.

    A missing PURL is tolerated only when the package still carries a registry
    download location and version, in which case those fields form the identity.
    Local artifacts without a PURL are keyed by their SPDXID and name; their
    checksums must be supplied through an explicit ``--artifact`` mapping.
    """

    name = str(package.get("name") or "").strip()
    if not name:
        raise IdentityError("SPDX package has no name")
    spdx_id = str(package.get("SPDXID") or "").strip()
    download = str(package.get("downloadLocation") or "").strip()
    version = str(package.get("versionInfo") or "").strip()

    purls = _purls(package)
    if len(purls) > 1:
        raise IdentityError(f"multiple PURLs make identity ambiguous: {purls!r}")
    if purls:
        ecosystem, namespace, purl_name, purl_version, qualifiers, _subpath = parse_purl(purls[0])
        effective_name = f"{namespace}/{purl_name}" if namespace else purl_name
        source = _source_from_qualifiers(qualifiers)
        if not source and download and download.upper() != "NOASSERTION":
            source = download
        return Identity(
            ecosystem=ecosystem.lower(),
            name=effective_name,
            version=purl_version or version,
            qualifiers=qualifiers,
            source=source,
        )

    if download and download.upper() != "NOASSERTION":
        if not version:
            raise IdentityError("registry package has no PURL and no versionInfo")
        if download.startswith("registry+"):
            ecosystem = "cargo" if "crates.io" in download else "registry"
            return Identity(ecosystem, name, version, (), download)
        raise IdentityError(f"no PURL and unsupported source: {download!r}")

    # Local source-adjacent artifact. SPDXID is stable inside the document and
    # the caller must map it to a file with --artifact before it can be trusted.
    return Identity(
        ecosystem="local",
        name=name,
        version=version,
        qualifiers=(),
        source=f"SPDXID={spdx_id}" if spdx_id else "SPDXID=MISSING",
    )


def load_cargo_lock(path: Path) -> dict[Identity, Authoritative]:
    with path.open("rb") as handle:
        document = tomllib.load(handle)

    index: dict[Identity, Authoritative] = {}
    for package in document.get("package", []):
        name = str(package.get("name") or "")
        version = str(package.get("version") or "")
        source = str(package.get("source") or "")
        checksum = package.get("checksum")
        if not name or not version:
            continue
        identity = Identity(CARGO_ECOSYSTEM, name, version, (), source)
        checksums: dict[str, str] = {}
        if isinstance(checksum, str) and checksum:
            checksums["SHA256"] = checksum.strip().lower()
        # Cargo lockfile v3 stores checksums in [metadata]; support it too.
        if not checksums:
            metadata = document.get("metadata") or {}
            for key, value in metadata.items():
                if key.startswith("checksum ") and f" {name} {version}" in key:
                    if isinstance(value, str) and value:
                        checksums["SHA256"] = value.strip().lower()
                    break
        if checksums:
            index[identity] = Authoritative(checksums, f"Cargo.lock:{name}@{version}")
    return index


def load_artifacts(mappings: list[str], sbom_path: Path) -> dict[Identity, Authoritative]:
    with sbom_path.open("r", encoding="utf-8") as handle:
        document = json.load(handle)

    by_id = {
        str(package.get("SPDXID")): package
        for package in document.get("packages", [])
        if package.get("SPDXID")
    }
    index: dict[Identity, Authoritative] = {}
    for mapping in mappings:
        spdx_id, separator, raw_path = mapping.partition("=")
        if not separator or not spdx_id or not raw_path:
            raise IdentityError(f"--artifact must be SPDXID=PATH, got {mapping!r}")
        package = by_id.get(spdx_id)
        if package is None:
            raise IdentityError(f"--artifact names unknown SPDXID {spdx_id!r}")
        artifact_path = Path(raw_path).resolve()
        digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        identity = identity_of(package)
        index[identity] = Authoritative({"SHA256": digest}, f"file:{raw_path}")
    return index


def _issue(code: str, message: str, **fields: Any) -> dict[str, Any]:
    issue: dict[str, Any] = {"code": code, "message": message}
    issue.update(fields)
    return issue


def verify(
    sbom_path: Path,
    lock_path: Path,
    artifacts: dict[Identity, Authoritative],
) -> tuple[dict[str, Any], dict[str, Any]]:
    with sbom_path.open("r", encoding="utf-8") as handle:
        document = json.load(handle)

    authoritative = dict(load_cargo_lock(lock_path))
    for identity, value in artifacts.items():
        authoritative[identity] = value

    issues: list[dict[str, Any]] = []
    seen: dict[Identity, str] = {}
    for package in document.get("packages", []):
        spdx_id = str(package.get("SPDXID") or "<no SPDXID>")
        checksums = package.get("checksums") or []
        try:
            identity = identity_of(package)
        except IdentityError as exc:
            issues.append(
                _issue(
                    "INCOMPLETE_IDENTITY",
                    str(exc),
                    spdx_id=spdx_id,
                    package_name=str(package.get("name") or ""),
                )
            )
            continue

        identity_text = identity.text()
        if identity in seen:
            issues.append(
                _issue(
                    "DUPLICATE_COMPONENT_IDENTITY",
                    "two SPDX packages resolve to the same stable identity",
                    spdx_id=spdx_id,
                    other_spdx_id=seen[identity],
                    identity=identity_text,
                )
            )
        else:
            seen[identity] = spdx_id

        source = authoritative.get(identity)
        if source is None:
            if checksums:
                if identity.ecosystem == "local":
                    # The document subject and other local entries carry
                    # provenance checksums with no single authoritative file.
                    # They are reported, not silently trusted or rejected.
                    issues.append(
                        _issue(
                            "UNVERIFIED_LOCAL_COMPONENT",
                            "local component checksums have no authoritative source mapping; "
                            "map it with --artifact to verify them",
                            spdx_id=spdx_id,
                            identity=identity_text,
                        )
                    )
                else:
                    issues.append(
                        _issue(
                            "NO_AUTHORITATIVE_CHECKSUM",
                            "package carries checksums but no Cargo.lock or mapped artifact source",
                            spdx_id=spdx_id,
                            identity=identity_text,
                        )
                    )
            continue

        reported: dict[str, list[str]] = {}
        for entry in checksums:
            if not isinstance(entry, dict):
                issues.append(
                    _issue(
                        "MALFORMED_CHECKSUM",
                        "checksum entry is not an object",
                        spdx_id=spdx_id,
                        identity=identity_text,
                    )
                )
                continue
            algorithm = _normalise_algorithm(str(entry.get("algorithm") or ""))
            value = str(entry.get("checksumValue") or "").strip().lower()
            reported.setdefault(algorithm, []).append(value)
            expected = source.checksums.get(algorithm)
            if expected is None:
                issues.append(
                    _issue(
                        "UNVERIFIED_CHECKSUM_ALGORITHM",
                        f"no authoritative {algorithm} value for this component",
                        spdx_id=spdx_id,
                        identity=identity_text,
                        algorithm=algorithm,
                    )
                )
            elif value != expected:
                issues.append(
                    _issue(
                        "CHECKSUM_MISMATCH",
                        "checksum does not belong to this stable component identity",
                        spdx_id=spdx_id,
                        identity=identity_text,
                        algorithm=algorithm,
                        expected=expected,
                        observed=value,
                        authoritative_source=source.origin,
                    )
                )

        for algorithm in sorted(source.checksums):
            if algorithm not in reported:
                issues.append(
                    _issue(
                        "MISSING_CHECKSUM",
                        f"authoritative {algorithm} checksum is absent from the SBOM package",
                        spdx_id=spdx_id,
                        identity=identity_text,
                        algorithm=algorithm,
                    )
                )
        for algorithm, values in reported.items():
            if len(set(values)) > 1:
                issues.append(
                    _issue(
                        "CONFLICTING_CHECKSUMS",
                        f"multiple different {algorithm} values for one component",
                        spdx_id=spdx_id,
                        identity=identity_text,
                        algorithm=algorithm,
                    )
                )

    issues.sort(
        key=lambda item: (
            str(item.get("code")),
            str(item.get("spdx_id", "")),
            str(item.get("identity", "")),
            str(item.get("algorithm", "")),
        )
    )
    errors = [item for item in issues if item["code"] in BLOCKING_CODES]
    report = {
        "status": "PASS" if not errors else "FAIL",
        "sbom": str(sbom_path),
        "lock": str(lock_path),
        "authoritative_components": len(authoritative),
        "spdx_packages": len(document.get("packages", [])),
        "issue_count": len(issues),
        "issues": issues,
    }
    return document, report


def repair(
    document: dict[str, Any],
    report: dict[str, Any],
    lock_path: Path,
    artifacts: dict[Identity, Authoritative],
) -> dict[str, Any]:
    blocking = {item["code"] for item in report["issues"]} & (BLOCKING_CODES - {
        "CHECKSUM_MISMATCH",
        "MISSING_CHECKSUM",
    })
    if blocking:
        raise IdentityError(
            "refusing repair with unresolved identity issues: " + ", ".join(sorted(blocking))
        )

    authoritative = dict(load_cargo_lock(lock_path))
    authoritative.update(artifacts)
    changed = 0
    for package in document.get("packages", []):
        identity = identity_of(package)
        source = authoritative.get(identity)
        if source is None:
            continue
        existing = package.get("checksums") or []
        seen_algorithms: set[str] = set()
        new_checksums: list[dict[str, str]] = []
        for entry in existing:
            algorithm = _normalise_algorithm(str(entry.get("algorithm") or ""))
            expected = source.checksums.get(algorithm)
            if expected is None:
                raise IdentityError(
                    f"cannot repair {identity.text()}: no authoritative {algorithm} checksum"
                )
            seen_algorithms.add(algorithm)
            value = str(entry.get("checksumValue") or "").strip().lower()
            if value != expected:
                changed += 1
            new_checksums.append({"algorithm": algorithm, "checksumValue": expected})
        for algorithm in sorted(source.checksums):
            if algorithm not in seen_algorithms:
                new_checksums.append(
                    {"algorithm": algorithm, "checksumValue": source.checksums[algorithm]}
                )
                changed += 1
        if new_checksums:
            package["checksums"] = new_checksums
    document["__repair_count__"] = changed
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbom", type=Path, default=Path("docs/release/warden_alpha1.spdx.json"))
    parser.add_argument("--lock", type=Path, default=Path("Cargo.lock"))
    parser.add_argument(
        "--artifact",
        action="append",
        default=[],
        metavar="SPDXID=PATH",
        help="map an SPDX local artifact to a file whose SHA-256 is authoritative",
    )
    parser.add_argument("--json-report", type=Path)
    parser.add_argument("--repair", action="store_true")
    args = parser.parse_args(argv)

    try:
        artifacts = load_artifacts(args.artifact, args.sbom)
        document, report = verify(args.sbom, args.lock, artifacts)

        if args.repair:
            repaired = repair(document, report, args.lock, artifacts)
            changed = int(repaired.pop("__repair_count__"))
            args.sbom.write_text(
                json.dumps(repaired, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
            after_document, after_report = verify(args.sbom, args.lock, artifacts)
            report = {
                "status": after_report["status"],
                "operation": "repair",
                "checksum_values_changed": changed,
                "sbom": str(args.sbom),
                "lock": str(args.lock),
                "authoritative_components": after_report["authoritative_components"],
                "spdx_packages": after_report["spdx_packages"],
                "issue_count": after_report["issue_count"],
                "issues": after_report["issues"],
            }
            document = after_document

        rendered = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        if args.json_report:
            args.json_report.write_text(rendered, encoding="utf-8")
        print(
            f"SBOM identity verification: {report['status']} "
            f"({report['issue_count']} issue(s), {report['spdx_packages']} packages)"
        )
        for issue in report["issues"]:
            print(
                f"  {issue['code']}: {issue.get('spdx_id', '')} "
                f"{issue.get('identity', '')}: {issue['message']}"
            )
        return 0 if report["status"] == "PASS" else 1
    except (IdentityError, OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        print(f"SBOM identity verification error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
