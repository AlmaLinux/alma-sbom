from datetime import datetime
from logging import getLogger
from spdx_tools.spdx.model import (
    Annotation,
    AnnotationType,
    Checksum,
    ChecksumAlgorithm,
    Document,
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package as PackageComponent,
    Relationship,
    RelationshipType,
)
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion

from alma_sbom import constants
from alma_sbom._version import __version__
from alma_sbom.type import Hash, Algorithms
from alma_sbom.data import Package, Build, Property

from . import constants as spdx_consts

_logger = getLogger(__name__)

def _make_hash(hash: Hash) -> Checksum:
    ALGO_MAP = {
        "SHA-256": ChecksumAlgorithm.SHA256,
    }
    algo = hash.algorithm.value

    if algo not in ALGO_MAP:
        raise ValueError(f"Algorithm {algo} is not supported in SPDX")

    return Checksum(ALGO_MAP[algo], hash.value)

def set_package_component(document: Document, package: Package, pkgid: int) -> None:
    pkg, rel = component_from_package(package, pkgid)
    document.packages += [pkg]
    document.relationships += [rel]

    for prop in package.get_properties():
        if prop is not None and prop.value is not None:
            note = _make_annotation(prop, pkgid)
            document.annotations += [note]

def set_build_component(document: Document, build: Build, pkgid: int) -> None:
    for prop in build.get_properties():
        if prop is not None and prop.value is not None:
            note = _make_annotation(prop, pkgid)
            document.annotations += [note]

def component_from_package(package: Package, pkgid: int) -> tuple[PackageComponent, Relationship]:
    pkg = PackageComponent(
        spdx_id=pkgid,
        name=package.package_nevra.name,
        download_location=SpdxNoAssertion(),
    )
    rel = Relationship(
        spdx_element_id="SPDXRef-DOCUMENT",
        relationship_type=RelationshipType.DESCRIBES,
        related_spdx_element_id=pkgid,
    )

    pkg.checksums = [_make_hash(h) for h in package.hashs]
    pkg.version = package.package_nevra.get_EVR()
    pkg.supplier = spdx_consts.AlmaActor
    pkg.external_references += [
        ExternalPackageRef(
            ExternalPackageRefCategory.SECURITY,
            'cpe23Type',
            package.get_cpe23(),
        ),
        ExternalPackageRef(
            ExternalPackageRefCategory.PACKAGE_MANAGER,
            'purl',
            package.get_purl(),
        ),
    ]
    pkg.built_date = datetime.fromtimestamp(package.package_timestamp) if package.package_timestamp else None
    pkg.files_analyzed = False

    if package.licenses:
        pkg.license_concluded = SpdxNoAssertion()
        if package.licenses.expression:
            pkg.license_comment = package.licenses.expression

    ### NOTE
    ##  license_info_frpm_files needs file_analyzed = True.
    ##  Now pending implementation as it is unclear if this value can be set.
    ##  See https://spdx.github.io/spdx-spec/v2.3/package-information/#714-all-licenses-information-from-files-field
    #     if 'ids' in component['licenses'] and component['licenses']['ids']:
    #         l = []
    #         for lid in component['licenses']['ids']:
    #             try:
    #                 le = Licensing().parse(lid, validate=False)
    #                 l.append(le)
    #             except ExpressionError as err:
    #                 pass
    #         pkg.license_info_from_files = l

    if package.summary:
        pkg.summary = package.summary
    if package.description:
        pkg.description = package.description

    return pkg, rel

def _make_comment_from_property(prop: Property) -> str:
    return f'{prop.name}={prop.value}'

def _make_annotation(prop: Property, spdxid: int) -> Annotation:
    return Annotation(
        spdx_id=spdxid,
        annotation_type=AnnotationType.OTHER,
        annotator=spdx_consts.AlmaSbomActor,
        annotation_date=datetime.now(),
        annotation_comment=_make_comment_from_property(prop),
    )

