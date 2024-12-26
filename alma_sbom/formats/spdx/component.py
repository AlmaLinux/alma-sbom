from datetime import datetime
from logging import getLogger
from spdx_tools.spdx.model import (
    Actor,
    ActorType,
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

from alma_sbom.data.models import Package, Build
from alma_sbom.data.attributes.property import Property

_logger = getLogger(__name__)

def set_package_component(document: Document, package: Package, pkgid: int) -> None:
    pkg, rel = component_from_package(package, pkgid)
    document.packages += [pkg]
    document.relationships += [rel]

    for prop in package.get_properties():
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

    ### TODO:
    # need to be considered multiple hashs
    pkg.checksums = [Checksum(ChecksumAlgorithm.SHA256, package.hash)]
    pkg.version = package.package_nevra.get_EVR()
    pkg.external_references += [
        ExternalPackageRef(
            ExternalPackageRefCategory.SECURITY,
            'cpe23Type',
            package.package_nevra.get_cpe23(),
        ),
        ExternalPackageRef(
            ExternalPackageRefCategory.PACKAGE_MANAGER,
            'purl',
            package.get_purl(),
        ),
    ]
    pkg.built_date = datetime.fromtimestamp(package.package_timestamp)
    pkg.files_analyzed = False

    return pkg, rel

def _make_comment_from_property(prop: Property) -> str:
    return f'{prop.name}={prop.value}'

def _make_annotation(prop: Property, spdxid: int) -> Annotation:
    ### TODO:
    # This is test actor. need to be rewrite correct one.
    actor = Actor(
        actor_type=ActorType.TOOL,
        name=f"test annotator",
    )
    return Annotation(
        spdx_id=spdxid,
        annotation_type=AnnotationType.OTHER,
        annotator=actor,
        annotation_date=datetime.now(),
        annotation_comment=_make_comment_from_property(prop),
    )

