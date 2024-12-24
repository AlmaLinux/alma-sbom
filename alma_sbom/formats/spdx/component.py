from datetime import datetime
from spdx_tools.spdx.model import (
    Checksum,
    ChecksumAlgorithm,
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package as PackageComponent,
    Relationship,
    RelationshipType,
)
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion

from alma_sbom.data.models import Package, Build

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
