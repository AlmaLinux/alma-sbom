import os
import pytest

from alma_sbom.type import Hash, PackageNevra, Licenses, Algorithms
from alma_sbom.data.collectors import RpmCollector
from alma_sbom.data.collectors.rpm import hash_file
from alma_sbom.data.models import Package
from alma_sbom.data.attributes.property import (
    Property,
    PackageProperties,
    BuildPropertiesForPackage as BuildProperties,
    GitSourceProperties,
    SBOMProperties,
)

TESTED_PACKAGE_NAME = 'bash-5.1.8-9.el9.x86_64.rpm'
TESTED_PACKAGE_PATH = os.path.dirname(__file__) + f'/{TESTED_PACKAGE_NAME}'

EXPECTED_LICENSES = licenses=Licenses(ids=[], expression='GPLv3+'),
EXPECTED_HASH_VALUE = '05dc1b806bd5456d40e3d7f882ead037aaf480c596e83fbfb6ab86be74a2d8d1'
EXPECTED_PACKAGE = Package(
    package_nevra=PackageNevra( # 0:bash-5.1.8-9.el9.x86_64
        epoch = None,
        name = 'bash',
        version = '5.1.8',
        release = '9.el9',
        arch = 'x86_64',
    ),
    source_rpm='bash-5.1.8-9.el9.src.rpm',
    package_timestamp=None, # 1714500330,
    hashs=[Hash(
        value='05dc1b806bd5456d40e3d7f882ead037aaf480c596e83fbfb6ab86be74a2d8d1',
        algorithm=Algorithms.SHA_256,
    )],
    licenses=Licenses(ids=[], expression='GPLv3+'),
    summary='The GNU Bourne Again shell',
    description='The GNU Bourne Again shell (Bash) is a shell or command language\ninterpreter that is compatible with the Bourne shell (sh). Bash\nincorporates useful features from the Korn shell (ksh) and the C shell\n(csh). Most sh scripts can be run by bash without modification.',
)

@pytest.fixture
def rpm_collector_instance() -> RpmCollector:
    return RpmCollector()


def test_collect_package_from_file(rpm_collector_instance: RpmCollector) -> None:
    # TODO: use path
    assert rpm_collector_instance.collect_package_from_file(TESTED_PACKAGE_PATH) == EXPECTED_PACKAGE


def test_hash_file() -> None:
    assert hash_file(TESTED_PACKAGE_PATH) == EXPECTED_HASH_VALUE

