import pytest

from alma_sbom.type import Hash, PackageNevra, Licenses, Algorithms
from alma_sbom.data.models import Package, NullPackage
from alma_sbom.data.attributes.property import (
    Property,
    PackageProperties,
    BuildPropertiesForPackage as BuildProperties,
    GitSourceProperties,
    SBOMProperties,
)

@pytest.fixture
def package_instance() -> Package:
    return Package(
        package_nevra=PackageNevra( # 0:bash-5.1.8-9.el9.x86_64
            epoch = 0,
            name = 'bash',
            version = '5.1.8',
            release = '9.el9',
            arch = 'x86_64',
        ),
        source_rpm='bash-5.1.8-9.el9.src.rpm',
        package_timestamp=1714500330,
        hashs=[Hash(
            value='05dc1b806bd5456d40e3d7f882ead037aaf480c596e83fbfb6ab86be74a2d8d1',
            algorithm=Algorithms.SHA_256,
        )],
        licenses=Licenses(ids=[], expression='GPLv3+'),
        summary='The GNU Bourne Again shell',
        description='The GNU Bourne Again shell (Bash) is a shell or command language\ninterpreter that is compatible with the Bourne shell (sh). Bash\nincorporates useful features from the Korn shell (ksh) and the C shell\n(csh). Most sh scripts can be run by bash without modification.',
        package_properties=PackageProperties(
            epoch=0,
            version='5.1.8',
            release='9.el9',
            arch='x86_64',
            buildhost='x64-builder01.almalinux.org',
            sourcerpm='bash-5.1.8-9.el9.src.rpm',
            timestamp=1714500330,
        ),
        build_properties=BuildProperties(
            build_id=11363,
            build_url=None,
            author='eabdullin1 <55892454+eabdullin1@users.noreply.github.com>',
            package_type='rpm',
            target_arch='x86_64',
            source=GitSourceProperties(
                # source_type='git',
                git_url='https://git.almalinux.org/rpms/bash.git',
                git_commit='https://git.almalinux.org/rpms/bash.git',
                git_ref='imports/c9/bash-5.1.8-9.el9',
                git_commit_immudb_hash='4533026da95ca85fab57eafbc91c28a3a2dabd79',
            ),
        ),
        sbom_properties=SBOMProperties(
            immudb_hash='05dc1b806bd5456d40e3d7f882ead037aaf480c596e83fbfb6ab86be74a2d8d1',
        ),
    )


def test_get_doc_name(package_instance: Package) -> None:
    expected_doc_name = "0:bash-5.1.8-9.el9"
    assert package_instance.get_doc_name() == expected_doc_name


def test_get_cpe23(package_instance: Package) -> None:
    expected_cpe23 = "cpe:2.3:a:almalinux:bash:5.1.8-9.el9:*:*:*:*:*:*:*"
    assert package_instance.get_cpe23() == expected_cpe23


def test_get_purl(package_instance: Package) -> None:
    expected_purl = "pkg:rpm/almalinux/bash@5.1.8-9.el9?arch=x86_64&distro=almalinux-9&upstream=bash-5.1.8-9.el9.src.rpm"
    assert package_instance.get_purl() == expected_purl


def test_get_properties(package_instance: Package) -> None:
    expected_props = PackageProperties(
        epoch=0,
        version='5.1.8',
        release='9.el9',
        arch='x86_64',
        buildhost='x64-builder01.almalinux.org',
        sourcerpm='bash-5.1.8-9.el9.src.rpm',
        timestamp=1714500330,
    ).to_properties() + \
    BuildProperties(
        build_id=11363,
        build_url=None,
        author='eabdullin1 <55892454+eabdullin1@users.noreply.github.com>',
        package_type='rpm',
        target_arch='x86_64',
        source=GitSourceProperties(
            git_url='https://git.almalinux.org/rpms/bash.git',
            git_commit='https://git.almalinux.org/rpms/bash.git',
            git_ref='imports/c9/bash-5.1.8-9.el9',
            git_commit_immudb_hash='4533026da95ca85fab57eafbc91c28a3a2dabd79',
        ),
    ).to_properties() + \
    SBOMProperties(
        immudb_hash='05dc1b806bd5456d40e3d7f882ead037aaf480c596e83fbfb6ab86be74a2d8d1',
    ).to_properties()
    assert package_instance.get_properties() == expected_props


def test_merge(package_instance: Package) -> None:
    pkg_merged = NullPackage.merge(package_instance)
    assert pkg_merged == package_instance

