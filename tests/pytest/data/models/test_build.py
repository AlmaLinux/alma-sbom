import pytest

from alma_sbom.data.models import Package, NullPackage, Build
from alma_sbom.data.attributes.property import (
    Property,
    BuildPropertiesForBuild as BuildProperties,
)

from .test_package import package_instance

@pytest.fixture
def build_instance(package_instance: Package) -> Build:
    return Build(
        build_id=11363,
        author='test author',
        packages=[package_instance],
        build_properties=BuildProperties(
            build_id=11363,
            build_url='https://build.almalinux.org/build/11363',
            timestamp=1714500330,
        ),
    )


def test_get_doc_name(build_instance: Build) -> None:
    expected_doc_name = 'build-11363'
    assert build_instance.get_doc_name() == expected_doc_name


def test_get_properties(build_instance: Build) -> None:
    expected_props = [
        Property(
            name='almalinux:albs:build:ID',
            value=11363,
        ),
        Property(
            name='almalinux:albs:build:URL',
            value='https://build.almalinux.org/build/11363',
        ),
        Property(
            name='almalinux:albs:build:timestamp',
            value=1714500330,
        ),
    ]
    assert build_instance.get_properties() == expected_props


def test_append_package(build_instance: Build, package_instance: Package) -> None:
    expected_build_instance = Build(
        build_id=11363,
        author='test author',
        packages=[package_instance, NullPackage],
        build_properties=BuildProperties(
            build_id=11363,
            build_url='https://build.almalinux.org/build/11363',
            timestamp=1714500330,
        ),
    )
    tested_build_instance = build_instance
    tested_build_instance.append_package(NullPackage)

    # TODO: need to implement __eq__ in Build class more precisely
    assert tested_build_instance == expected_build_instance

