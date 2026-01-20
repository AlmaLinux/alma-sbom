import pytest

from alma_sbom.data.models import Package, NullPackage, Iso

from .test_package import package_instance


@pytest.fixture
def iso_instance(package_instance: Package) -> Iso:
    return Iso(
        releasever=9,
        image_type='Minimal',
        packages=[package_instance],
    )


def test_append_package(iso_instance: Iso, package_instance: Package) -> None:
    expected_iso_instance = Iso(
        releasever=9,
        image_type='Minimal',
        packages=[package_instance, NullPackage],
    )
    tested_iso_instance = iso_instance
    tested_iso_instance.append_package(NullPackage)

    # TODO: need to implement __eq__ in Iso class more precisely
    assert tested_iso_instance == expected_iso_instance


def test_get_doc_name(iso_instance: Iso) -> None:
    expected_doc_name = 'AlmaLinux 9 Minimal ISO'
    assert iso_instance.get_doc_name() == expected_doc_name

