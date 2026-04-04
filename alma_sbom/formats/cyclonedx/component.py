from logging import getLogger
from cyclonedx.factory.license import LicenseFactory
from cyclonedx.model import HashAlgorithm, HashType
from cyclonedx.model.component import Property as CDXProperty
from cyclonedx.model.component import Component, ComponentType
from packageurl import PackageURL

from alma_sbom import constants
from alma_sbom.type import Hash, Algorithms, Licenses
from alma_sbom.data import Package, Build, Iso, Property

_logger = getLogger(__name__)
lc_factory = LicenseFactory()

def component_from_package(package: Package) -> Component:
    pkg_comp = Component(
        type=ComponentType.LIBRARY,
        name=package.package_nevra.name,
        version=package.package_nevra.get_EVR(),
        hashes=[_make_hash(h) for h in package.hashs],
        properties=[
            _make_property(prop) for prop in package.get_properties()
        ],
        licenses=_make_licenses(package.licenses)
            if package.licenses else None ,
        description=package.description
            if package.description else None ,
    )
    _make_alma_specific_fields(package, pkg_comp)
    return pkg_comp

def component_from_build(build: Build) -> Component:
    return Component(
        type=ComponentType.FRAMEWORK,
        name=build.get_doc_name(),
        author=build.author,
        properties=[
            _make_property(prop) for prop in build.get_properties()
        ],
    )

def component_from_iso(iso: Iso) -> Component:
    return Component(
        type=ComponentType.OPERATING_SYSTEM,
        name=iso.get_doc_name(),
    )

def _make_alma_specific_fields(package: Package, pkg_comp: Component) -> None:
    if package.is_alma_pkg():
        pkg_comp.publisher=constants.ALMAOS_VENDOR
        pkg_comp.cpe=package.get_cpe23()
        pkg_comp.purl=PackageURL.from_string(package.get_purl())
    else:
        _logger.warning(f'Package \"{package.get_doc_name()}\" is not AlmaLinux package.')
        _logger.warning(f'So, This SBOM donsn\'t have following info:')
        _logger.warning('\tcpe, purl, publisher')

def _make_hash(hash: Hash) -> HashType:
    return HashType(
        alg=HashAlgorithm(hash.algorithm.value),
        content=hash.value,
    )

def _make_property(prop: Property) -> CDXProperty:
    # See Property spec:
    # https://cyclonedx.org/docs/1.4/json/#components_items_properties_items_value
    return CDXProperty(name=prop.name, value=f'{prop.value}')

def _make_licenses(licenses: Licenses) -> list:
    l = []
    if licenses.ids:
        for lid in licenses.ids:
            l.append(lc_factory.make_from_string(lid))
    elif licenses.expression:
        l.append(lc_factory.make_from_string(licenses.expression))
    return l
