from logging import getLogger
from cyclonedx.model import HashAlgorithm, HashType
from cyclonedx.model.component import Property as CDXProperty
from cyclonedx.model.component import Component, ComponentType

from alma_sbom.data.models.package import Hash, Algorithms
from alma_sbom.data.models import Package, Build
from alma_sbom.data.attributes.property import Property

_logger = getLogger(__name__)

def _make_hash(hash: Hash) -> HashType:
    return HashType(
        algorithm=HashAlgorithm(hash.algorithm.value),
        hash_value=hash.value,
    )

def component_from_package(package: Package) -> Component:
    return Component(
        component_type=ComponentType('library'),
        name=package.package_nevra.name,
        version=package.package_nevra.get_EVR(),
        #publisher=constants.ALMAOS_VENDOR,
        hashes=[_make_hash(h) for h in package.hashs],
        cpe=package.package_nevra.get_cpe23(),
        purl=package.get_purl(),
        properties=[
            _make_property(prop) for prop in package.get_properties()
        ],
    )

def _make_property(prop: Property) -> CDXProperty:
    # See Property spec:
    # https://cyclonedx.org/docs/1.4/json/#components_items_properties_items_value
    return CDXProperty(name=prop.name, value=f'{prop.value}')
