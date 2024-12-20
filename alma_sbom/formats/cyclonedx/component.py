
from cyclonedx.model.component import Component, ComponentType
from alma_sbom.data.models import Package, Build

def component_from_package(package: Package) -> Component:
    return Component(
        component_type=ComponentType('library'),
        name=package.package_nevra.name,
        version=package.package_nevra.get_EVR(),
        #publisher=constants.ALMAOS_VENDOR,
        #hashes=[self.__generate_hash(h) for h in comp['hashes']],
        cpe=package.package_nevra.get_cpe23(),
        purl=package.get_purl(),
        #properties=[
        #    self.__generate_prop(prop) for prop in comp['properties']
        #],
    )

