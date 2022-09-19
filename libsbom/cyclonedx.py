import json

from cas_wrapper import CasWrapper
from cyclonedx.model import Property, HashType, HashAlgorithm
from cyclonedx.model.bom import Bom, Tool
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.output import OutputFormat, get_instance

from packageurl import PackageURL
from version import __version__

ALMAOS_VENDOR = 'AlmaLinux OS Foundation'

TOOLS = [
    {
        "vendor": ALMAOS_VENDOR,
        "name": "AlmaLinux Build System",
        "version": "0.1"  # Shall we start versioning ALBS?
    },
    {
        "vendor": ALMAOS_VENDOR,
        "name": "alma-sbom",
        "version": __version__
    },
    {
        "vendor": "Codenotary Inc",
        "name": "Community Attestation Service (CAS)",
        "version": CasWrapper.get_version()
    }
]


class SBOM:
    def __init__(self, data, sbom_type, output_format, output_file):
        self.input_data = data
        self.sbom_type = sbom_type
        self.output_format = OutputFormat(output_format.capitalize())
        self.output_file = output_file
        self._bom = Bom()

    def run(self):
        if self.sbom_type == 'build':
            self.generate_build_sbom()
        else:
            self.generate_package_sbom()

        output = get_instance(
            bom=self._bom,
            output_format=self.output_format)

        # [Potential] TODOs:
        # - Shall we overwrite by default?
        # - Shall we check and/or include extension .json|.xml
        # - Shall we output to a particular folder
        # - Shall we save the files manually so we can add
        # a pretty formatting to them?
        output.output_to_file(self.output_file, allow_overwrite=True)


    def __generate_tool(self, tool):
        return Tool(
                vendor=tool['vendor'],
                name=tool['name'],
                version=tool['version'])

    def __generate_prop(self, prop):
        # See Property spec:
        # https://cyclonedx.org/docs/1.4/json/#components_items_properties_items_value
        return Property(
                name=prop['name'],
                value=str(prop['value']))

    def __generate_hash(self, hash_):
        return HashType(
            algorithm=HashAlgorithm(hash_['alg']),
            hash_value=hash_['content'])


    def __generate_package_component(self, comp):
        return Component(
            component_type=ComponentType('library'),
            name=comp['name'],
            version=comp['version'],
            publisher='AlmaLinux',
            hashes=[
                self.__generate_hash(h)
                for h in comp['hashes']
            ],
            cpe=comp['cpe'],
            purl=PackageURL.from_string(comp['purl']),
            properties=[
                self.__generate_prop(prop)
                for prop in comp['properties']])


    def generate_build_sbom(self):
        input_metadata = self.input_data['metadata']
        input_components = self.input_data['components']

        # TODO: Figure out how to set the SBOM version, because
        # self._bom.version = self.input_data['version'] results
        # in adding 'ersion: 1' to the final SBOM

        # We do this way to keep cyclonedx-python-lib as a tool
        for tool in TOOLS:
            self._bom.metadata.tools.add(self.__generate_tool(tool))

        properties = [
            self.__generate_prop(prop)
            for prop in input_metadata['properties']
        ]

        component = Component(
            component_type=ComponentType('library'),
            name=input_metadata['name'],
            author=input_metadata['author'],
            properties = properties
        )
        self._bom.metadata.component = component

        # We do this way because Bom.components is not just a list
        for component in input_components:
            comp = self.__generate_package_component(component)
            self._bom.components.add(comp)

    def generate_package_sbom(self):
        # TODO: Figure out how to set the SBOM version, because
        # self._bom.version = self.input_data['version'] results
        # in adding 'ersion: 1' to the final SBOM

        # We do this way to keep cyclonedx-python-lib as a tool
        for tool in TOOLS:
            self._bom.metadata.tools.add(self.__generate_tool(tool))

        self._bom.metadata.component = self.__generate_package_component(
            self.input_data['component'])
