from cyclonedx.model import Property, HashType, HashAlgorithm
from cyclonedx.model.bom import Bom, Tool
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.output import BaseOutput, OutputFormat, get_instance

ALMA_SBOM_VENDOR='AlmaLinux OS Foundation'
ALMA_SBOM_NAME='alma-sbom'
ALMA_SBOM_VERSION='0.1'

class NoComponents(Exception):
    pass

class NoMetadata(Exception):
    pass

class SBOM:
    def __init__(self, sbom_data):
        self.input_data = sbom_data
        self._bom = Bom()

        if 'metadata' not in self.input_data:
            raise NoMetadata('No metadata provided in input dictionary')
        if 'components' not in self.input_data:
            raise NoComponents('No components provided in input dictionary')

    def generate_sbom(self):
        metadata = self.input_data['metadata']
        # By default, cyclonedx-python-lib is added into tools
        # Keep/remove/move to deps?
        for tool in metadata['tools']:
            t = Tool(
                vendor=tool['vendor'],
                name=tool['name'],
                version=tool['version'])

            self._bom.metadata.tools.add(t)

        alma_sbom_tool = Tool(
            vendor=ALMA_SBOM_VENDOR,
            name=ALMA_SBOM_NAME,
            version=ALMA_SBOM_VERSION)
        self._bom.metadata.tools.add(alma_sbom_tool)

        if 'component' in metadata:
            c_input = metadata['component']

            props = []
            for prop in c_input['properties']:
                props.append(Property(
                    name=prop['name'],
                    value=prop['value']))

            component = Component(
                component_type=ComponentType(c_input['type']),
                name=c_input['name'],
                author=c_input['author'],
                properties=props)

            self._bom.metadata.component = component

        cs_input = self.input_data['components']
        # Considering we receive packages as described in:
        # https://github.com/AlmaLinux/build-system-rfes/blob/sbom_draft/SBOM/SBOM.md#build-system-build-sbom-data-record
        for comp in cs_input:
            props = []
            for prop in comp['properties']:
                props.append(Property(
                    name=prop['name'],
                    value=prop['value']))

            hashes = []
            for h in comp['hashes']:
                hashes.append(HashType(
                    algorithm=HashAlgorithm(h['alg']),
                    hash_value=h['content']))

            self._bom.components.add(Component(
                component_type=ComponentType(comp['type']),
                name=comp['name'],
                version=comp['version'],
                publisher=comp['publisher'],
                hashes=hashes,
                cpe=comp['cpe'],
                # Commented purl since xml output is failing
                #comp['purl'], # we should use packageurl.PackageURL
                properties=props))


    def validate(self):
        self._bom.validate()


    def to_json_string(self):
        output = get_instance(bom=self._bom, output_format=OutputFormat.JSON)
        return output.output_as_string()


    def to_xml_string(self):
        output = get_instance(bom=self._bom, output_format=OutputFormat.XML)
        return output.output_as_string()
