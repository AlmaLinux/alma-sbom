import json
import xml.dom.minidom
from logging import getLogger

from cyclonedx.model import HashAlgorithm, HashType, Property, LicenseChoice
from cyclonedx.model.bom import Bom, Tool
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.output import OutputFormat, get_instance
from packageurl import PackageURL

from version import __version__

from . import constants
from . import common

_logger = getLogger('alma-sbom')


class SBOM:
    def __init__(self, data, sbom_object_type, output_format, output_file):
        self.input_data = data
        self.sbom_object_type = sbom_object_type
        self.output_format = OutputFormat(output_format.capitalize())
        self.output_file = output_file
        self._bom = Bom()

    def run(self):
        if self.sbom_object_type == 'build':
            self.generate_build_sbom()
        else:
            self.generate_package_sbom()

        output = get_instance(bom=self._bom, output_format=self.output_format)

        # [Potential] TODOs:
        # - Shall we check and/or include extension .json|.xml?
        # - Shall we output to a particular folder?
        output_str = output.output_as_string()
        if self.output_format == OutputFormat.XML:
            xml_output = xml.dom.minidom.parseString(output_str)
            # Post generation version bump
            if 'version' in self.input_data:
                xml_output.firstChild.setAttribute(
                    'version', str(self.input_data['version'])
                )

            pretty_output = xml_output.toprettyxml()
        else:
            json_output = json.loads(output_str)
            # Post generation version bump
            if 'version' in self.input_data:
                json_output['version'] = self.input_data['version']

            pretty_output = json.dumps(json_output, indent=4)

        if self.output_file:
            with open(self.output_file, 'w') as fd:
                fd.write(pretty_output)
            _logger.info('Wrote generated SBOM to %s', self.output_file)
        else:
            print(pretty_output)

    @staticmethod
    def __generate_tool(tool):
        return Tool(
            vendor=tool['vendor'],
            name=tool['name'],
            version=tool['version'],
        )

    @staticmethod
    def __generate_prop(prop):
        # See Property spec:
        # https://cyclonedx.org/docs/1.4/json/#components_items_properties_items_value
        return Property(
            name=prop['name'],
            value=common.normalize_epoch_in_prop(prop['name'],
                                                 str(prop['value'])),
        )

    @staticmethod
    def __generate_hash(hash_):
        return HashType(
            algorithm=HashAlgorithm(hash_['alg']),
            hash_value=hash_['content'],
        )

    @staticmethod
    def __generate_licenses(_license):
        l = []
        if 'ids' in _license and _license['ids']:
            for lid in _license['ids']:
                l.append( LicenseChoice(license_=lid) )

        elif 'expression' in _license and _license['expression']:
            l.append( LicenseChoice(license_expression=_license['expression']) )
        return l

    def __generate_package_component(self, comp):
        purl = common.normalize_epoch_in_purl(comp['purl'])
        return Component(
            component_type=ComponentType('library'),
            name=comp['name'],
            version=common.normalize_epoch_in_version(str(comp['version'])),
            publisher=constants.ALMAOS_VENDOR,
            hashes=[self.__generate_hash(h) for h in comp['hashes']],
            cpe=common.normalize_epoch_in_cpe(comp['cpe']),
            purl=PackageURL.from_string(purl),
            properties=[
                self.__generate_prop(prop) for prop in comp['properties']
            ],
            licenses=self.__generate_licenses(comp['licenses'])
                if 'licenses' in comp and comp['licenses'] else [] ,
            description=comp['description']
        )

    def generate_build_sbom(self):
        input_metadata = self.input_data['metadata']['component']
        input_components = self.input_data['components']

        # TODO: Figure out how to set the SBOM version, because
        # self._bom.version = self.input_data['version'] results
        # in adding 'ersion: 1' to the final SBOM

        # We do this way to keep cyclonedx-python-lib as a tool
        for tool in constants.TOOLS:
            self._bom.metadata.tools.add(self.__generate_tool(tool))

        properties = [
            self.__generate_prop(prop) for prop in input_metadata['properties']
        ]

        component = Component(
            component_type=ComponentType('library'),
            name=input_metadata['name'],
            author=input_metadata['author'],
            properties=properties,
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
        for tool in constants.TOOLS:
            self._bom.metadata.tools.add(self.__generate_tool(tool))

        self._bom.metadata.component = self.__generate_package_component(
            self.input_data['metadata']['component'],
        )
