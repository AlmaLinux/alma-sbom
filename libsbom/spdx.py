import datetime
import uuid
from typing import Optional, Union
from logging import getLogger

from spdx_tools.spdx.model import (
    Actor,
    ActorType,
    Annotation,
    AnnotationType,
    Checksum,
    ChecksumAlgorithm,
    CreationInfo,
    Document,
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package,
    Relationship,
    RelationshipType,
)
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.writer.json import json_writer
from spdx_tools.spdx.writer.tagvalue import tagvalue_writer
from spdx_tools.spdx.writer.xml import xml_writer
from spdx_tools.spdx.writer.yaml import yaml_writer

from version import __version__

from . import constants
from . import common

writers = {
    'json': json_writer,
    'tagvalue': tagvalue_writer,
    'xml': xml_writer,
    'yaml': yaml_writer,
}

_logger = getLogger('alma-sbom')


def component_get_property(
    component: dict,
    property_name: str,
) -> Optional[Union[str, int]]:
    for prop in component.get("properties", []):
        if prop["name"] == property_name:
            return prop["value"]

    return None


def make_cpe_ref(cpe: str) -> ExternalPackageRef:
    return ExternalPackageRef(
        ExternalPackageRefCategory.SECURITY,
        "cpe23Type",
        common.normalize_epoch_in_cpe(cpe),
    )


def make_purl_ref(purl: str) -> ExternalPackageRef:
    return ExternalPackageRef(
        ExternalPackageRefCategory.PACKAGE_MANAGER,
        "purl",
        common.normalize_epoch_in_purl(purl),
    )


def make_annotation(spdxid: str, content: str) -> Annotation:
    this_tool = Actor(
        actor_type=ActorType.TOOL,
        name=f"alma-sbom {__version__}",
    )

    return Annotation(
        spdx_id=spdxid,
        annotation_type=AnnotationType.OTHER,
        annotator=this_tool,
        annotation_date=datetime.datetime.now(),
        annotation_comment=common.normalize_epoch_in_prop(name=None,
                                                          value=content),
    )


def make_checksum(algo: str, value: str) -> Checksum:
    algo_map = {
        "SHA-256": ChecksumAlgorithm.SHA256,
    }

    if algo not in algo_map:
        raise ValueError(f"Algorithm {algo} is not supported")

    return Checksum(algo_map[algo], value)


def buildtime_to_datetime(buildtime: int) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(buildtime)


def component_get_buildtime(component: dict) -> Optional[datetime.datetime]:
    buildtime = component_get_property(
        component,
        "almalinux:package:timestamp",
    )

    # Components in build SBOMs do not have timestamps
    if not buildtime:
        return None
    return buildtime_to_datetime(buildtime)


def build_get_timestamp(build: dict) -> Optional[datetime.datetime]:
    buildtime = component_get_property(build, "almalinux:albs:build:timestamp")

    try:
        # build timestamps don't have nanosecond-precision, no need for buildtime_to_datetime()
        return datetime.datetime.fromisoformat(buildtime)
    except TypeError:
        return None


class SBOM:
    def __init__(self, data, sbom_object_type, output_format, output_file, opt_creators):
        self._input_data = data
        self._sbom_object_type = sbom_object_type
        self._output_format = output_format
        self._output_file = output_file
        self._opt_creators = opt_creators
        self._prepare_creators()
        self._document = None
        self._next_id = 0
        self._prepare_document()

    def get_next_package_id(self) -> str:
        """Return an identifier that can be assigned to a package in this document.

        Further reading:
        https://spdx.github.io/spdx-spec/v2-draft/package-information/#72-package-spdx-identifier-field
        """
        cur_id = self._next_id
        self._next_id += 1
        return f"SPDXRef-{cur_id}"

    def _add_creators(self, actor_type, creators):
        if creators == None:
            return None

        d = len(creators['name']) - len(creators['email'])
        if d > 0:
            creators['email'] += [None] * d
        for name, email in zip(creators['name'], creators['email']):
            self._creators += [
                Actor(
                    actor_type=actor_type,
                    name=name,
                    email=email,
                )
            ]

    def _prepare_creators(self):
        tools = constants.TOOLS + constants.TOOLS_SPDX
        self._org = Actor(
            ActorType.ORGANIZATION,
            constants.ALMAOS_VENDOR,
            constants.ALMAOS_EMAIL,
        )
        self._creators = [self._org] + [
            Actor(
                actor_type=ActorType.TOOL,
                name=f"{tool['name']} {tool['version']}",
            )
            for tool in tools
        ]

        persons = self._opt_creators['creators_person']
        orgs = self._opt_creators['creators_org']
        self._add_creators(ActorType.PERSON, persons)
        self._add_creators(ActorType.ORGANIZATION, orgs)

    def _prepare_document(self):
        metadata = self._input_data["metadata"]['component']
        if self._sbom_object_type == 'build':
            doc_name = metadata["name"]
        else: # self._sbom_object_type == 'package':
            pkgname = metadata['name']
            pkgvers = metadata['version']
            pkgvers = common.normalize_epoch_in_version(pkgvers)
            doc_name = f"{pkgname}-{pkgvers}"

        doc_uuid = uuid.uuid4()
        doc_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name=doc_name,
            data_license=constants.ALMAOS_SBOMLICENSE,
            document_namespace=f"{constants.ALMAOS_NAMESPACE}-{doc_name}-{doc_uuid}",
            creators=self._creators,
            created=datetime.datetime.now(),
        )

        self._document = Document(doc_info)

    def add_package(self, component, build):
        pkgid = self.get_next_package_id()

        pkg = Package(
            spdx_id=pkgid,
            name=component["name"],
            download_location=SpdxNoAssertion(),
        )
        rel = Relationship(
            spdx_element_id="SPDXRef-DOCUMENT",
            relationship_type=RelationshipType.DESCRIBES,
            related_spdx_element_id=pkgid,
        )

        for pkghash in component["hashes"]:
            pkg.checksums += [
                make_checksum(pkghash["alg"], pkghash["content"])
            ]

        pkg.version = common.normalize_epoch_in_version(component['version'])
        pkg.supplier = self._org
        pkg.external_references += [
            make_cpe_ref(component["cpe"]),
            make_purl_ref(component["purl"]),
        ]

        pkg.built_date = component_get_buildtime(
            component
        ) or build_get_timestamp(build)

        pkg.files_analyzed = False

        self._document.packages += [pkg]
        self._document.relationships += [rel]

        for prop in component["properties"]:
            value = common.normalize_epoch_in_prop(prop['name'],
                                                   str(prop['value']))
            note = make_annotation(pkgid, f"{prop['name']}={value}")
            self._document.annotations += [note]

    def add_build(self, metadata):
        spdxid = self._document.creation_info.spdx_id

        for prop in metadata["properties"]:
            value = common.normalize_epoch_in_prop(prop['name'],
                                                   str(prop['value']))
            note = make_annotation(spdxid, f"{prop['name']}={value}")
            self._document.annotations += [note]

    def _generate(self):
        components = []

        # packages data are in "components" if sbom_object_type = 'build'
        # package data is in "metadata"."component" if sbom_object_type = 'package'
        # build SBOMs also contain build metadata
        if self._sbom_object_type == 'build':
            build_data = self._input_data["metadata"]["component"]
            self.add_build(build_data)
            components += self._input_data["components"]
        else: # self._sbom_object_type == 'package':
            build_data = {}
            components += [self._input_data["metadata"]["component"]]

        for component in components:
            self.add_package(component, build_data)

    def run(self):
        writer = writers[self._output_format]

        self._generate()
        writer.write_document_to_file(
            self._document,
            self._output_file or "/dev/stdout",
            validate=True,
        )
        if self._output_file:
            _logger.info('Wrote generated SBOM to %s', self._output_file)
