import logging
import datetime
import uuid

from spdx_tools.spdx.writer.json     import json_writer
from spdx_tools.spdx.writer.tagvalue import tagvalue_writer
from spdx_tools.spdx.writer.xml      import xml_writer
from spdx_tools.spdx.writer.yaml     import yaml_writer
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
    PackagePurpose,
    Relationship,
    RelationshipType
)

from cas_wrapper import CasWrapper
from version import __version__

ALMAOS_VENDOR = 'AlmaLinux OS Foundation'
ALMAOS_EMAIL = 'cloud-infra@almalinux.org'
ALMAOS_SBOMLICENSE = 'CC0-1.0'                  # FIXME: Determine license for AlmaLinux SBOMs
ALMAOS_NAMESPACE = 'https://security.almalinux.org/spdx'

TOOLS = [
    {
        "vendor": ALMAOS_VENDOR,
        "name": "AlmaLinux Build System",
        "version": "0.1"
    }, {
        "vendor": ALMAOS_VENDOR,
        "name": "alma-sbom",
        "version": __version__
    }, {
        "vendor": ALMAOS_VENDOR,
        "name": "spdx-tools",
        "version": "0.0" # FIXME: Need correct version info for spdx-tools
    }, {
        "vendor": "Codenotary Inc",
        "name": "Community Attestation Service (CAS)",
        "version": CasWrapper.get_version()
    }
]

writers = {
    'json':     json_writer,
    'tagvalue': tagvalue_writer,
    'xml':      xml_writer,
    'yaml':     yaml_writer,
}

def component_get_property(component: dict, property_name: str) -> str:
    for prop in component["properties"]:
        if prop["name"] == property_name:
            return prop["value"]

    return None


def make_cpe_ref(cpe: str) -> ExternalPackageRef:
    return ExternalPackageRef(ExternalPackageRefCategory.SECURITY,
                              "cpe23Type", cpe)


def make_purl_ref(purl: str) -> ExternalPackageRef:
    return ExternalPackageRef(ExternalPackageRefCategory.PACKAGE_MANAGER,
                              "purl", purl)


def make_annotation(spdxid: str, content: str) -> Annotation:
    this_tool = Actor(actor_type=ActorType.TOOL,
                      name=f"alma-sbom {__version__}")

    return Annotation(spdx_id=spdxid,
                      annotation_type=AnnotationType.OTHER,
                      annotator=this_tool,
                      annotation_date=datetime.datetime.now(),
                      annotation_comment=content)


def make_checksum(algo: str, value: str) -> Checksum:
    algo_map = {
        "SHA-256": ChecksumAlgorithm.SHA256
    }

    if not algo in algo_map:
        raise ValueError(f"Algorithm {algo} is not supported")

    return Checksum(algo_map[algo], value)


def component_get_buildtime(component: dict) -> datetime.datetime:
    buildtime = component_get_property(component, "almalinux:package:timestamp")
    return datetime.datetime.fromisoformat(buildtime)


class SBOM:
    def __init__(self, data, sbom_object_type, output_format, output_file):
        self._input_data = data
        self._sbom_object_type = sbom_object_type
        self._output_format = output_format
        self._output_file = output_file

        self._org = Actor(ActorType.ORGANIZATION,
                          ALMAOS_VENDOR,
                          ALMAOS_EMAIL)
        self._creators = [self._org] + [Actor(actor_type=ActorType.TOOL,
                                              name=f"{tool['name']} {tool['version']}") for tool in TOOLS]

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


    def _prepare_document(self):
        if "metadata" in self._input_data:
            doc_name = self._input_data["metadata"]["name"]
        else:
            pkgname = self._input_data['component']['name']
            pkgvers = self._input_data['component']['version']
            doc_name = f"{pkgname}-{pkgvers}"

        doc_info = CreationInfo(spdx_version="SPDX-2.3",
                                spdx_id=f"SPDXRef-{uuid.uuid4()}",
                                name=doc_name,
                                data_license=ALMAOS_SBOMLICENSE,
                                document_namespace=ALMAOS_NAMESPACE,
                                creators=self._creators,
                                created=datetime.datetime.now())

        self._document = Document(doc_info)


    def add_package(self, component):
        pkgid = self.get_next_package_id()

        pkg = Package(spdx_id=pkgid,
                      name=component["name"],
                      download_location=component["purl"]) # FIXME: download_location must point to the RPM on a mirror

        for pkghash in component["hashes"]:
            pkg.checksums += [make_checksum(pkghash["alg"],
                                            pkghash["content"])]

        pkg.version = component["version"]
        pkg.supplier = self._org
        pkg.external_references += [make_cpe_ref(component["cpe"]),
                                    make_purl_ref(component["purl"])]
        pkg.built_date = component_get_buildtime(component)
        pkg.files_analyzed = False

        self._document.packages += [pkg]

        for prop in component["properties"]:
            note = make_annotation(pkgid, f"{prop['name']}={prop['value']}")
            self._document.annotations += [note]


    def add_build(self, metadata):
        spdxid = self._document.creation_info.spdx_id

        for prop in metadata:
            note = make_annotation(spdxid, f"{prop['name']}={prop['value']}")
            self._document.annotations += [note]


    def _generate(self):
        components = []

        # There is either a single package in "component" or multiple packages in "components"
        if "component" in self._input_data:
            components += [self._input_data["component"]]
        if "components" in self._input_data:
            components += self._input_data["components"]

        for component in components:
            self.add_package(component)

        # build SBOMs also contain build metadata
        if "metadata" in self._input_data:
            self.add_build(self._input_data["metadata"])


    def run(self):
        writer = writers[self._output_format]

        self._generate()
        writer.write_document_to_file(self._document,
                                      self._output_file or "/dev/stdout",
                                      validate=False)