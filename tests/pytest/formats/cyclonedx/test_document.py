import pytest
import os
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from cyclonedx.builder.this import this_component as cdx_lib_component
from cyclonedx.model import HashAlgorithm, HashType
# from cyclonedx.factory.license import LicenseFactory, License
from cyclonedx.factory.license import LicenseFactory
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import Property as CDXProperty
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.tool import ToolRepository
from cyclonedx.schema import OutputFormat
from packageurl import PackageURL

from alma_sbom import constants
from alma_sbom.type import Hash, PackageNevra, Licenses, Algorithms, SbomFileFormatType
from alma_sbom.formats.cyclonedx.document import CDXFormatter, CDXDocument
from alma_sbom.data import Package, Build, Iso
from alma_sbom.data.attributes.property import (
    # Property,
    PackageProperties,
    BuildPropertiesForPackage,# as BuildProperties,
    BuildPropertiesForBuild,# as BuildProperties,
    GitSourceProperties,
    SBOMProperties,
)


lc_factory = LicenseFactory()

EXPECTED_CDX_FORMATTER_JSON = CDXFormatter(OutputFormat.JSON)
EXPECTED_CDX_FORMATTER_XML = CDXFormatter(OutputFormat.XML)

TESTED_BOM = Bom(
    metadata=BomMetaData(
        component=Component(
            bom_ref='BomRef.123456789012345.12345678901234567',
            name='bash',
        ),
        tools=ToolRepository(
            components=[
                Component(
                    name=tool['name'],
                    group=tool['vendor'],
                    version=tool['version'],
                    type=None,
                ) for tool in constants.TOOLS
            ] + [cdx_lib_component()],
        ),
        timestamp=datetime(2023, 4, 5, 6, 7, 8, 123456, timezone.utc),
    ),
    serial_number=UUID('12345678-1234-5678-9abc-123456789abc'),
)
EXPECTED_JSON_FILE = 'expected.cyclonedx.json'
EXPECTED_JSON_FILEPATH = Path(os.path.dirname(__file__)) / f'{EXPECTED_JSON_FILE}'
EXPECTED_JSON_OUTPUT = EXPECTED_JSON_FILEPATH.read_text(encoding='utf-8')
EXPECTED_XML_FILE = 'expected.cyclonedx.xml'
EXPECTED_XML_FILEPATH = Path(os.path.dirname(__file__)) / f'{EXPECTED_XML_FILE}'
EXPECTED_XML_OUTPUT = EXPECTED_XML_FILEPATH.read_text(encoding='utf-8')
# TESTED_CDX_DOCUMENT_JSON = CDXDocument(
#     bom=TESTED_BOM,
#     formatter=EXPECTED_CDX_FORMATTER_JSON,
# )

TESTED_PACKAGE = Package(
    package_nevra=PackageNevra( # 0:bash-5.1.8-9.el9.x86_64
        epoch = 0,
        name = 'bash',
        version = '5.1.8',
        release = '9.el9',
        arch = 'x86_64',
    ),
    source_rpm='bash-5.1.8-9.el9.src.rpm',
    package_timestamp=1714500330,
    hashs=[Hash(
        value='05dc1b806bd5456d40e3d7f882ead037aaf480c596e83fbfb6ab86be74a2d8d1',
        algorithm=Algorithms.SHA_256,
    )],
    licenses=Licenses(ids=[], expression='GPLv3+'),
    summary='The GNU Bourne Again shell',
    description='The GNU Bourne Again shell (Bash) is a shell or command language\ninterpreter that is compatible with the Bourne shell (sh). Bash\nincorporates useful features from the Korn shell (ksh) and the C shell\n(csh). Most sh scripts can be run by bash without modification.',
    package_properties=PackageProperties(
        epoch=0,
        version='5.1.8',
        release='9.el9',
        arch='x86_64',
        buildhost='x64-builder01.almalinux.org',
        sourcerpm='bash-5.1.8-9.el9.src.rpm',
        timestamp=1714500330,
    ),
    build_properties=BuildPropertiesForPackage(
        build_id=11363,
        build_url=None,
        author='eabdullin1 <55892454+eabdullin1@users.noreply.github.com>',
        package_type='rpm',
        target_arch='x86_64',
        source=GitSourceProperties(
            # source_type='git',
            git_url='https://git.almalinux.org/rpms/bash.git',
            git_commit='https://git.almalinux.org/rpms/bash.git',
            git_ref='imports/c9/bash-5.1.8-9.el9',
            git_commit_immudb_hash='4533026da95ca85fab57eafbc91c28a3a2dabd79',
        ),
    ),
    sbom_properties=SBOMProperties(
        immudb_hash='05dc1b806bd5456d40e3d7f882ead037aaf480c596e83fbfb6ab86be74a2d8d1',
    ),
)
TESTED_BUILD = Build(
    build_id=11363,
    author='test author',
    packages=[TESTED_PACKAGE],
    build_properties=BuildPropertiesForBuild(
        build_id=11363,
        build_url='https://build.almalinux.org/build/11363',
        timestamp=1714500330,
    ),
)
TESTED_ISO = Iso(
    releasever=9.6,
    image_type='test',
    packages=[TESTED_PACKAGE],
)


EXPECTED_DOC_FROM_PACKAGE = CDXDocument(
    bom=Bom(
        metadata=BomMetaData(
            component=Component(
                name='bash',
                version='0:5.1.8-9.el9',
                type=ComponentType.LIBRARY,
                publisher=constants.ALMAOS_VENDOR,
                description='The GNU Bourne Again shell (Bash) is a shell or command language\ninterpreter that is compatible with the Bourne shell (sh). Bash\nincorporates useful features from the Korn shell (ksh) and the C shell\n(csh). Most sh scripts can be run by bash without modification.',
                hashes=[HashType(
                    alg=HashAlgorithm(Algorithms.SHA_256.value),
                    content='05dc1b806bd5456d40e3d7f882ead037aaf480c596e83fbfb6ab86be74a2d8d1',
                )],
                licenses=[lc_factory.make_from_string('GPLv3+')],
                purl=PackageURL.from_string('pkg:rpm/almalinux/bash@5.1.8-9.el9?arch=x86_64&distro=almalinux-9&upstream=bash-5.1.8-9.el9.src.rpm'),
                properties=[
                    CDXProperty(name='almalinux:albs:build:ID', value='11363'),
                    CDXProperty(name='almalinux:albs:build:author', value='eabdullin1 <55892454+eabdullin1@users.noreply.github.com>'),
                    CDXProperty(name='almalinux:albs:build:packageType', value='rpm'),
                    CDXProperty(name='almalinux:albs:build:source:gitCommit', value='https://git.almalinux.org/rpms/bash.git'),
                    CDXProperty(name='almalinux:albs:build:source:gitCommitImmudbHash', value='4533026da95ca85fab57eafbc91c28a3a2dabd79'),
                    CDXProperty(name='almalinux:albs:build:source:gitRef', value='imports/c9/bash-5.1.8-9.el9'),
                    CDXProperty(name='almalinux:albs:build:source:gitURL', value='https://git.almalinux.org/rpms/bash.git'),
                    CDXProperty(name='almalinux:albs:build:source:type', value='git'),
                    CDXProperty(name='almalinux:albs:build:targetArch', value='x86_64'),
                    CDXProperty(name='almalinux:package:arch', value='x86_64'),
                    CDXProperty(name='almalinux:package:buildhost', value='x64-builder01.almalinux.org'),
                    CDXProperty(name='almalinux:package:epoch', value='0'),
                    CDXProperty(name='almalinux:package:release', value='9.el9'),
                    CDXProperty(name='almalinux:package:sourcerpm', value='bash-5.1.8-9.el9.src.rpm'),
                    CDXProperty(name='almalinux:package:timestamp', value='1714500330'),
                    CDXProperty(name='almalinux:package:version', value='5.1.8'),
                    CDXProperty(name='almalinux:sbom:immudbHash', value='05dc1b806bd5456d40e3d7f882ead037aaf480c596e83fbfb6ab86be74a2d8d1'),
                ],
                cpe='cpe:2.3:a:almalinux:bash:5.1.8-9.el9:*:*:*:*:*:*:*'
            ),
            tools=ToolRepository(
                components=[
                    Component(
                        name=tool['name'],
                        group=tool['vendor'],
                        version=tool['version'],
                        type=None,
                    ) for tool in constants.TOOLS
                ] + [cdx_lib_component()],
            ),
        ),
    ),
    formatter=CDXFormatter(output_format_type=OutputFormat.JSON),
)
EXPECTED_DOC_FROM_BUILD = CDXDocument(
    bom=Bom(
        metadata=BomMetaData(
            component=Component(
                name='build-11363',
                author='test author',
                type=ComponentType.FRAMEWORK,
                properties=[
                    CDXProperty(name='almalinux:albs:build:ID', value='11363'),
                    CDXProperty(name='almalinux:albs:build:URL', value='https://build.almalinux.org/build/11363'),
                    CDXProperty(name='almalinux:albs:build:timestamp', value='1714500330'),
                ],
            ),
            tools=ToolRepository(
                components=[
                    Component(
                        name=tool['name'],
                        group=tool['vendor'],
                        version=tool['version'],
                        type=None,
                    ) for tool in constants.TOOLS
                ] + [cdx_lib_component()],
            ),
        ),
        components=[Component(
            name='bash',
            version='0:5.1.8-9.el9',
            type=ComponentType.LIBRARY,
            publisher=constants.ALMAOS_VENDOR,
            description='The GNU Bourne Again shell (Bash) is a shell or command language\ninterpreter that is compatible with the Bourne shell (sh). Bash\nincorporates useful features from the Korn shell (ksh) and the C shell\n(csh). Most sh scripts can be run by bash without modification.',
            hashes=[HashType(
                alg=HashAlgorithm(Algorithms.SHA_256.value),
                content='05dc1b806bd5456d40e3d7f882ead037aaf480c596e83fbfb6ab86be74a2d8d1',
            )],
            licenses=[lc_factory.make_from_string('GPLv3+')],
            purl=PackageURL.from_string('pkg:rpm/almalinux/bash@5.1.8-9.el9?arch=x86_64&distro=almalinux-9&upstream=bash-5.1.8-9.el9.src.rpm'),
            properties=[
                CDXProperty(name='almalinux:albs:build:ID', value='11363'),
                CDXProperty(name='almalinux:albs:build:author', value='eabdullin1 <55892454+eabdullin1@users.noreply.github.com>'),
                CDXProperty(name='almalinux:albs:build:packageType', value='rpm'),
                CDXProperty(name='almalinux:albs:build:source:gitCommit', value='https://git.almalinux.org/rpms/bash.git'),
                CDXProperty(name='almalinux:albs:build:source:gitCommitImmudbHash', value='4533026da95ca85fab57eafbc91c28a3a2dabd79'),
                CDXProperty(name='almalinux:albs:build:source:gitRef', value='imports/c9/bash-5.1.8-9.el9'),
                CDXProperty(name='almalinux:albs:build:source:gitURL', value='https://git.almalinux.org/rpms/bash.git'),
                CDXProperty(name='almalinux:albs:build:source:type', value='git'),
                CDXProperty(name='almalinux:albs:build:targetArch', value='x86_64'),
                CDXProperty(name='almalinux:package:arch', value='x86_64'),
                CDXProperty(name='almalinux:package:buildhost', value='x64-builder01.almalinux.org'),
                CDXProperty(name='almalinux:package:epoch', value='0'),
                CDXProperty(name='almalinux:package:release', value='9.el9'),
                CDXProperty(name='almalinux:package:sourcerpm', value='bash-5.1.8-9.el9.src.rpm'),
                CDXProperty(name='almalinux:package:timestamp', value='1714500330'),
                CDXProperty(name='almalinux:package:version', value='5.1.8'),
                CDXProperty(name='almalinux:sbom:immudbHash', value='05dc1b806bd5456d40e3d7f882ead037aaf480c596e83fbfb6ab86be74a2d8d1'),
            ],
            cpe='cpe:2.3:a:almalinux:bash:5.1.8-9.el9:*:*:*:*:*:*:*'
        )],
    ),
    formatter=CDXFormatter(output_format_type=OutputFormat.JSON),
)
EXPECTED_DOC_FROM_ISO = CDXDocument(
    bom=Bom(
        metadata=BomMetaData(
            component=Component(
                name='AlmaLinux 9.6 test ISO',
                type=ComponentType.OPERATING_SYSTEM,
            ),
            tools=ToolRepository(
                components=[
                    Component(
                        name=tool['name'],
                        group=tool['vendor'],
                        version=tool['version'],
                        type=None,
                    ) for tool in constants.TOOLS
                ] + [cdx_lib_component()],
            ),
        ),
        components=[Component(
            name='bash',
            version='0:5.1.8-9.el9',
            type=ComponentType.LIBRARY,
            publisher=constants.ALMAOS_VENDOR,
            description='The GNU Bourne Again shell (Bash) is a shell or command language\ninterpreter that is compatible with the Bourne shell (sh). Bash\nincorporates useful features from the Korn shell (ksh) and the C shell\n(csh). Most sh scripts can be run by bash without modification.',
            hashes=[HashType(
                alg=HashAlgorithm(Algorithms.SHA_256.value),
                content='05dc1b806bd5456d40e3d7f882ead037aaf480c596e83fbfb6ab86be74a2d8d1',
            )],
            licenses=[lc_factory.make_from_string('GPLv3+')],
            purl=PackageURL.from_string('pkg:rpm/almalinux/bash@5.1.8-9.el9?arch=x86_64&distro=almalinux-9&upstream=bash-5.1.8-9.el9.src.rpm'),
            properties=[
                CDXProperty(name='almalinux:albs:build:ID', value='11363'),
                CDXProperty(name='almalinux:albs:build:author', value='eabdullin1 <55892454+eabdullin1@users.noreply.github.com>'),
                CDXProperty(name='almalinux:albs:build:packageType', value='rpm'),
                CDXProperty(name='almalinux:albs:build:source:gitCommit', value='https://git.almalinux.org/rpms/bash.git'),
                CDXProperty(name='almalinux:albs:build:source:gitCommitImmudbHash', value='4533026da95ca85fab57eafbc91c28a3a2dabd79'),
                CDXProperty(name='almalinux:albs:build:source:gitRef', value='imports/c9/bash-5.1.8-9.el9'),
                CDXProperty(name='almalinux:albs:build:source:gitURL', value='https://git.almalinux.org/rpms/bash.git'),
                CDXProperty(name='almalinux:albs:build:source:type', value='git'),
                CDXProperty(name='almalinux:albs:build:targetArch', value='x86_64'),
                CDXProperty(name='almalinux:package:arch', value='x86_64'),
                CDXProperty(name='almalinux:package:buildhost', value='x64-builder01.almalinux.org'),
                CDXProperty(name='almalinux:package:epoch', value='0'),
                CDXProperty(name='almalinux:package:release', value='9.el9'),
                CDXProperty(name='almalinux:package:sourcerpm', value='bash-5.1.8-9.el9.src.rpm'),
                CDXProperty(name='almalinux:package:timestamp', value='1714500330'),
                CDXProperty(name='almalinux:package:version', value='5.1.8'),
                CDXProperty(name='almalinux:sbom:immudbHash', value='05dc1b806bd5456d40e3d7f882ead037aaf480c596e83fbfb6ab86be74a2d8d1'),
            ],
            cpe='cpe:2.3:a:almalinux:bash:5.1.8-9.el9:*:*:*:*:*:*:*'
        )],
    ),
    formatter=CDXFormatter(output_format_type=OutputFormat.JSON),
)



@pytest.fixture
def cdx_formatter_json_instance() -> CDXFormatter:
    return CDXFormatter.from_format_type(SbomFileFormatType.JSON)
@pytest.fixture
def cdx_formatter_xml_instance() -> CDXFormatter:
    return CDXFormatter.from_format_type(SbomFileFormatType.XML)
def test_from_format_type(
        cdx_formatter_json_instance: CDXFormatter,
        cdx_formatter_xml_instance: CDXFormatter
    ) -> None:
        assert cdx_formatter_json_instance == EXPECTED_CDX_FORMATTER_JSON
        assert cdx_formatter_xml_instance == EXPECTED_CDX_FORMATTER_XML

def test_formatter_write(
        cdx_formatter_json_instance: CDXFormatter,
        cdx_formatter_xml_instance: CDXFormatter,
    ) -> None:
    assert cdx_formatter_json_instance.write(TESTED_BOM) == EXPECTED_JSON_OUTPUT
    assert cdx_formatter_xml_instance.write(TESTED_BOM) == EXPECTED_XML_OUTPUT


@pytest.fixture
def cdx_document_package_instance() -> CDXDocument:
    return CDXDocument.from_package(
        package=TESTED_PACKAGE,
        file_format_type=SbomFileFormatType.JSON
    )
def test_from_package(cdx_document_package_instance) -> None:
    ### NOTE: We should set same value to below attributes(like id or timestamp)
    object.__setattr__(
        cdx_document_package_instance.bom,
        'serial_number',
        EXPECTED_DOC_FROM_PACKAGE.bom.serial_number,
    )
    object.__setattr__(
        cdx_document_package_instance.bom.metadata,
        '_timestamp',
        EXPECTED_DOC_FROM_PACKAGE.bom.metadata._timestamp,
    )
    if cdx_document_package_instance == EXPECTED_DOC_FROM_PACKAGE:
        assert cdx_document_package_instance == EXPECTED_DOC_FROM_PACKAGE
    else:
        diff_CDXDocument(cdx_document_package_instance, EXPECTED_DOC_FROM_PACKAGE)


@pytest.fixture
def cdx_document_build_instance() -> CDXDocument:
    return CDXDocument.from_build(
        build=TESTED_BUILD,
        file_format_type=SbomFileFormatType.JSON
    )
def test_from_build(cdx_document_build_instance) -> None:
    ### NOTE: We should set same value to below attributes(like id or timestamp)
    object.__setattr__(
        cdx_document_build_instance.bom,
        'serial_number',
        EXPECTED_DOC_FROM_BUILD.bom.serial_number,
    )
    object.__setattr__(
        cdx_document_build_instance.bom.metadata,
        '_timestamp',
        EXPECTED_DOC_FROM_BUILD.bom.metadata._timestamp,
    )
    if cdx_document_build_instance == EXPECTED_DOC_FROM_BUILD:
        assert cdx_document_build_instance == EXPECTED_DOC_FROM_BUILD
    else:
        diff_CDXDocument(cdx_document_build_instance, EXPECTED_DOC_FROM_BUILD)


@pytest.fixture
def cdx_document_iso_instance() -> CDXDocument:
    return CDXDocument.from_iso(
        iso=TESTED_ISO,
        file_format_type=SbomFileFormatType.JSON
    )
def test_from_iso(cdx_document_iso_instance) -> None:
    ### NOTE: We should set same value to below attributes(like id or timestamp)
    object.__setattr__(
        cdx_document_iso_instance.bom,
        'serial_number',
        EXPECTED_DOC_FROM_ISO.bom.serial_number,
    )
    object.__setattr__(
        cdx_document_iso_instance.bom.metadata,
        '_timestamp',
        EXPECTED_DOC_FROM_ISO.bom.metadata._timestamp,
    )
    if cdx_document_iso_instance == EXPECTED_DOC_FROM_ISO:
        assert cdx_document_iso_instance == EXPECTED_DOC_FROM_ISO
    else:
        diff_CDXDocument(cdx_document_iso_instance, EXPECTED_DOC_FROM_ISO)

def diff_CDXDocument(doc1: CDXDocument, doc2: CDXDocument) -> None:
    assert doc1.bom.metadata.component.group == doc2.bom.metadata.component.group
    assert doc1.bom.metadata.component.name == doc2.bom.metadata.component.name
    assert doc1.bom.metadata.component.version == doc2.bom.metadata.component.version
    assert doc1.bom.metadata.component.type == doc2.bom.metadata.component.type
    assert doc1.bom.metadata.component.version == doc2.bom.metadata.component.version
    assert doc1.bom.metadata.component.publisher == doc2.bom.metadata.component.publisher
    assert doc1.bom.metadata.component.hashes == doc2.bom.metadata.component.hashes
    assert doc1.bom.metadata.component.cpe == doc2.bom.metadata.component.cpe
    assert doc1.bom.metadata.component.properties == doc2.bom.metadata.component.properties
    assert doc1.bom.metadata.component.licenses == doc2.bom.metadata.component.licenses
    assert doc1.bom.metadata.component.description == doc2.bom.metadata.component.description

    assert doc1.bom.metadata.component == doc2.bom.metadata.component

    assert doc1.bom.dependencies == doc2.bom.dependencies
    assert doc1.bom.vulnerabilities == doc2.bom.vulnerabilities
    assert doc1.bom.properties == doc2.bom.properties
    assert doc1.bom.definitions == doc2.bom.definitions
    assert doc1.bom.services == doc2.bom.services
    assert doc1.bom.external_references == doc2.bom.external_references
    assert doc1.bom.serial_number == doc2.bom.serial_number
    assert doc1.bom.version == doc2.bom.version
    assert doc1.bom.components == doc2.bom.components
    assert doc1.bom.metadata == doc2.bom.metadata

    assert doc1.formatter == doc2.formatter
    assert doc1.bom == doc2.bom

    ### NOTE: We can't use Bom.__eq__() directly
    assert doc1 == doc2


@pytest.fixture
def cdx_document_json_instance() -> CDXDocument:
    return CDXDocument(
    bom=TESTED_BOM,
    formatter=CDXFormatter(OutputFormat.JSON),
)
@pytest.fixture
def cdx_document_xml_instance() -> CDXDocument:
    return CDXDocument(
    bom=TESTED_BOM,
    formatter=CDXFormatter(OutputFormat.XML),
)
def test_document_write(
        tmp_path,
        cdx_document_json_instance,
        cdx_document_xml_instance
    ) -> None:
    json_output_file = tmp_path / 'output.json.txt'
    xml_output_file = tmp_path / 'output.xml.txt'
    cdx_document_json_instance.write(json_output_file)
    cdx_document_xml_instance.write(xml_output_file)
    assert json_output_file.exists()
    assert xml_output_file.exists()
    assert json_output_file.read_text(encoding='utf-8') == EXPECTED_JSON_OUTPUT
    assert xml_output_file.read_text(encoding='utf-8') == EXPECTED_XML_OUTPUT
