# Script that generates a document similar to the specs here:
# https://github.com/AlmaLinux/build-system-rfes/blob/sbom_draft/SBOM/SBOM.md#build-system-build-sbom-data-record

import json
import os
import plumbum
import sys
import uuid

from datetime import datetime, timezone

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
plumbum.local.env.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'alma-sbom', 'env', 'bin'))


from libsbom import cyclonedx_models as sbom

author = sbom.Author(
    name='Eugene Zamriy',
    email='ezamriy@almalinux.org'
)
print('Author: ', author)

albsTool = sbom.Tool(
    vendor='AlmaLinux OS Foundation',
    name='AlmaLinux Build System',
    version='0.1' # do we have some versioning in place?
)

# Maybe a good idea to add a staticmethod to cas_wrapper that returns the cas version?
casVersion = plumbum.local['cas']['--version']()[:-1].split(' ')[-1].replace('v', '')
casTool = sbom.Tool(
    vendor='Codenotary Inc',
    name='Community Attestation Service (CAS)',
    version=casVersion
)

sbomTools = [albsTool, casTool]
print('sbomTools: ', sbomTools)

#build system build unique identifier property
albsUUIDProp = sbom.ComponentProperty(
    name='almalinux:albs:build:ID',
    value='478'
)

# build system build URL
albsBuildUrlProp = sbom.ComponentProperty(
    name='almalinux:albs:build:URL',
    value='https://build.almalinux.org/build/478'
)

componentProperties = [albsUUIDProp, albsBuildUrlProp]
print('componentProperties: ', componentProperties)


component = sbom.Component(
    type='library',
    name='build-478',
    author=str(author),
    properties=componentProperties
)

print('component: ', component)

metadata = sbom.Metadata(
    timestamp=datetime.now().timestamp(),
    tools=sbomTools,
    component=component
)
print('metadata: ', metadata)

rpmChecksum = sbom.Checksum(
    alg='SHA-256',
    content='aeb7b7d638ebad749c8ef2ec7c8b699201e176101f129a49dcb5781158e95632'
)
print('rpmChecksum: ', rpmChecksum)

rpmComponent = sbom.RPMComponent(
    type='library',
    name='bash',
    author=str(author),
    version='4.4.20-4.el8_6',
    publisher='AlmaLinux',
    hashes=[rpmChecksum],
    cpe="TBD",
    purl="TBD",
    properties=[
        sbom.ComponentProperty(
            name='almalinux:package:epoch',
            value='1'
        ),
        sbom.ComponentProperty(
            name='almalinux:package:version',
            value='4.4.20'
        ),
        sbom.ComponentProperty(
            name='almalinux:package:release',
            value='4.el8_6'
        ),
        sbom.ComponentProperty(
            name='almalinux:package:arch',
            value='x86_64'
        ),
        sbom.ComponentProperty(
            name='almalinux:package:sourcerpm',
            value='bash-4.4.20-4.el8_6.src.rpm'
        ),
        sbom.ComponentProperty(
            name='almalinux:package:buildhost',
            value='x64-builder02.almalinux.org'
        ),
        sbom.ComponentProperty(
            name='almalinux:albs:build:targetArch',
            value='x86_64'
        ),
        sbom.ComponentProperty(
            name='almalinux:albs:build:packageType',
            value='rpm'
        ),
        sbom.ComponentProperty(
            name='almalinux:sbom:casHash',
            value='aeb7b7d638ebad749c8ef2ec7c8b699201e176101f129a49dcb5781158e95632'
        ),
        sbom.ComponentProperty(
            name='almalinux:albs:build:ID',
            value='478'
        ),
        sbom.ComponentProperty(
            name='almalinux:albs:build:URL',
            value='https://build.almalinux.org/build/478'
        ),
        sbom.ComponentProperty(
            name='almalinux:albs:build:author',
            value='Eugene Zamriy <ezamriy@almalinux.org>'
        )
    ]
)
print('rpmComponent: ', json.dumps(rpmComponent.dict()))

bsRecord = sbom.BuildRecord(
    bomFormat='CycloneDX',
    specVersion='1.4',
    serialNumber='urn:uuid:' + str(uuid.uuid4()),
    version='1',
    metadata=metadata,
    components=[rpmComponent]
)
print('bsRecord: ', json.dumps(bsRecord.dict(), indent=4))
