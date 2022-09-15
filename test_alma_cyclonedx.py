import json
import xml.dom.minidom

from libsbom import cyclonedx

# Taken from
# https://github.com/AlmaLinux/build-system-rfes/blob/sbom_draft/SBOM/SBOM.md#build-system-build-sbom-data-record
myDict = {
    "version": 1,
    "metadata": {
        "tools": [
            {
                "vendor": "AlmaLinux OS Foundation",
                "name": "AlmaLinux Build System",
                "version": "0.1"
            },
            {
                "vendor": "Codenotary Inc",
                "name": "Community Attestation Service (CAS)",
                "version": "1.0.0"
            }
        ],
        "component": {
            "type": "library",
            "name": "build-478",
            "author": "Eugene Zamriy <ezamriy@almalinux.org>",
            "properties": [
                {
                    "name": "almalinux:albs:build:ID",
                    "value": "478"
                },
                {
                    "name": "almalinux:albs:build:URL",
                    "value": "https://build.almalinux.org/build/478"
                }
            ]
        }
    },
    "components": [
        {
            "type": "library",
            "name": "bash",
            "properties": [
                {
                    "name": "almalinux:package:epoch",
                    "value": "1"
                },
                {
                    "name": "almalinux:package:version",
                    "value": "4.4.20"
                },
                {
                    "name": "almalinux:package:release",
                    "value": "4.el8_6"
                },
                {
                    "name": "almalinux:package:arch",
                    "value": "x86_64"
                },
                {
                    "name": "almalinux:package:sourcerpm",
                    "value": "bash-4.4.20-4.el8_6.src.rpm"
                },
                {
                    "name": "almalinux:package:buildhost",
                    "value": "x64-builder02.almalinux.org"
                },
                {
                    "name": "almalinux:albs:build:targetArch",
                    "value": "x86_64"
                },
                {
                    "name": "almalinux:albs:build:packageType",
                    "value": "rpm"
                },
                {
                    "name": "almalinux:sbom:casHash",
                    "value": "aeb7b7d638ebad749c8ef2ec7c8b699201e176101f129a49dcb5781158e95632"
                },
                {
                    "name": "almalinux:albs:build:ID",
                    "value": "478"
                },
                {
                    "name": "almalinux:albs:build:URL",
                    "value": "https://build.almalinux.org/build/478"
                },
                {
                    "name": "almalinux:albs:build:author",
                    "value": "Eugene Zamriy <ezamriy@almalinux.org>"
                }
            ],
            "version": "4.4.20-4.el8_6",
            "publisher": "AlmaLinux",
            "hashes": [
                {
                    "alg": "SHA-256",
                    "content": "aeb7b7d638ebad749c8ef2ec7c8b699201e176101f129a49dcb5781158e95632"
                }
            ],
            "cpe": "TBD",
            "purl": "TBD"
        }
    ]
}

bom = cyclonedx.SBOM(sbom_data=myDict)
bom.generate_sbom()

# Investigate warnings a bit more
bom.validate()

json_s = bom.to_json_string()
print(json.dumps(json.loads(json_s), indent=4))
xml_s = bom.to_xml_string()
pretty_xml= xml.dom.minidom.parseString(xml_s).toprettyxml()
print(pretty_xml)
