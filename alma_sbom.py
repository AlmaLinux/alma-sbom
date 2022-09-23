#!/usr/bin/env python3
# -*- mode:python; coding:utf-8; -*-


import argparse
import json
from typing import Dict, Tuple, Optional

import dataclasses
from collections import defaultdict

import requests
import logging
import sys
from plumbum import local

from libsbom import cyclonedx as alma_cyclonedx

ALBS_URL = 'https://build.almalinux.org'
SIGNER_ID = 'cloud-infra@almalinux.org'
SBOM_TYPES = [
    'cyclonedx',
    'spdx',
]
SUPPORTED_SBOM_TYPES = [
    'cyclonedx',
]
FILE_FORMATS = [
    'json',
    'xml',
]
SUPPORTED_FILE_FORMATS = defaultdict(list, **{
    'cyclonedx': [
        'json',
        'xml',
    ]
})
IS_SIGNED = 3


logging.basicConfig(level=logging.INFO)


@dataclasses.dataclass
class PackageNevra:
    name: str = None
    epoch: str = None
    version: str = None
    release: str = None
    arch: str = None


def split_name_of_package_by_nevra(package_name: str) -> PackageNevra:
    package_nevra = PackageNevra()

    split_by_dot = package_name.replace('.rpm', '')[::-1].split('.', 1)
    package_nevra.arch = split_by_dot[0][::-1]
    split_by_hyphen = split_by_dot[1].split('-', 2)
    package_nevra.release = split_by_hyphen[0][::-1]
    package_nevra.version = split_by_hyphen[1][::-1]
    package_nevra.name = split_by_hyphen[2][::-1]

    return package_nevra


def generate_sbom_version(json_data: Dict) -> int:
    sbom_version = 1
    if json_data['sign_tasks'] and 'status' in json_data['sign_tasks'][-1]:
        sbom_version += json_data['sign_tasks'][-1]['status'] == IS_SIGNED
    return sbom_version


def _extract_cas_info_about_package(cas_hash: str, signer_id: str):
    def _convert_none_string_to_none(obj: Dict):
        for key, value in obj.items():
            if isinstance(value, dict):
                obj[key] = _convert_none_string_to_none(obj=value)
            if value == 'None':
                obj[key] = None
        return obj

    # TODO: Use cas_wrapper instead of dealing directly with cas
    command = local['cas'][
        'authenticate',
        '--signerID',
        signer_id,
        '--output',
        'json',
        '--hash',
        cas_hash,
    ]
    logging.info(command)
    result = json.loads(command())
    return _convert_none_string_to_none(result)


def _get_specific_info_about_package(
        cas_info_about_package: Dict
) -> Tuple[Optional[str], PackageNevra]:
    cas_metadata = cas_info_about_package['metadata']
    if cas_metadata['sbom_api'] == '0.1':
        package_name = cas_info_about_package['name']
        package_nevra = split_name_of_package_by_nevra(package_name)
        source_rpm = None
    else:
        package_nevra = PackageNevra(
            name=cas_metadata['name'],
            epoch=cas_metadata['epoch'],
            version=cas_metadata['version'],
            release=cas_metadata['release'],
            arch=cas_metadata['arch'],
        )
        source_rpm = cas_metadata['sourcerpm']
    return source_rpm, package_nevra


def _generate_cpe(package_nevra: PackageNevra) -> str:
    # https://github.com/AlmaLinux/build-system-rfes/commit/e4e6e655ecd09796e539fc6bc4665a55b047e49d
    cpe_version = '2.3'

    cpe_epoch_part = f'{package_nevra.epoch if package_nevra.epoch else ""}'
    cpe_epoch_part += '\\:' if cpe_epoch_part else ""
    cpe = f'cpe:{cpe_version}:a:almalinux:' \
          f'{package_nevra.name}:{cpe_epoch_part}' \
          f'{package_nevra.version}-{package_nevra.release}:*:*:*:*:*:*:*'
    return cpe


def _generate_purl(package_nevra: PackageNevra, source_rpm: str):
    # https://github.com/AlmaLinux/build-system-rfes/commit/a132ececa1d7901fe42348022ce954d475578920
    if package_nevra.epoch:
        purl_epoch_part = f'&epoch={package_nevra.epoch}'
    else:
        purl_epoch_part = ''
    if source_rpm:
        purl_upstream_part = f'&upstream={source_rpm}'
    else:
        purl_upstream_part = ''
    purl = f'pkg:rpm/almalinux/{package_nevra.name}@{package_nevra.version}-' \
           f'{package_nevra.release}?arch={package_nevra.arch}' \
           f'{purl_epoch_part}{purl_upstream_part}'
    return purl


def get_info_about_package(cas_hash: str, signer_id: str, albs_url: str):
    result = {}
    cas_info_about_package = _extract_cas_info_about_package(
        cas_hash=cas_hash,
        signer_id=signer_id,
    )
    source_rpm, package_nevra = _get_specific_info_about_package(
        cas_info_about_package=cas_info_about_package,
    )
    cas_metadata = cas_info_about_package['metadata']
    result['version'] = 1
    if 'unsigned_hash' in cas_metadata:
        result['version'] += 1
    result['component'] = {
        'name': package_nevra.name,
        'version': f'{package_nevra.epoch if package_nevra.epoch else ""}'
                   f'{":" if package_nevra.epoch else ""}'
                   f'{package_nevra.version}-{package_nevra.release}',
        'hashes': [
            {
                'alg': 'SHA-256',
                'content': cas_hash,
            }
        ],
        'cpe': _generate_cpe(package_nevra=package_nevra),
        'purl': _generate_purl(
            package_nevra=package_nevra,
            source_rpm=source_rpm,
        ),
        'properties': [
            {
                'name': 'almalinux:package:epoch',
                'value': package_nevra.epoch,
            },
            {
                'name': 'almalinux:package:version',
                'value': package_nevra.version,
            },
            {
                'name': 'almalinux:package:release',
                'value': package_nevra.release,
            },
            {
                'name': 'almalinux:package:arch',
                'value': package_nevra.arch,
            },
            {
                'name': 'almalinux:package:sourcerpm',
                'value': source_rpm,
            },
            {
                'name': 'almalinux:package:buildhost',
                'value': cas_metadata['build_host'],
            },
            {
                'name': 'almalinux:package:timestamp',
                'value': cas_info_about_package['timestamp'],
            },
            {
                'name': 'almalinux:albs:build:targetArch',
                'value': cas_metadata['build_arch'],
            },
            {
                'name': 'almalinux:albs:build:packageType',
                'value': 'rpm',
            },
            {
                'name': 'almalinux:sbom:cashHash',
                'value': cas_hash,
            },
            {
                'name': 'almalinux:albs:build:ID',
                'value': cas_metadata['build_id'],
            },
            {
                'name': 'almalinux:albs:build:URL',
                'value': f'{albs_url}/build/{cas_metadata["build_id"]}',
            },
            {
                'name': 'almalinux:albs:build:author',
                'value': cas_metadata['built_by'],
            },
        ]
    }

    return result


def get_info_about_build(build_id: int, signer_id: str, albs_url: str):
    result = {}
    albs_builds_endpoint = f'{albs_url}/api/v1/builds'
    response = requests.get(
        url=f'{albs_builds_endpoint}/{build_id}',
    )
    response.raise_for_status()
    json_data = response.json()
    result['version'] = generate_sbom_version(json_data)
    owner = json_data['owner']
    build_url = f'{albs_url}/build/{build_id}'
    build_metadata = {
        'name': f'build-{build_id}',
        'author': f"{owner['username']} <{owner['email']}>",
        'properties': [
            {
                'name': 'almalinux:albs:build:ID',
                'value': build_id,
            },
            {
                'name': 'almalinux:albs:build:URL',
                'value': build_url,
            },
            {
                'name': 'almalinux:albs:build:timestamp',
                'value': json_data['created_at'],
            }
        ]
    }
    result['metadata'] = build_metadata
    components = []
    for task in json_data['tasks']:
        for artifact in task['artifacts']:
            if artifact['type'] != 'rpm':
                continue
            cas_hash = artifact['cas_hash']
            result_of_execution = _extract_cas_info_about_package(
                cas_hash=cas_hash,
                signer_id=signer_id,
            )
            cas_metadata = result_of_execution['metadata']
            source_rpm, package_nevra = _get_specific_info_about_package(
                cas_info_about_package=result_of_execution,
            )
            component = {
                'name': package_nevra.name,
                'version': package_nevra.version,
                'cpe': _generate_cpe(package_nevra=package_nevra),
                'purl': _generate_purl(
                    package_nevra=package_nevra,
                    source_rpm=source_rpm,
                ),
                'hashes': [
                    {
                        'alg': 'SHA-256',
                        'content': cas_hash,
                    }
                ],
                'properties': [
                    {
                        'name': 'almalinux:package:epoch',
                        'value': package_nevra.epoch,
                    },
                    {
                        'name': 'almalinux:package:version',
                        'value': package_nevra.version,
                    },
                    {
                        'name': 'almalinux:package:release',
                        'value': package_nevra.release,
                    },
                    {
                        'name': 'almalinux:package:arch',
                        'value': package_nevra.arch,
                    },
                    {
                        'name': 'almalinux:package:sourcerpm',
                        'value': source_rpm,
                    },
                    {
                        'name': 'almalinux:package:buildhost',
                        'value': cas_metadata['build_host'],
                    },
                    {
                        'name': 'almalinux:abls:build:targetArch',
                        'value': cas_metadata['build_arch'],
                    },
                    {
                        'name': 'almalinux:abls:build:packageType',
                        'value': 'rpm',
                    },
                    {
                        'name': 'almalinux:sbom:casHash',
                        'value': result_of_execution['hash'],
                    },
                    {
                        'name': 'almalinux:albs:build:ID',
                        'value': build_id,
                    },
                    {
                        'name': 'almalinux:albs:build:URL',
                        'value': build_url,
                    },
                    {
                        'name': 'almalinux:albs:build:author',
                        'value': cas_metadata['built_by'],
                    },
                ]
            }
            if cas_metadata['source_type'] == 'git':
                component['properties'].extend([
                    {
                        'name': 'almalinux:albs:build:source:gitURL',
                        'value': cas_metadata['git_url'],
                    },
                    {
                        'name': 'almalinux:albs:build:source:type',
                        'value': 'git',
                    },
                    {
                        'name': 'almalinux:albs:build:source:gitCommit',
                        'value': cas_metadata['git_commit'],
                    },
                    {
                        'name': 'almalinux:albs:build:source:gitRef',
                        'value': cas_metadata['git_ref'],
                    },
                    {
                        'name': 'almalinux:albs:build:source:gitCommitCasHash',
                        'value': cas_metadata['alma_commit_sbom_hash'],
                    }
                ])
            elif cas_metadata['source_type'] == 'srpm':
                component['properties'].extend([
                    {
                        'name': 'almalinux:albs:build:source:srpmURL',
                        'value': cas_metadata['srpm_url'],
                    },
                    {
                        'name': 'almalinux:albs:build:source:type',
                        'value': 'srpm',
                    },
                    {
                        'name': 'almalinux:albs:build:source:srpmChecksum',
                        'value': cas_metadata['srpm_sha256'],
                    },
                    {
                        'name': 'almalinux:albs:build:source:srpmNEVRA',
                        'value': cas_metadata['srpm_nevra'],
                    },
                ])
            components.append(component)
    result['components'] = components
    return result


def create_parser():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--output-file',
        type=str,
        help='Full path to an output file with SBOM',
        required=False,
        default=None,
    )
    parser.add_argument(
        '--sbom-type',
        default=SBOM_TYPES[0],
        const=SBOM_TYPES[0],
        nargs='?',
        choices=SBOM_TYPES,
        help='Generate SBOM in one of format type (default: "%(default)s")',
    )
    parser.add_argument(
        '--file-format',
        default=FILE_FORMATS[0],
        const=FILE_FORMATS[0],
        nargs='?',
        choices=FILE_FORMATS,
        help='Generate SBOM in one of format mode (default: "%(default)s")',
    )
    object_id_group = parser.add_mutually_exclusive_group(required=True)
    object_id_group.add_argument(
        '--build-id',
        type=int,
        help='UID of a build from AlmaLinux Build System',
    )
    object_id_group.add_argument(
        '--rpm-package-hash',
        type=str,
        help='SHA256 hash of an RPM package',
    )
    parser.add_argument(
        '--signer-id',
        type=str,
        help='Override signerID',
    )
    parser.add_argument(
        '--albs-url',
        type=str,
        help='Override ALBS url',
    )

    return parser


def cli_main():

    args = create_parser().parse_args()
    if args.sbom_type not in SUPPORTED_SBOM_TYPES:
        logging.error('The utility doesn\'t support that format type yet')
        sys.exit(1)
    if args.file_format not in SUPPORTED_FILE_FORMATS[args.sbom_type]:
        logging.error('The utility doesn\'t support that format mode yet')
        sys.exit(1)
    signer_id = args.signer_id or SIGNER_ID
    albs_url = args.albs_url or ALBS_URL
    if args.build_id:
        sbom = get_info_about_build(
            args.build_id,
            signer_id=signer_id,
            albs_url=albs_url,
        )
        sbom_type = 'build'
    else:
        sbom = get_info_about_package(
            args.rpm_package_hash,
            signer_id=signer_id,
            albs_url=albs_url,
        )
        sbom_type = 'package'

    # TODO: For now we only support CycloneDX
    # We should revisit this when adding SPDX
    sbom_formatter = alma_cyclonedx.SBOM(
        data=sbom,
        sbom_type=sbom_type,
        output_format=args.file_format,
        output_file=args.output_file)

    sbom_formatter.run()

if __name__ == '__main__':
    cli_main()
