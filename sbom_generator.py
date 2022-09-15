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


ALBS_URL = 'https://build.almalinux.org'
SIGNER_ID = 'cloud-infra@almalinux.org'
FORMAT_TYPES = [
    'cyclonedx',
    'spdx',
]
SUPPORTED_TYPES = [
    'cyclonedx',
]
FORMAT_MODES = [
    'json',
    'xml',
]
SUPPORTED_MODES = defaultdict(list, **{
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
    return json.loads(command())


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
    result['timestamp'] = cas_info_about_package['timestamp']
    result['component'] = {
        'name': package_nevra.name,
        'version': f'{package_nevra.epoch}{":" if package_nevra.epoch else ""}'
                   f'{package_nevra.version}-{package_nevra.release}',
        'hashes': [
            {
                'alg': 'SHA-256',
                'content': cas_hash,
            }
        ],
        'cpe': 'TBD',
        'purl': 'TBD',
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
        'timestamp': json_data['created_at'],
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
                'cpe': 'TBD',
                'purl': 'TBD',
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
            components.append(component)
    result['components'] = components
    return result


def create_parser():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--output-file',
        type=str,
        help='Full path to an output file with SBOM',
        required=True,
    )
    parser.add_argument(
        '--format-type',
        default=FORMAT_TYPES[0],
        const=FORMAT_TYPES[0],
        nargs='?',
        choices=FORMAT_TYPES,
        help='Generate SBOM in one of format type (default: "%(default)s")',
    )
    parser.add_argument(
        '--format-mode',
        default=FORMAT_MODES[0],
        const=FORMAT_MODES[0],
        nargs='?',
        choices=FORMAT_MODES,
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
    if args.format_type not in SUPPORTED_TYPES:
        logging.error('The utility doesn\'t support that format type yet')
        sys.exit(1)
    if args.format_mode not in SUPPORTED_MODES[args.format_type]:
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
    else:
        sbom = get_info_about_package(
            args.rpm_package_hash,
            signer_id=signer_id,
            albs_url=albs_url,
        )
    # TODO: insert here formatter of SBOM and pass to it:
    #       sbom
    #       args.output_file
    #       args.format_type (CycloneDX or SPDX)
    #       args.format_mode (JSON or XML)
    #
    # TODO: remove it as debug line
    logging.info(json.dumps(sbom, indent=4))


if __name__ == '__main__':
    cli_main()
