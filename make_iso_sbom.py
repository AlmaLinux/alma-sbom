#!/usr/bin/env python3
# -*- mode:python; coding:utf-8; -*-

import os
import sys
import collections
import pycdlib
import tempfile
import configparser
import argparse

from logging import basicConfig, getLogger, DEBUG, INFO, WARNING
from typing import Dict, List, Literal, Optional, Tuple

from immudb_wrapper import ImmudbWrapper

from libsbom import cyclonedx as alma_cyclonedx
from libsbom import spdx as alma_spdx

import alma_sbom


path_to_treeinfo = '/.treeinfo'

_logger = getLogger('alma-sbom')

def create_parser():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--output-file',
        type=str,
        help=(
            'Full path to an output file with SBOM. Output will be '
            'to stdout if the parameter is absent or emtpy'
        ),
        required=False,
        default=None,
    )
    parser.add_argument(
        '--file-format',
        default=alma_sbom.FileFormat(),
        const=alma_sbom.FileFormat(),
        nargs='?',
        choices=alma_sbom.FileFormatType.choices(),
        type=alma_sbom.FileFormatType(),
        help='Generate SBOM in one of format mode (default: %(default)s)',
    )
    object_id_group = parser.add_mutually_exclusive_group(required=True)
    object_id_group.add_argument(
        '--iso-file',
        type=str,
        help='path to ISO image',
    )
    parser.add_argument(
        '--immudb-username',
        type=str,
        help=(
            'Provide your immudb username if not set as '
            'an environmental variable'
        ),
        required=False,
    )
    parser.add_argument(
        '--immudb-password',
        type=str,
        help=(
            'Provide your immudb password if not set as '
            'an environmental variable'
        ),
        required=False,
    )
    parser.add_argument(
        '--immudb-database',
        type=str,
        help=(
            'Provide your immudb database if not set as '
            'an environmental variable'
        ),
        required=False,
    )
    parser.add_argument(
        '--immudb-address',
        type=str,
        help=(
            'Provide your immudb address if not set as '
            'an environmental variable'
        ),
        required=False,
    )
    parser.add_argument(
        '--immudb-public-key-file',
        type=str,
        help=(
            'Provide your immudb public key file if not set as '
            'an environmental variable'
        ),
        required=False,
    )
    parser.add_argument(
        '--verbose',
        help=(
            'Print verbose output'
        ),
        required=False,
        default=WARNING,
        action='store_const', dest='loglevel', const=INFO,
    )
    parser.add_argument(
        '--debug',
        help=(
            'Print debug log'
        ),
        required=False,
        action='store_const', dest='loglevel', const=DEBUG,
    )
    parser.add_argument(
        '--creator-name-person',
        type=str,
        action='append',
        help=(
            'The person(s) who create SBOM'
        ),
        required=False,
        default=[],
    )
    parser.add_argument(
        '--creator-email-person',
        type=str,
        action='append',
        help=(
            'The email address of SBOM creator. '
            'This option is only required if --creator-name-personal is provided. '
            'The combination of name and email address depends on the order specified. '
            'If an extra email address is specified, it will be ignored'
        ),
        required=False,
        default=[],
    )
    parser.add_argument(
        '--creator-name-org',
        type=str,
        action='append',
        help=(
            'The organization(s) who create SBOM'
        ),
        required=False,
        default=[],
    )
    parser.add_argument(
        '--creator-email-org',
        type=str,
        action='append',
        help=(
            'The email address of SBOM creator. '
            'This option is only required if --creator-name-org is provided. '
            'The combination of name and email address depends on the order specified. '
            'If an extra email address is specified, it will be ignored.'
        ),
        required=False,
        default=[],
    )

    return parser


def cli_main():
    fmt = '%(asctime)s %(name)s: [%(levelname)s] %(message)s'
    datefmt = '%b %d %H:%M:%S'
    basicConfig(format=fmt, datefmt=datefmt)

    args = create_parser().parse_args()

    _logger.setLevel(args.loglevel)

    immudb_wrapper = ImmudbWrapper(
        username=(
            args.immudb_username
            or os.getenv('IMMUDB_USERNAME')
            or ImmudbWrapper.read_only_username()
        ),
        password=(
            args.immudb_password
            or os.getenv('IMMUDB_PASSWORD')
            or ImmudbWrapper.read_only_password()
        ),
        database=(
            args.immudb_database
            or os.getenv('IMMUDB_DATABASE')
            or ImmudbWrapper.almalinux_database_name()
        ),
        immudb_address=(
            args.immudb_address
            or os.getenv('IMMUDB_ADDRESS')
            or ImmudbWrapper.almalinux_database_address()
        ),
        public_key_file=(
            args.immudb_public_key_file or os.getenv('IMMUDB_PUBLIC_KEY_FILE')
        ),
    )

    iso = pycdlib.PyCdlib()
    iso.open(args.iso_file)


    index = 0
    result = {}
    components = []

    # Read ISO directory structure from .treeinfo
    config = configparser.ConfigParser()
    variants = []
    variant_packages = {}
    with tempfile.NamedTemporaryFile(delete=True) as tmp:
        iso.get_file_from_iso(local_path=tmp.name, rr_path=path_to_treeinfo)
        config.read(tmp.name)
        if 'general' in config and 'family' in config['general']:
            if config['general']['family'] != 'AlmaLinux':
                _logger.error('alma-sbom only can make ISO SBOM for AlmaLinux ISO Image.')
                sys.exit(1)
        else:
            _logger.error('ISO file may be corrupted.')
            sys.exit(1)

        if 'general' in config and 'variants' in config['general']:
            variants = config['general']['variants'].split(',')
        elif 'tree' in config and 'variants' in config['tree']:
            variants = config['tree']['variants'].split(',')
        else:
            _logger.error('ISO file may be corrupted.')
            sys.exit(1)

        for variant in variants:
            section_name = f'variant-{variant}'
            if section_name in config and 'packages' in config[section_name]:
                variant_packages[variant] = config[section_name]['packages']

    if 'general' in config and 'version' in config['general']:
        iso_releasever = config['general']['version']
    else:
        _logger.error('ISO file may be corrupted.')
        sys.exit(1)

    variants_list = list(variant_packages.keys())
    if variants_list == ['AppStream', 'BaseOS']:
        iso_type = 'DVD'
    elif variants_list == ['Minimal']:
        iso_type = 'Minimal'
    else:
        _logger.error('ISO file may be corrupted.')
        sys.exit(1)


    for variant_packages_repo in variant_packages.values():
        index = 0
        variant_path = os.path.join('/', variant_packages_repo)
        variant_entry = iso.get_record(iso_path=variant_path)
        for child in variant_entry.children:
            pkg_name = child.rock_ridge.name().decode('utf8')
            print(pkg_name)
            if pkg_name.endswith('.rpm'):
                full_rr_path = os.path.join(variant_path, pkg_name)
                full_iso_path = os.path.join(
                                    variant_path,
                                    child.file_identifier().decode('utf8')
                                )
                with tempfile.NamedTemporaryFile(delete=True) as tmp:
                    iso.get_file_from_iso(local_path=tmp.name, rr_path=full_rr_path)
                    response = immudb_wrapper.authenticate_file(tmp)
                    immudb_info_about_package = response.get('value', {})
                    immudb_info_about_package['timestamp'] = response.get('timestamp')
                    immudb_hash = immudb_info_about_package['Hash']
                    component = {}
                    alma_sbom.add_package_info(
                        immudb_hash=immudb_hash,
                        immudb_info_about_package=immudb_info_about_package,
                        component=component,
                        albs_url=alma_sbom.ALBS_URL,
                    )
                    components.append(component)

    result['components'] = components

    opt_creators = alma_sbom._proc_opt_creators(
        args.creator_name_person,
        args.creator_email_person,
        args.creator_name_org,
        args.creator_email_org
    )
    sbom_formatter = alma_cyclonedx.SBOM(
        data=result,
        sbom_object_type='iso',
        output_format=args.file_format.file_format,
        output_file=args.output_file,
        opt_creators=opt_creators,
    )
    sbom_formatter.run(
        iso_releasever=iso_releasever, 
        iso_type=iso_type,
    )

    iso.close()


if __name__ == '__main__':
    cli_main()
