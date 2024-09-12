#!/usr/bin/env python3
# -*- mode:python; coding:utf-8; -*-

import argparse
import dataclasses
import os
import sys
import contextlib
import rpm
from logging import basicConfig, getLogger, DEBUG, INFO, WARNING
from collections import defaultdict
from typing import Dict, List, Literal, Optional, Tuple

import requests
from immudb_wrapper import ImmudbWrapper

from libsbom import cyclonedx as alma_cyclonedx
from libsbom import spdx as alma_spdx
from libsbom import common

ALBS_URL = 'https://build.almalinux.org'
IS_SIGNED = 3


_logger = getLogger('alma-sbom')


@dataclasses.dataclass
class PackageNevra:
    name: str = None
    epoch: str = None
    version: str = None
    release: str = None
    arch: str = None

    def __repr__(self):
        if self.epoch is not None:
            return (
                f'{self.epoch}:{self.name}-'
                f'{self.version}-{self.release}.{self.arch}'
            )
        return f'{self.name}-{self.version}-' f'{self.release}.{self.arch}'


@dataclasses.dataclass
class FileFormat:
    sbom_record_type: Literal[
        'cyclonedx',
        'spdx',
    ] = 'cyclonedx'
    file_format: Literal[
        'json',
        'tagvalue',
        'xml',
        'yaml',
    ] = 'json'

    def __repr__(self):
        return f'"{self.sbom_record_type}-{self.file_format}"'


class FileFormatType:
    supported_file_formats = defaultdict(
        list,
        **{
            'cyclonedx': [
                'json',
                'xml',
            ],
            'spdx': [
                'json',
                'tagvalue',
                'xml',
                'yaml',
            ],
        },
    )

    def __call__(self, sbom_type_file_format: str) -> FileFormat:
        sbom_record_type, file_format = sbom_type_file_format.split('-')
        if sbom_record_type not in self.supported_file_formats:
            _logger.error('The utility doesn\'t support that SBOM type yet')
            sys.exit(1)
        if file_format not in self.supported_file_formats[sbom_record_type]:
            _logger.error('The utility doesn\'t support that file format yet')
            sys.exit(1)
        return FileFormat(
            sbom_record_type=sbom_record_type,
            file_format=file_format,
        )

    @classmethod
    def choices(cls) -> List[FileFormat]:
        return [
            FileFormat(sbom_record_type, file_format)
            for sbom_record_type in cls.supported_file_formats
            for file_format in cls.supported_file_formats[sbom_record_type]
        ]


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


def _extract_immudb_info_about_package(
    immudb_wrapper: ImmudbWrapper,
    immudb_hash: str = None,
    rpm_package: str = None,
) -> Dict:
    if immudb_hash != None :
        response = immudb_wrapper.authenticate(immudb_hash)
    elif rpm_package != None :
        if not os.path.exists(rpm_package):
            _logger.error(f'File {rpm_package} Not Found')
            sys.exit(1)
        response = immudb_wrapper.authenticate_file(rpm_package)
    result = response.get('value', {})
    result['timestamp'] = response.get('timestamp')
    return result


def _get_specific_info_about_package(
    immudb_info_about_package: Dict,
) -> Tuple[Optional[str], PackageNevra]:
    immudb_metadata = immudb_info_about_package['Metadata']
    # We have `sbom_api_ver` in git records and `sbom_api`
    # in RPM package records. The latter parameter is the bug,
    # but we should handle it anyway
    # since a lot of packages already have it.
    api_ver = immudb_metadata.get('sbom_api_ver')
    if not api_ver:
        api_ver = immudb_metadata.get('sbom_api')
    if not api_ver:
        raise ValueError(
            'Immudb metadata is malformed, API version cannot be detected'
        )
    if api_ver == '0.1':
        package_name = immudb_info_about_package['Name']
        package_nevra = split_name_of_package_by_nevra(package_name)
        source_rpm = None
    else:
        package_nevra = PackageNevra(
            name=immudb_metadata['name'],
            epoch=immudb_metadata['epoch'],
            version=immudb_metadata['version'],
            release=immudb_metadata['release'],
            arch=immudb_metadata['arch'],
        )
        source_rpm = immudb_metadata['sourcerpm']
    return source_rpm, package_nevra


def _generate_cpe(package_nevra: PackageNevra) -> str:
    # https://github.com/AlmaLinux/build-system-rfes/commit/e4e6e655ecd09796e539fc6bc4665a55b047e49d
    cpe_version = '2.3'

    cpe_epoch_part = f'{package_nevra.epoch if package_nevra.epoch else ""}'
    cpe_epoch_part += '\\:' if cpe_epoch_part else ""
    cpe = (
        f'cpe:{cpe_version}:a:almalinux:'
        f'{package_nevra.name}:{cpe_epoch_part}'
        f'{package_nevra.version}-{package_nevra.release}:*:*:*:*:*:*:*'
    )
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
    purl = (
        f'pkg:rpm/almalinux/{package_nevra.name}@{package_nevra.version}-'
        f'{package_nevra.release}?arch={package_nevra.arch}'
        f'{purl_epoch_part}{purl_upstream_part}'
    )
    return purl


def _add_package_build_info(immudb_metadata: Dict, component: Dict, albs_url: str = None, build_url: str = None):
    component['properties'].extend(
        [
            {
                'name': 'almalinux:package:buildhost',
                'value': immudb_metadata['build_host'],
            },
            {
                'name': 'almalinux:albs:build:targetArch',
                'value': immudb_metadata['build_arch'],
            },
            {
                'name': 'almalinux:albs:build:ID',
                'value': immudb_metadata['build_id'],
            },
            {
                'name': 'almalinux:albs:build:URL',
                'value': build_url or f'{albs_url}/build/{immudb_metadata["build_id"]}',
            },
            {
                'name': 'almalinux:albs:build:author',
                'value': immudb_metadata['built_by'],
            },
        ]
    )

def _add_package_source_info(immudb_metadata: Dict, component: Dict):
    if immudb_metadata['source_type'] == 'git':
        component['properties'].extend(
            [
                {
                    'name': 'almalinux:albs:build:source:gitURL',
                    'value': immudb_metadata['git_url'],
                },
                {
                    'name': 'almalinux:albs:build:source:type',
                    'value': 'git',
                },
                {
                    'name': 'almalinux:albs:build:source:gitCommit',
                    'value': immudb_metadata['git_commit'],
                },
                {
                    'name': 'almalinux:albs:build:source:gitRef',
                    'value': immudb_metadata['git_ref'],
                },
                {
                    'name': 'almalinux:albs:build:source:gitCommitImmudbHash',
                    'value': immudb_metadata['alma_commit_sbom_hash']
                    if 'alma_commit_sbom_hash' in immudb_metadata
                    else None,
                },
            ]
        )
    elif immudb_metadata['source_type'] == 'srpm':
        component['properties'].extend(
            [
                {
                    'name': 'almalinux:albs:build:source:srpmURL',
                    'value': immudb_metadata['srpm_url'],
                },
                {
                    'name': 'almalinux:albs:build:source:type',
                    'value': 'srpm',
                },
                {
                    'name': 'almalinux:albs:build:source:srpmChecksum',
                    'value': immudb_metadata['srpm_sha256'],
                },
                {
                    'name': 'almalinux:albs:build:source:srpmNEVRA',
                    'value': immudb_metadata['srpm_nevra'],
                },
            ]
        )

def _get_each_package_component(
    immudb_info_about_package: Dict,
    albs_url: str,
    build_url: str = None,
    immudb_hash: str = None,
    rpm_package: str = None,
):
    result = {}
    source_rpm, package_nevra = _get_specific_info_about_package(
        immudb_info_about_package=immudb_info_about_package,
    )
    immudb_hash = immudb_hash or immudb_info_about_package['Hash']
    immudb_metadata = immudb_info_about_package['Metadata']
    result = {
        'name': package_nevra.name,
        'version': (
            f'{package_nevra.epoch if package_nevra.epoch else ""}'
            f'{":" if package_nevra.epoch else ""}'
            f'{package_nevra.version}-{package_nevra.release}'
        ),
        'cpe': _generate_cpe(package_nevra=package_nevra),
        'purl': _generate_purl(
            package_nevra=package_nevra,
            source_rpm=source_rpm,
        ),
        'hashes': [
            {
                'alg': 'SHA-256',
                'content': immudb_hash,
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
                'name': 'almalinux:package:timestamp',
                'value': immudb_info_about_package['timestamp'],
            },
            {
                'name': 'almalinux:albs:build:packageType',
                'value': 'rpm',
            },
            {
                'name': 'almalinux:sbom:immudbHash',
                'value': immudb_hash,
            },
        ],
    }

    build_info_fields = ['build_host', 'build_arch', 'build_id', 'built_by']
    is_build_info, missing_fields = common.check_required_data(immudb_metadata, build_info_fields)
    if is_build_info:
        _add_package_build_info(
            immudb_metadata=immudb_metadata,
            component=result,
            albs_url=albs_url,
            build_url=build_url
        )
    else:
        _logger.warning(f'build info are lacking.')

    if 'source_type' in immudb_metadata:
        _add_package_source_info(
            immudb_metadata=immudb_metadata,
            component=result,
        )
    else:
        _logger.warning(f'source info are lacking.')

    return result

def comp_package_info(
    immudb_info_about_package: Dict,
    rpm_package: str = None,
):
    ts = None
    if not rpm_package:
        pass
    else:
        ts = rpm.TransactionSet()
        try:
            fd = os.open(rpm_package, os.O_RDONLY)
            hdr = ts.hdrFromFdno(fd)
        except OSError as e:
            raise RuntimeError(f'File open error: {e.strerror}') from e
        except rpm.error as e:
            raise RuntimeError(f'RPM error: {str(e)}') from e
        finally:
            if fd is not None:
                with contextlib.suppress(Exception):
                    os.close(fd)

    if 'Hash' not in immudb_info_about_package:
        if rpm_package is not None:
            immudb_info_about_package['Hash'] = ImmudbWrapper.hash_file(self=ImmudbWrapper, file_path=rpm_package)
        else:
            raise ValueError('Cannot get required package info from immudb or The data is lacking. Cannot make SBOM.')

    immudb_metadata = immudb_info_about_package['Metadata'] if 'Metadata' in immudb_info_about_package else {}
    if immudb_metadata == {}: # There isn't metadata on immudb
        immudb_metadata['sbom_api'] = '0.0'

    required_fields = ['name', 'epoch', 'version', 'release', 'arch', 'sourcerpm']
    dict_field_rpmtag = {
        'name': rpm.RPMTAG_NAME,
        'epoch': rpm.RPMTAG_EPOCH,
        'version': rpm.RPMTAG_VERSION,
        'release': rpm.RPMTAG_RELEASE,
        'arch': rpm.RPMTAG_ARCH,
        'sourcerpm': rpm.RPMTAG_SOURCERPM,
    }
    is_required_data, missing_fields = common.check_required_data(immudb_metadata, required_fields)
    if not is_required_data:
        _logger.warning('Required data are missing')
        _logger.debug(f'missing_required_field: {missing_fields}')
        if ts is None:
            raise ValueError('Cannot get required package info from immudb or The data is lacking.')
        else:
            _logger.warning('Complete the data from the RPM package information.')
            for field in missing_fields:
                _logger.debug(f'Complete {field}-field with {hdr[dict_field_rpmtag[field]]}')
                immudb_metadata[field] = hdr[dict_field_rpmtag[field]]
    ### NOTE
    ### There are little bit difference of buildtime between immudb_metadata & rpm_package.
    ### So, now we don't set buildtime using rpm_package info.
    ### According to the specifications of extractimmudb_info_about_package, even if there is no timestamp
    ### info in immudb, None will be stored.
    ### Or, We should set it anymore? because whenever this code is executed, immudb_metadata is None or lacking.
    ### If you want do this, uncomment below block.
    # if 'timestamp' not in immudb_info_about_package or immudb_info_about_package['timestamp'] is None:
    #     immudb_info_about_package['timestamp'] = hdr[rpm.RPMTAG_BUILDTIME]

    immudb_info_about_package['Metadata'] = immudb_metadata

def get_info_about_package(
    albs_url: str,
    immudb_wrapper: ImmudbWrapper,
    immudb_hash: str = None,
    rpm_package: str = None,
):
    result = {}

    immudb_info_about_package = _extract_immudb_info_about_package(
        immudb_wrapper=immudb_wrapper,
        immudb_hash=immudb_hash,
        rpm_package=rpm_package,
    )
    comp_package_info(
        immudb_info_about_package=immudb_info_about_package,
        rpm_package=rpm_package,
    )
    immudb_metadata = immudb_info_about_package['Metadata']
    result['version'] = 1
    if 'unsigned_hash' in immudb_metadata:
        result['version'] += 1
    result['metadata'] = {}

    result['metadata']['component'] = _get_each_package_component(
        immudb_info_about_package=immudb_info_about_package,
        albs_url = albs_url,
        immudb_hash=immudb_hash,
        rpm_package=rpm_package,
    )

    return result


def get_info_about_build(
    build_id: int,
    albs_url: str,
    immudb_wrapper: ImmudbWrapper,
):
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
            },
        ],
    }
    result['metadata'] = {}
    result['metadata']['component'] = build_metadata
    components = []
    for task in json_data['tasks']:
        for artifact in task['artifacts']:
            if artifact['type'] != 'rpm':
                continue
            immudb_hash = artifact['cas_hash']

            immudb_info_about_package = _extract_immudb_info_about_package(
                immudb_wrapper=immudb_wrapper,
                immudb_hash=immudb_hash,
            )
            comp_package_info(
                immudb_info_about_package=immudb_info_about_package,
            )

            component = _get_each_package_component(
                immudb_info_about_package=immudb_info_about_package,
                albs_url = albs_url,
                build_url = build_url,
                immudb_hash=immudb_hash,
                rpm_package=rpm_package,
            )
            components.append(component)
    result['components'] = components
    return result


def _proc_opt_creators(
    persons_name: list,
    persons_email: list,
    orgs_name: list,
    orgs_email: list,
):
    creators_person = {
        'name': persons_name,
        'email': persons_email,
    }
    creators_org = {
        'name': orgs_name,
        'email': orgs_email,
    }
    opt_creators = {
        'creators_person': creators_person,
        'creators_org': creators_org,
    }
    return opt_creators


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
        default=FileFormat(),
        const=FileFormat(),
        nargs='?',
        choices=FileFormatType.choices(),
        type=FileFormatType(),
        help='Generate SBOM in one of format mode (default: %(default)s)',
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
    object_id_group.add_argument(
        '--rpm-package',
        type=str,
        help='path to an RPM package',
    )
    parser.add_argument(
        '--albs-url',
        type=str,
        help='Override ALBS url',
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
    formatters = {
        'cyclonedx': alma_cyclonedx.SBOM,
        'spdx': alma_spdx.SBOM,
    }

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
    albs_url = args.albs_url or ALBS_URL
    if args.build_id:
        sbom = get_info_about_build(
            args.build_id,
            albs_url=albs_url,
            immudb_wrapper=immudb_wrapper,
        )
        sbom_object_type = 'build'
    else:
        sbom = get_info_about_package(
            albs_url=albs_url,
            immudb_wrapper=immudb_wrapper,
            immudb_hash=args.rpm_package_hash,
            rpm_package=args.rpm_package,
        )
        sbom_object_type = 'package'
    opt_creators = _proc_opt_creators(
        args.creator_name_person,
        args.creator_email_person,
        args.creator_name_org,
        args.creator_email_org
    )

    sbom_formatter = formatters[args.file_format.sbom_record_type](
        data=sbom,
        sbom_object_type=sbom_object_type,
        output_format=args.file_format.file_format,
        output_file=args.output_file,
        opt_creators=opt_creators,
    )

    sbom_formatter.run()


if __name__ == '__main__':
    cli_main()
