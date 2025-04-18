import requests
from logging import getLogger
from typing import ClassVar, Iterator

from alma_sbom.data import Build
from alma_sbom.data.attributes.property import BuildPropertiesForBuild as BuildProperties

_logger = getLogger(__name__)

class AlbsCollector:
    albs_url: str
    package_hash_list: list[str]

    def __init__(self, albs_url) -> None:
        self.albs_url = albs_url
        self.package_hash_list = None

    def collect_build_by_id(self, build_id: str) -> Build:
        build_info = self._extract_build_info_by_id(build_id)
        if build_id != str(build_info['id']):
            raise RuntimeError(
                'Unexpected situation has occurred. '
                'build_id retrieved from albs differs provided build_id. '
                f'provided build_id: {build_id}, '
                f"build_id retrieved from albs: {str(build_info['id'])}"
            )
        build = Build(
            build_id = build_id,
            author = f"{build_info['owner']['username']} <{build_info['owner']['email']}>",
            build_properties = self._make_BuildProperties_from_build_info(build_info),
        )

        self.package_hash_list = list()
        for task in build_info['tasks']:
            for artifact in task['artifacts']:
                if artifact['type'] != 'rpm':
                    continue
                self.package_hash_list.append(artifact['cas_hash'])

        return build

    def iter_package_hash(self) -> Iterator[str]:
        try:
            for pkg_hash in self.package_hash_list:
                yield pkg_hash
        except TypeError as e:
            raise RuntimeError(
                'Unexpected situation has occurred. '
                'You need to call AlbsCollector.collect_build_by_id() '
                'prior to call AlbsCollector.iter_package_hash()'
            )

    def _extract_build_info_by_id(self, build_id: str) -> dict:
        response = requests.get(
            url=f'{self._get_albs_builds_endpoint()}/{build_id}',
        )
        response.raise_for_status()
        return response.json()

    def _make_BuildProperties_from_build_info(self, build_info: dict) -> BuildProperties:
        return BuildProperties(
            build_id = str(build_info['id']),
            build_url = f"{self._get_build_base_url()}/{build_info['id']}",
            timestamp = build_info['created_at'],
        )

    def _get_albs_builds_endpoint(self) -> str:
        return f'{self.albs_url}/api/v1/builds'

    def _get_build_base_url(self) -> str:
        return f'{self.albs_url}/build'

