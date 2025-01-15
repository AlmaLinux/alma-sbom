import requests
from logging import getLogger
from typing import Union, ClassVar

from alma_sbom.data import Package, Build, PackageNevra
from alma_sbom.data.attributes.property import BuildProperties

_logger = getLogger(__name__)

class AlbsCollector:
    ### TODO:
    # need to rethink where to declared
    DEF_ALBS_URL: ClassVar[str] = 'https://build.almalinux.org'

    albs_url: str
    ### TODO:
    # Think that Should we set build_id as a instance variable
    # build_id: str

    def __init__(self, albs_url: str = None) -> None:
        self.albs_url = albs_url or AlbsCollector.DEF_ALBS_URL

    def collect_build_by_id(self, build_id: str) -> Union[Build, list[str]]:
        build_info = self._extract_build_info_by_id(build_id)
        if build_id != str(build_info['id']):
            raise RuntimeError('Unexpected situation has occurred')
        build = Build(
            build_id = build_id,
            author = f"{build_info['owner']['username']} <{build_info['owner']['email']}>",
            build_properties = self._make_BuildProperties_from_build_info(build_info),
        )

        package_hash_list = list()
        for task in build_info['tasks']:
            for artifact in task['artifacts']:
                if artifact['type'] != 'rpm':
                    continue
                package_hash_list.append(artifact['cas_hash'])

        return build, package_hash_list

    def _extract_build_info_by_id(self, build_id: str) -> dict:
        response = requests.get(
            url=f'{self._get_albs_builds_endpoint()}/{build_id}',
        )
        response.raise_for_status()
        return response.json()

    def _make_BuildProperties_from_build_info(self, build_info: dict) -> BuildProperties:
        return BuildProperties(
            target_arch = None,
            package_type = None,
            build_id = str(build_info['id']),
            build_url = f"{self._get_build_base_url()}/{build_info['id']}",
            author = None,
            source = None,
            ##### There is no timestamp field in BuildProperties
            # timestamp = .......
        )

    def _get_albs_builds_endpoint(self) -> str:
        return f'{self.albs_url}/api/v1/builds'

    def _get_build_base_url(self) -> str:
        return f'{self.albs_url}/build'

