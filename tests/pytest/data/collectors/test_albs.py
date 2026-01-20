import pytest

from alma_sbom.data import Build
from alma_sbom.data.attributes.property import BuildPropertiesForBuild as BuildProperties
from alma_sbom.data.collectors import AlbsCollector
from alma_sbom.cli.config import CommonConfig

EXPECTED_BUILD = Build(
    build_id='11363', 
    author='eabdullin1 <55892454+eabdullin1@users.noreply.github.com>', 
    packages=[], 
    build_properties=BuildProperties(
        build_id='11363', 
        build_url='https://build.almalinux.org/build/11363', 
        timestamp='2024-04-30T14:02:23.231308'
    )
)


@pytest.fixture
def albs_collector_instance() -> AlbsCollector:
    return AlbsCollector(CommonConfig.DEF_ALBS_URL)


def test_collect_build_by_id_and_iter_package_hash(albs_collector_instance: AlbsCollector) -> None:
    build = albs_collector_instance.collect_build_by_id('11363')
    assert build == EXPECTED_BUILD

    tested_pkg_hash_list = list()
    for pkg in albs_collector_instance.iter_package_hash():
        tested_pkg_hash_list.append(pkg)
    assert tested_pkg_hash_list == albs_collector_instance.package_hash_list

