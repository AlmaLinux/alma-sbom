import os
import pytest

from alma_sbom.data.collectors import IsoCollector
from alma_sbom.data.models import Iso


TESTED_ISOIMAGE_NAME = 'AlmaLinux-9-latest-x86_64-minimal.iso'
TESTED_ISOIMAGE_PATH = os.path.dirname(__file__) + f'/{TESTED_ISOIMAGE_NAME}'

EXPECTED_ISO = Iso(
    releasever='9',
    image_type='Minimal',
    packages=[],
)


@pytest.fixture
def iso_collector_instance() -> IsoCollector:
    return IsoCollector()


# TODO: Implement in the future
# def test_collect_iso_by_file(iso_collector_instance: IsoCollector) -> None:
#     assert iso_collector_instance.collect_iso_by_file(TESTED_ISOIMAGE_PATH) == EXPECTED_ISO


def test_get_fd_path(iso_collector_instance: IsoCollector) -> None:
    expected_fd_path = f'{iso_collector_instance.memfd_path}'
    assert iso_collector_instance.get_fd_path() == expected_fd_path


# TODO: Implement in the future
# def test_iter_packages(self) -> None:
