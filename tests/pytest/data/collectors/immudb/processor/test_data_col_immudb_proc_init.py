import pytest

from alma_sbom.data.collectors.immudb.processor import processor_factory
from alma_sbom.data.collectors.immudb.processor.apiver01 import DataProcessor01
from alma_sbom.data.collectors.immudb.processor.apiver02 import DataProcessor02


IMMUDB_INFO_V01 = {
    'Hash': '05dc1b806bd5456d40e3d7f882ead037aaf480c596e83fbfb6ab86be74a2d8d1',
    'Metadata': {
        'sbom_api': '0.1',
    },
}
IMMUDB_INFO_V02 = {
    'Hash': '05dc1b806bd5456d40e3d7f882ead037aaf480c596e83fbfb6ab86be74a2d8d1',
    'Metadata': {
        'sbom_api_ver': '0.2',
    },
}


def test_processor_factory() -> None:
    processor_v01 = processor_factory(immudb_info=IMMUDB_INFO_V01, hash=None)
    processor_v02 = processor_factory(immudb_info=IMMUDB_INFO_V02, hash=None)
    assert isinstance(processor_v01, DataProcessor01)
    assert isinstance(processor_v02, DataProcessor02)

