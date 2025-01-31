from .processor import DataProcessor
from .apiver01 import DataProcessor01
from .apiver02 import DataProcessor02

from alma_sbom.data import Hash, Algorithms

processor_classes: dict[str, type[DataProcessor]] = {
    '0.1': DataProcessor01,
    '0.2': DataProcessor02,
}

def processor_factory(immudb_info: dict, hash: str) -> DataProcessor:
    if 'Metadata' in immudb_info:
            immudb_metadata = immudb_info['Metadata']
    else:
        raise ValueError('Immudb info is malformed, not has Metadata field')

    api_ver = immudb_metadata.get('sbom_api_ver')
    if not api_ver:
        api_ver = immudb_metadata.get('sbom_api')
    if not api_ver:
        raise ValueError('Immudb metadata is malformed, API version cannot be detected')

    if hash is not None and hash != immudb_info['Hash']:
        raise ValueError('malformed hash value')
    hash = hash or immudb_info['Hash']
    hashs = Hash(algorithm=Algorithms.SHA_256, value=hash)

    try:
        processor_class = processor_classes[api_ver]
        return processor_class(immudb_info, immudb_metadata, hashs)
    except KeyError:
        raise ValueError(f"Unknown api_ver: {api_ver}")

