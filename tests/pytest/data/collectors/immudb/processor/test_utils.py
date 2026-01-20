from alma_sbom.data.collectors.immudb.processor.utils import normalize_epoch




# def normalize_epoch(epoch: Union[str, int]) -> int:
#     '''normalize inconsistent null epoch representations in immudb'''
#     '''In alma-sbom, null epoch is represented as 0'''
def test_normalize_epoch() -> None:
    assert normalize_epoch(None) == 0
    assert normalize_epoch('None') == 0
    assert normalize_epoch('(none)') == 0
    assert normalize_epoch(1) == 1
