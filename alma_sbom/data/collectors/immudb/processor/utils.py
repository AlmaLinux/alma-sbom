from typing import Union

def normalize_epoch(epoch: Union[str, int]) -> int:
    '''normalize inconsistent null epoch representations in immudb'''
    '''In alma-sbom, null epoch is represented as 0'''
    if epoch is None or epoch == 'None' or epoch == '(none)':
        return 0
    return epoch
