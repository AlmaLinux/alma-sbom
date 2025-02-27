import hashlib
import rpm
from license_expression import get_spdx_licensing, ExpressionError

from alma_sbom.type import Hash, Licenses
from alma_sbom.data.models import Package, PackageNevra

class RpmCollector:
    ts: rpm.TransactionSet

    def __init__(self):
        self.ts = rpm.TransactionSet()

    def collect_package_from_file(self, rpm_package: str) -> Package:
        try:
            with open(rpm_package) as fd:
                hdr = self.ts.hdrFromFdno(fd)
        except (OSError, rpm.error) as e:
            e.args = (f'Error opening RPM package: {str(e)}',) + e.args[1:]
            raise
        except Exception as e:
            e.args = (f'Unknown error while processing RPM package: {str(e)}',) + e.args[1:]
            raise

        package_nevra = PackageNevra(
            ### NOTE:
            # In alma-sbom, null epoch is represented as 0
            # Please see normalize_epoch implementation for more details
            epoch = hdr[rpm.RPMTAG_EPOCH],
            name = hdr[rpm.RPMTAG_NAME],
            version = hdr[rpm.RPMTAG_VERSION],
            release = hdr[rpm.RPMTAG_RELEASE],
            arch = hdr[rpm.RPMTAG_ARCH],
        )
        pkg = Package(
            package_nevra = package_nevra,
            source_rpm = hdr[rpm.RPMTAG_SOURCERPM],
            hashs = [Hash(value=hash_file(rpm_package))],
            ### NOTE:
            ##  There are little bit difference of buildtime between immudb_metadata & rpm_package.
            ##  So, now we don't set buildtime using rpm_package info.
            ##  According to the specifications of extractimmudb_info_about_package, even if there is no timestamp
            ##  info in immudb, None will be stored.
            ##  Or, We should set it anymore? because whenever this code is executed, immudb_metadata is None or lacking.
            ##  If you want do this, uncomment below block.
            #package_timestamp = hdr[rpm.RPMTAG_BUILDTIME],
            ### NOTE:
            ## data from rpm package doesn't have propeties info
            #package_properties = None,
            #build_properties = None,
            #sbom_properties = None,
        )

        pkg.licenses = _proc_licenses(hdr[rpm.RPMTAG_LICENSE])
        pkg.summary = hdr[rpm.RPMTAG_SUMMARY]
        pkg.description = hdr[rpm.RPMTAG_DESCRIPTION]

        return pkg

def _proc_licenses(licenses_str: str) -> Licenses:
    licensing = get_spdx_licensing()
    licenses = Licenses(ids=[], expression=licenses_str)
    try:
        parsed = licensing.parse(licenses_str, validate=True)
    except ExpressionError as err:
        pass
    else:
        symbols = licensing.license_symbols(parsed)
        for sym in symbols:
            licenses.ids.append(str(sym))
    return licenses

def hash_file(file_path: str, buff_size: int = 1048576) -> str:
    """
    Returns SHA256 checksum (hexadecimal digest) of the file.

    Parameters
    ----------
    file_path : str
        File path to hash.
    buff_size : int
        Number of bytes to read at once.

    Returns
    -------
    str
        Checksum (hexadecimal digest) of the file.
    """
    hasher = hashlib.sha256()

    with open(file_path, 'rb') as fd:
        buff = fd.read(buff_size)
        while len(buff):
            hasher.update(buff)
            buff = fd.read(buff_size)

    return hasher.hexdigest()

