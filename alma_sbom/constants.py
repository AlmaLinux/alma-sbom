from immudb_wrapper import ImmudbWrapper

from alma_sbom._version import __version__

ALMAOS_VENDOR = 'AlmaLinux OS Foundation'
ALMAOS_SBOMLICENSE = 'CC0-1.0'
ALMAOS_NAMESPACE = 'https://security.almalinux.org'

TOOLS = [
    {
        "vendor": ALMAOS_VENDOR,
        "name": "AlmaLinux Build System",
        "version": "0.1",  # Shall we start versioning ALBS?
    },
    {
        "vendor": ALMAOS_VENDOR,
        "name": "alma-sbom",
        "version": __version__,
    },
    {
        "vendor": ALMAOS_VENDOR,
        "name": "Immudb Wrapper",
        "version": ImmudbWrapper.get_version(),
    },
]
