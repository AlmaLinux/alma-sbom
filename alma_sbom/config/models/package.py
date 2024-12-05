from dataclasses import dataclass, asdict
from ..config import CommonConfig

@dataclass
class PackageConfig(CommonConfig):
    rpm_package_hash: str = None
    rpm_package: str = None

    def __post_init__(self) -> None:
        # validation? need to be spalate?
        if (config.rpm_package_hash is None and config.rpm_package is None) or \
           (config.rpm_package_hash is not None and config.rpm_package is not None):
            raise ValueError("Either rpm_package_hash or rpm_package must be specified")

