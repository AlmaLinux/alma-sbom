from dataclasses import dataclass, asdict
from ..config import CommonConfig

@dataclass
class PackageConfig(CommonConfig):
    rpm_package_hash: str = None
    rpm_package: str = None

    def __post_init__(self) -> None:
        # validation? need to be spalate?
        if (self.rpm_package_hash is None and self.rpm_package is None) or \
           (self.rpm_package_hash is not None and self.rpm_package is not None):
            raise ValueError("Either rpm_package_hash or rpm_package must be specified")
        super().__post_init__()

    @classmethod
    def from_base(cls, base: CommonConfig, rpm_package_hash: str, rpm_package: str) -> 'PackageConfig':
        base_fields = vars(base)
        return cls(**base_fields, rpm_package_hash=rpm_package_hash, rpm_package=rpm_package)

