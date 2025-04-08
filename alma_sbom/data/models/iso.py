
from dataclasses import dataclass, field

from .package import Package

@dataclass
class Iso:
    releasever: int
    image_type: str

    packages: list[Package] = field(default_factory=list)

    def append_package(self, package: Package) -> None:
        self.packages.append(package)

    def get_doc_name(self) -> str:
        return f'AlmaLinux {self.releasever} {self.image_type} ISO'
