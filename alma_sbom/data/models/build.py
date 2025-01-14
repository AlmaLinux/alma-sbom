from dataclasses import dataclass

from .package import Package
from ..attributes.property import Property, BuildProperties

@dataclass
class Build:
    build_id: str
    author: str
    packages: list[Package]

    build_properties: BuildProperties = None

    def get_doc_name(self) -> str:
        return f'build-{self.build_id}'

    def get_properties(self) -> list[Property]:
        return (self.build_properties.to_properties() if self.build_properties is not None else [])

