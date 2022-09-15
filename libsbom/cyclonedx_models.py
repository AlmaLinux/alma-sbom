import logging
import json
import typing

from pydantic import BaseModel

class Author(BaseModel):
    name: str
    email: str

    def __str__(self):
        return f'{self.name} <{self.email}>'

    def __repr__(self):
        return self.__str__()


class Tool(BaseModel):
    vendor: str
    name: str
    version: str


class ComponentProperty(BaseModel):
    name: str
    value: str

class BaseComponent(BaseModel):
    type: str
    name: str
    properties: typing.List[ComponentProperty]


class Component(BaseComponent):
    author: str


class Metadata(BaseModel):
    timestamp: str
    tools: typing.List[Tool]
    component: Component


class Checksum(BaseModel):
    alg: str
    content: str


class PackageComponent(BaseComponent):
    version: str
    publisher: str
    hashes: typing.List[Checksum]
    cpe: typing.Optional[str]  # TBD: https://nvd.nist.gov/products/cpe
    purl: typing.Optional[str] # TBD: https://github.com/package-url/purl-spec


class BuildRecord(BaseModel):
    bomFormat: str
    specVersion: str
    serialNumber: str
    version: int
    metadata: Metadata
    components: typing.List[PackageComponent]
