from dataclasses import dataclass
from typing import ClassVar
import pytest

from alma_sbom.data.attributes.property import Property, PropertyMixin


@dataclass
class ForTestPropertyMixin(PropertyMixin):
    PROPERTY_KEYS: ClassVar[dict[str, str]] = {
        "testvalue01": "almalinux:unittest:test:value:01",
        "testvalue02": "almalinux:unittest:test:value:02",
    }

    testvalue01: str
    testvalue02: str

    def to_properties(self) -> list[Property]:
        return self._create_properties()

EXPECTED_PROPS_LIST = [
    Property(
        name="almalinux:unittest:test:value:01",
        value="testvalue01",
    ),
    Property(
        name="almalinux:unittest:test:value:02",
        value="testvalue02",
    ),
]

@pytest.fixture
def for_test_property_mixin_instance() -> ForTestPropertyMixin:
    return ForTestPropertyMixin(
        testvalue01='testvalue01',
        testvalue02='testvalue02',
    )


def test_PropertyMixin__create_properties(for_test_property_mixin_instance: ForTestPropertyMixin) -> None:
    assert for_test_property_mixin_instance.to_properties() == EXPECTED_PROPS_LIST




