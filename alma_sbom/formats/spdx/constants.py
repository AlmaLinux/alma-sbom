from spdx_tools.spdx.model import Actor, ActorType

from alma_sbom import constants
from alma_sbom.constants import ALMAOS_SBOMLICENSE
from alma_sbom._version import __version__

SPDX_ALMAOS_NAMESPACE = constants.ALMAOS_NAMESPACE + '/spdx'

TOOLS_SPDX = [
    {
        "vendor": constants.ALMAOS_VENDOR,
        "name": "spdx-tools",
        "version": "0.8",
    }
]

### Actors
ToolsActors = [
    Actor(
        actor_type=ActorType.TOOL,
        name=f"{tool['name']} {tool['version']}",
    )
    for tool in constants.TOOLS
]
ToolsSpdxActors = [
    Actor(
        actor_type=ActorType.TOOL,
        name=f"{tool['name']} {tool['version']}",
    )
    for tool in TOOLS_SPDX
]
AlmaActor = Actor(
    ActorType.ORGANIZATION,
    constants.ALMAOS_VENDOR,
)
CREATORS = [AlmaActor] + ToolsActors + ToolsSpdxActors

AlmaSbomActor = Actor(
    actor_type=ActorType.TOOL,
    name=f"alma-sbom {__version__}",
)

