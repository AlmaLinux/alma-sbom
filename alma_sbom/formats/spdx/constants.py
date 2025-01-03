from spdx_tools.spdx.model import Actor, ActorType

from alma_sbom import constants
from alma_sbom._version import __version__

AlmaSbomActor = Actor(
    actor_type=ActorType.TOOL,
    name=f"alma-sbom {__version__}",
)

AlmaActor = Actor(
    ActorType.ORGANIZATION,
    constants.ALMAOS_VENDOR,
)
