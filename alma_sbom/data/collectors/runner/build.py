from typing import Callable

from alma_sbom.data import Build
from alma_sbom.config.models.build import BuildConfig
from .runner import CollectorRunner

class BuildCollectorRunner(CollectorRunner):
    config: BuildConfig
    func: Callable

    def run(self) -> Build:
        raise NotImplementedError()

