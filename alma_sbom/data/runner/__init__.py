
from alma_sbom.config.config import CommonConfig
from alma_sbom.config.models.package import PackageConfig
from alma_sbom.config.models.build import BuildConfig

from .runner import CollectorRunner
from .package import PackageCollectorRunner
from .build import BuildCollectorRunner

collector_runner_classes: dict[type[CommonConfig], type[CollectorRunner]] = {
    PackageConfig: PackageCollectorRunner,
    BuildConfig: BuildCollectorRunner,
}

def collector_runner_factory(config: CommonConfig) -> CollectorRunner:
    try:
        collector_runner_class = collector_runner_classes[type(config)]
        return collector_runner_class(config)
    except KeyError:
        raise RuntimeError('Unexpected situation has occurred')

