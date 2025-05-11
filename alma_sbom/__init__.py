# alma_sbom/__init__.py

import logging

logger = logging.getLogger("alma-sbom")
logger.setLevel(logging.INFO)

handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - Alma SBOM - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

logger.info("Logger initialized")

