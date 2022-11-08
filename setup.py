from setuptools import setup
from version import __version__

setup(
    name="alma_sbom",
    version=__version__,
    author="Stepan Oksanichenko",
    author_email="soksanichenko@almalinux.org",
    description="AlmaLinux OS SBOM data management utility.",
    url="https://git.almalinux.org/almalinux/alma-sbom",
    project_urls={
        "Bug Tracker": "https://git.almalinux.org/almalinux/alma-sbom/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: "
        "GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: OS Independent",
    ],
    py_modules=['alma_sbom'],
    scripts=['alma_sbom.py'],
    install_requires=[
        'plumbum>=1.7.2',
        'requests>=2.20.0',
        'dataclasses>=0.8',
        'cyclonedx-python-lib==2.7.1',
        'packageurl-python==0.10.3',
        'GitPython==3.1.29',
        'cas_wrapper'
    ],
    dependency_links=[
        'git+https://git.almalinux.org/almalinux/cas_wrapper.git@0.0.5#egg=cas_wrapper'
    ],
    python_requires=">=3.9",
)
