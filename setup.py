import sys
from setuptools import setup, find_namespace_packages

from alma_sbom._version import __version__

def get_install_requires():
    requires=[
        'requests>=2.20.0',
        'cyclonedx-python-lib==9.0.0',
        'spdx-tools==0.8',
        'urllib3<2.0',
        'packageurl-python==0.16.0',
        'GitPython==3.1.29',
        'immudb_wrapper @ git+https://github.com/AlmaLinux/immudb-wrapper.git@0.1.5#egg=immudb_wrapper',
    ]

    is_venv = sys.prefix != sys.base_prefix
    if is_venv:
        requires.append('rpm==0.3.1')
    else: # not is_venv
        requires.append('rpm>=4.14')

    return requires

setup(
    name="alma-sbom",
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
    packages=find_namespace_packages(include=['alma_sbom*']),
    install_requires=get_install_requires(),
    python_requires=">=3.9",
    entry_points={
        'console_scripts': [
            'alma-sbom=alma_sbom.cli.main:cli_main'
        ],
    },

    ### tests setting
    extras_require={
        'dev': [
            'pytest',
            'pytest-cov',
        ],
    },
)
