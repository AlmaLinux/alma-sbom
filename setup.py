from setuptools import setup

from version import __version__

def get_requires():
    requires=[
        'requests>=2.20.0',
        'cyclonedx-python-lib==2.7.1',
        'spdx-tools==0.8',
        'urllib3<2.0',
        'packageurl-python==0.10.3',
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
    install_requires=get_requires(),
    python_requires=">=3.9",
)
