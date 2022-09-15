from setuptools import setup

setup(
    name="alma_sbom",
    version="0.0.1",
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
    scripts=['sbom_generator.py'],
    install_requires=[
        'plumbum>=1.7.2',
        'requests>=2.20.0',
        'dataclasses>=0.8',
    ],
    python_requires=">=3.6",
)
