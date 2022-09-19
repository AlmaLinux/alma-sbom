# AlmaLinux OS SBOM data management utility

The AlmaLinux OS SBOM data management utility allows to create SBOM records for artifacts created with the [AlmaLinux Build System](https://github.com/AlmaLinux/build-system).

It comes with an easy-to-use CLI that allows you to create SBOM records for Builds and Packages.

## Requirements

* python >= 3.9
* plumbum >= 1.7.2
* requests >= 2.20.0
* dataclasses >= 0.8
* cyclonedx-python-lib >= 2.7.1
* packageurl-python >= 0.10.3
* cas_wrapper >= 0.5

## Getting started

1. Create a Python Virtual Environment: `python3.9 -m venv env`
2. Activate the Virtual Environment: `source env/bin/activate`
3. Install dependencies: `python setup.py install`

## Using the AlmaLinux OS SBOM CLI

The AlmaLinux OS SBOM CLI accepts the following arguments:

* __output-file__: The file you want to save the generated SBOM to
* __sbom-type__: The SBOM type you want to generate. Either CycloneDX or SPDX, although right now we only support the CycloneDX format
* __sbom-format__: The output format you want to use, either JSON or XML
* __build-id__: The Build id you want to generate the SBOM for
* __rpm-package-hash__: The cas hash of the package you want to generate the SBOM for
* __signer-id__: The CAS signer id, if different from the default one, _cloud-infra@almalinux.org_
* __albs-url__: The URL of the AlmaLinux Build System, if different from the production one, _https://build.almalinux.org_

Note that you have to either provide a _build-id_ or an _rpm-package-hash_

### Creating an SBOM of a Build

`python sbom_generator.py --output-file sbom_build.json --sbom-type cyclonedx --file-format json --build-id 149`

### Creating an SBOM of a package

`python sbom_generator.py --output-file sbom_package.json --sbom-type cyclonedx --file-format json --rpm-package-hash 0843129730468c4c4a17f050be3edf1449ffddc4c6be9459f54fc544d45cc257`

## Contributing to Alma SBOM

Any question? Found a bug? File an [issue](https://github.com/AlmaLinux/alma-sbom/issues).
Do you want to contribute with source code?
1. Fork the repository on Github
2. Create a new feature branch
3. Write your change
4. Submit a pull request
