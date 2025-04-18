# AlmaLinux SBOM data management utilities

These utilities consist in:
* __AlmaLinux SBOM CLI__: This utility is used to create SBOM records for artifacts created with the [AlmaLinux Build System](https://github.com/AlmaLinux/build-system). It generates SBOM records for Builds and Packages.
* __AlmaLinux Git Notarization Tool__: This utility allows to manually notarize [AlmaLinux git sources](https://git.almalinux.org) using the [ImmudbWrapper](https://github.com/AlmaLinux/immudb-wrapper).

## Requirements

* python >= 3.9
* requests >= 2.20.0
* dataclasses >= 0.8
* cyclonedx-python-lib >= 2.7.1
* packageurl-python >= 0.10.3
* GitPython == 3.1.29
* immudb_wrapper >= 0.1.4
* rpm >= 4.14 (or rpm == 0.3.1 in venv)

## Getting started

1. Create a Python Virtual Environment: `python3.9 -m venv env`
2. Activate the Virtual Environment: `source env/bin/activate`
3. Install dependencies: `pip install .`

## Getting started with pipx - easier way

[pipx](https://pipx.pypa.io/stable/) is tool to install and run python allplication in isolated environments.
You can use a python-based command line tool easier with it. Ofcourse alma-sbom too.
pipx package is released in epel(https://docs.fedoraproject.org/en-US/epel/), so you can install it easily in AlmaLinux.

Install alma-sbom with pipx:
`pipx install .`

or you can install alma-sbom using github link directly:
`pipx install git+https://github.com/AlmaLinux/alma-sbom.git`

## Using the AlmaLinux SBOM CLI

The AlmaLinux SBOM CLI named __alma-sbom__ is provided as command line tool installed on your system or on your virtual environment(if you follow Getting Started).
It has two subcommands. You can get two different types of SBOMs(Build and Package) by using these subcommands appropriately.

You can use the following arguments for alma-sbom command:
* __output-file__: The file you want to save the generated SBOM to. If not provided, the resulting SBOM is printed to stdout
* __file-format__: The SBOM type and file format you want to generate. Either CycloneDX or SPDX. The available file formats vary depending on the SBOM format. Currently, we support the following combinations: {spdx-json,spdx-xml,spdx-yaml,spdx-tagvalue,spdx-rdf,cyclonedx-json,cyclonedx-xml}
* __albs-url__: The URL of the AlmaLinux Build System, if different from the production one, _https://build.almalinux.org_
* __immudb-username__: The immudb username, could be provided either by setting the environmental variable or by using this option, by default uses value from ImmudbWrapper module
* __immudb-password__: The immudb password, could be provided either by setting the environmental variable or by using this option, by default uses value from ImmudbWrapper module
* __immudb-database__: The immudb database name, could be provided either by setting the environmental variable or by using this option, by default uses value from ImmudbWrapper module
* __immudb-address__: The immudb host address, could be provided either by setting the environmental variable or by using this option, by default uses value from ImmudbWrapper module 
* __immudb-public-key-file__: (Optional) Path of the public key to use for authenticating requests, must be provided either by setting the environmental variable or by using this option
* __verbose__ or __debug__: You can get verbose or debug output

### Creating an SBOM of a Build

You can get SBOM of a Build using __build__ subcommand.

You can use the following arguments for build subcommand:
* __build-id__: The Build id you want to generate the SBOM for

Note that you have to provide a _build-id_

Example to make SBOM of a Build with build-id option in cyclonedx-json format:
`$ alma-sbom --file-format cyclonedx-json build --build-id 4372`

### Creating an SBOM of a package in other formats

You can get SBOM of a Package using __package__ subcommand.

You can use the following arguments for package subcommand:
* __rpm-package-hash__: The Immudb hash of the package you want to generate the SBOM for
* __rpm-package__: The path to RPM package you want to generate the SBOM for

Note that you have to either provide a _rpm-package-hash_ or an _rpm-package_

Example to make SBOM of a Package with rpm-package-hash option in cyclonedx-xml format with verbose output:
`$ alma-sbom --verbose --file-format cyclonedx-xml package --rpm-package-hash b00d871e204ca8cbcae72c37c53ab984fdadc3846c91fb35c315335adfe0699b`

Example to make SBOM of a Package with rpm-package option in spdx-yaml format with debug output:
`$ alma-sbom --debug --file-format spdx-yaml package --rpm-package /path/to/package`

### Creating an SBOM of a ISO image in default(=SPDX-json) format

You can use the following arguments for build subcommand:
* __iso-image__: Path to `AlmaLinux installer ISO image` you want to generate the SBOM for

Note that you have to provide a _iso-image_

Example to make SBOM of a Package with rpm-package with default(=spdx-json) format:
`$ alma-sbom iso --iso-image /path/to/isoimage`

## Using the AlmaLinux Git Notarization Tool

When importing git sources from CentOS, these are notarizared using Immudb, however, there are corner cases where these sources can't be notarized.
For this reason, this tool has been created in order to allow AlmaLinux developers to manually notarize AlmaLinux sources that couldn't be notarized at import time.

To summarize what the tool does:
* It checks whether an AlmaLinux git source's commit has a git tag assigned according to the AlmaLinux tagging conventions
* If this tag is "modified" according to the AlmaLinux tagging conventions, then the tool will try to find a matching tag in a corresponding upstream tag
* If the matching tag is found, the tool will authenticate its commit and take its Immudb hash if found. This hash will be added as an attribute of an AlmaLinux source Immudb record
* If the matching tag/commit is not notarized, the tool can notarize it and then use that hash as an attribute when notarizing the AlmaLinux source
* If no upstream matching tag can be found, the tool allows notarizing the AlmaLinux source without having a notarized upstream corresponding tag

The AlmaLinux Git Notarization Tool accepts the following arguments:
* __immudb-username__: The immudb username, must be provided either by setting the environmental variable or by using this option to notarize sources
* __immudb-password__: The immudb password, must be provided either by setting the environmental variable or by using this option to notarize sources
* __immudb-database__: The immudb database name, could be provided either by setting the environmental variable or by using this option, by default uses value from ImmudbWrapper module
* __immudb-address__: The immudb host address, could be provided either by setting the environmental variable or by using this option, by default uses value from ImmudbWrapper module 
* __immudb-public-key-file__: (Optional) Path of the public key to use for authenticating requests, must be provided either by setting the environmental variable or by using this option
* __local-git-repo__: The path to a local AlmaLinux git source repository. If not provided, uses the current working directory
* __notarize-without-upstream-hash__: Use this option if you want to force the notarization of an AlmaLinux commit even when there's no matched upstream tag
* __notarize-upstream-tag__: Use this option if you want to force the notarization of an upstream tag before notarizing an AlmaLinux source
* __notarize-without-imported-source-notarization__: Use this option if you want to force the notarization of an upstream tag without an imported source notarization
* __debug__: This option will make the tool to display debug information while running, which could be useful when diagnosing a problem in the tool

There are no mandatory arguments to pass (unless strictly required to force a notarization), if you are currently in a local clone of an AlmaLinux source, you can run `python /path/to/git_notarize.py`.
If you want to specify the folder, you should run `python /path/to/git_notarize.py --local-git-repo <path to local copy of a git repo>`.

Note that this tool is meant for AlmaLinux developers that have write permissions into [git.almalinux.org](https://git.almalinux.org) and that have the AlmaLinux Immudb credentials required to notarize artifacts on behalf of AlmaLinux

## Contributing to Alma SBOM

Any question? Found a bug? File an [issue](https://github.com/AlmaLinux/alma-sbom/issues).
Do you want to contribute with source code?
1. Fork the repository on GitHub
2. Create a new feature branch
3. Write your change
4. Submit a pull request
