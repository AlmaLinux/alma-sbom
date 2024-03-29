#!/usr/bin/env python3
# -*- mode:python; coding:utf-8; -*-

import argparse
import logging
import os
import re
import sys

from git import Repo
from git.exc import GitCommandError, InvalidGitRepositoryError
from immudb_wrapper import ImmudbWrapper


def create_parser():
    parser = argparse.ArgumentParser(
        "git_notarize.py",
        description="Notarize commits in AlmaLinux git repositories",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        '--immudb-username',
        type=str,
        help=(
            'Provide your immudb username if not set as '
            'an environmental variable'
        ),
        required=False,
    )

    parser.add_argument(
        '--immudb-password',
        type=str,
        help=(
            'Provide your immudb password if not set as '
            'an environmental variable'
        ),
        required=False,
    )

    parser.add_argument(
        '--immudb-database',
        type=str,
        help=(
            'Provide your immudb database if not set as '
            'an environmental variable'
        ),
        required=False,
    )

    parser.add_argument(
        '--immudb-address',
        type=str,
        help=(
            'Provide your immudb address if not set as '
            'an environmental variable'
        ),
        required=False,
    )

    parser.add_argument(
        '--immudb-public-key-file',
        type=str,
        help=(
            'Provide your immudb public key file if not set as '
            'an environmental variable'
        ),
        required=False,
    )

    parser.add_argument(
        "--local-git-repo",
        help=(
            "Path to a local AlmaLinux git source repository. "
            "If not provided, uses the current working directory"
        ),
        type=str,
        required=False,
        default=os.getcwd(),
    )

    parser.add_argument(
        "--notarize-without-upstream-hash",
        help=(
            "Force notarization of AlmaLinux commit even when "
            "there's no matching upstream tag"
        ),
        action="store_true",
        required=False,
    )

    parser.add_argument(
        "--notarize-upstream-tag",
        help=(
            "Force notarization of upstream tag before "
            "notarizing AlmaLinux commit"
        ),
        action="store_true",
        required=False,
    )

    parser.add_argument(
        "--notarize-without-imported-source-notarization",
        help=(
            "Force notarization of upstream tag without an "
            "imported source notarization"
        ),
        action="store_true",
        required=False,
    )

    parser.add_argument(
        "--debug",
        help=(
            "Display debug information while running git_notarize.py. "
            "This info could be useful when diagnosing a problem in the tool"
        ),
        action="store_true",
        required=False,
    )

    return parser


class GitRepo(Repo):
    def get_branches(self):
        branches = []
        # remote branches
        for ref in self.remotes.origin.refs:
            if ref.remote_head not in branches and ref.remote_head != "HEAD":
                branches.append(ref.remote_head)
        return branches

    def get_tags(self):
        return [tag.name for tag in self.tags]

    def get_current_commit(self):
        return self.head.object

    def get_current_tag(self):
        current_tag = None
        try:
            current_tag = self.git.describe(
                "--tags",
                self.get_current_commit().hexsha,
            )
        except GitCommandError:
            pass

        return current_tag

    def get_split_tag(self, name: str, tag: str):
        tag_type, tag_distro, tag_nvr = tag.split("/")
        # Let the user know that the tag doesn't follow AlmaLinux tag format.
        # We do not fail as there are packages that don't include AlmaLinux
        # branding, i.e.: kernel

        if tag_type != "changed":
            logging.warning(
                "Current tag's type is '%s' and should be 'changed'",
                tag_type,
            )
        if not tag_distro.startswith("a"):
            logging.warning(
                "Current tag's distro %s doesn't start with 'a'",
                tag_distro,
            )

        alma_nvr = re.search(r"\.alma.*$", tag_nvr)
        if not alma_nvr:
            logging.warning(
                "Current tag's nvr '%s' doesn't include 'alma' branding",
                alma_nvr,
            )

        return tag_type, tag_distro, tag_nvr

    def get_origin_url(self):
        origin = self.remote("origin")
        return list(origin.urls)[0]

    def get_name(self):
        return self.get_origin_url().split("/")[-1].replace(".git", "")

    def find_matching_imports_tag(self, name: str, tag: str):
        # Return tag if the source comes directly
        # from CentOS sources
        if tag.startswith('imports'):
            return tag
        # We want to find "imports" that match a given "changed" tag
        # As an example, we will receive a "changed" tag like this:
        #  changed/a8-beta/anaconda-33.16.7.10-1.el8.alma
        # And we want to find an "imports" tag that looks like:
        #  imports/c8-beta/anaconda-33.16.7.10-1.el8
        debranded_tag = self.get_debranded_imports_tag(tag)
        imports_tag = (
            debranded_tag if debranded_tag in self.get_tags() else None
        )
        return imports_tag

    def get_debranded_imports_tag(self, tag: str):
        tag_type, tag_distro, tag_nvr = tag.split("/")
        debranded_type = "imports"
        # a8, a8s, a8s-beta, a8-stream ...
        # We only need to replace the first character
        debranded_distro = tag_distro.replace("a", "c", 1)
        # this will get, i.e.: anaconda-33.16.7.10-1.el8
        # Without AlmaLinux custom suffixes (.alma, .alma.2), if any
        debranded_nvr = re.sub(r"\.alma.*$", "", tag_nvr)

        debranded_tag = (debranded_type, debranded_distro, debranded_nvr)

        return "/".join(debranded_tag)


def notarize(
    immudb_wrapper: ImmudbWrapper,
    repo_path: str,
    upstream_commit_sbom_hash: str = None,
):
    metadata = {
        "sbom_api_ver": "0.2",
    }

    if upstream_commit_sbom_hash:
        logging.info(
            "Notarizing AlmaLinux source using the "
            "upstream_commit_sbom_hash %s",
            upstream_commit_sbom_hash,
        )
        metadata['upstream_commit_sbom_hash'] = upstream_commit_sbom_hash

    result = immudb_wrapper.notarize_git_repo(
        repo_path=repo_path,
        user_metadata=metadata,
    )
    notarized_hash = result.get('value', {}).get('Hash')

    return notarized_hash


def cli_main():
    args = create_parser().parse_args()

    logging.basicConfig(
        format="%(levelname)-8s %(message)s",
        level=logging.DEBUG if args.debug else logging.INFO,
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.StreamHandler(),
        ],
    )

    logging.info("Starting git_notarize.py")

    immudb_username, immudb_password = (
        args.immudb_username or os.getenv('IMMUDB_USERNAME'),
        args.immudb_password or os.getenv('IMMUDB_PASSWORD'),
    )
    if not immudb_username:
        logging.error(
            "No IMMUDB_USERNAME found, and it's required to operate with immudb. "
            "You can either set it as an environmental variable or providing "
            "it using the --immudb-username option."
        )
        sys.exit(1)
    if not immudb_password:
        logging.error(
            "No IMMUDB_PASSWORD found, and it's required to operate with immudb. "
            "You can either set it as an environmental variable or providing "
            "it using the --immudb-password option."
        )
        sys.exit(1)

    immudb_wrapper = ImmudbWrapper(
        username=immudb_username,
        password=immudb_password,
        database=(
            args.immudb_database
            or os.getenv('IMMUDB_DATABASE')
            or ImmudbWrapper.almalinux_database_name()
        ),
        immudb_address=(
            args.immudb_address
            or os.getenv('IMMUDB_ADDRESS')
            or ImmudbWrapper.almalinux_database_address()
        ),
        public_key_file=(
            args.immudb_public_key_file or os.getenv('IMMUDB_PUBLIC_KEY_FILE')
        ),
    )

    alma_repo_path = os.path.abspath(args.local_git_repo)
    try:
        alma_repo = GitRepo(alma_repo_path)
        logging.info("Using git repository %s", alma_repo_path)
    except InvalidGitRepositoryError:
        logging.error("Current folder is not a git repository")
        sys.exit(1)

    logging.debug("Git repo name: %s", alma_repo.get_name())
    logging.debug("Git origin url: %s", alma_repo.get_origin_url())
    logging.debug("Git branches: %s", str(alma_repo.get_branches()))
    logging.debug("Git tags: %s", str(alma_repo.get_tags()))

    if alma_repo.head.is_detached:
        logging.warning(
            "The git repo is in DETACHED state. This means that if "
            "git_notarize.py stops its execution, you will probably "
            "need to manually return to this detached state before "
            "running the tool again."
        )
        current_branch = None
    else:
        current_branch = alma_repo.active_branch.name
        logging.info("Current branch is %s", current_branch)

    current_commit = alma_repo.get_current_commit()
    logging.debug(
        "Current commit is:\n\n%s\nAuthor: %s <%s>\nDate: %s\n\t%s",
        current_commit.hexsha,
        current_commit.author.name,
        current_commit.author.email,
        current_commit.authored_datetime.strftime("%a %b %d %H:%M:%S %Y %z"),
        current_commit.message,
    )

    current_tag = alma_repo.get_current_tag()
    if current_tag:
        logging.debug("Tag associated with current commit is: %s", current_tag)
    else:
        logging.error(
            "Couldn't find any tag associated with current commit.\n"
            "Please, create a tag of this change before keep going"
        )
        sys.exit(1)

    tag_type, tag_distro, tag_nvr = alma_repo.get_split_tag(
        alma_repo.get_name(), current_tag
    )
    if (
        tag_type.startswith("imports")
        and tag_distro.startswith("c")
        and not args.notarize_without_imported_source_notarization
    ):
        logging.error(
            "Exiting as the current tag %s looks like an imported source\n"
            "Imported sources should have been automatically "
            "notarized at import time, and this tool is meant to help with "
            "notarization of modified sources. Are you maybe in the wrong "
            "branch/tag?\n"
            "Use --notarize-without-imported-source-notarization if you "
            "really want to notarize this AlmaLinux source without "
            "an imported source notarization",
            current_tag,
        )
        sys.exit(1)

    logging.debug("Authenticating current tag %s", current_tag)
    current_tag_is_authenticated = False
    current_immudb_hash = None
    try:
        result = immudb_wrapper.authenticate_git_repo(
            alma_repo_path,
        )
        current_tag_is_authenticated = result.get('verified', False)
        current_immudb_hash = result.get('value', {}).get('Hash')
    except Exception:
        pass

    if current_tag_is_authenticated:
        logging.info(
            "Current tag is already notarized, its Immudb hash is %s.\n"
            "Nothing to do, exiting now.",
            current_immudb_hash,
        )
        sys.exit(0)

    matching_tag = None
    if tag_type.startswith("changed"):
        matching_tag = alma_repo.find_matching_imports_tag(
            alma_repo.get_name(),
            current_tag,
        )

    if not matching_tag:
        logging.warning(
            "Couldn't find a matching imports tag for %s",
            current_tag,
        )
        if not args.notarize_without_upstream_hash:
            logging.error(
                "Use --notarize-without-upstream-hash if you really want to "
                "notarize this AlmaLinux source without a corresponding "
                "upstream Immudb hash"
            )
            sys.exit(1)
        else:
            logging.info(
                "Notarizing tag without a corresponding upstream Immudb hash"
            )
            immudb_hash = notarize(immudb_wrapper, alma_repo_path)
            logging.info(
                "The tag %s has been notarized. Immudb hash: %s",
                current_tag,
                immudb_hash,
            )
            sys.exit(0)
    else:
        logging.info(
            "Found a matching tag for %s: %s",
            current_tag,
            matching_tag,
        )

        # git checkout the matching tag
        logging.debug("git checkout %s", matching_tag)
        alma_repo.git.checkout(matching_tag)

        matching_tag_is_authenticated = False
        matching_immudb_hash = None
        logging.debug("Authenticating matching tag %s", matching_tag)
        try:
            result = immudb_wrapper.authenticate_git_repo(
                alma_repo_path,
            )
            matching_tag_is_authenticated = result.get('verified', False)
            matching_immudb_hash = result.get('value', {}).get('Hash')
        except Exception:
            logging.warning(
                "Couldn't authenticate the matching tag %s",
                matching_tag,
            )

        if not matching_tag_is_authenticated:
            if not args.notarize_upstream_tag:
                logging.error(
                    "Use --notarize-upstream-tag to notarize the matching "
                    "tag and keep going with the notarization of the "
                    "AlmaLinux tag"
                )
                alma_repo.git.checkout(current_branch)
                sys.exit(1)
            else:
                logging.info("Notarizing the matching upstream tag")
                matching_immudb_hash = notarize(immudb_wrapper, alma_repo_path)
                logging.info(
                    "The matching upstream tag %s has been notarized. "
                    "Immudb hash: %s",
                    matching_tag,
                    matching_immudb_hash,
                )

        # git checkout to the current_branch
        alma_repo.git.checkout(current_branch)
        alma_immudb_hash = notarize(
            immudb_wrapper,
            alma_repo_path,
            matching_immudb_hash,
        )
        logging.info(
            "The AlmaLinux tag %s has been notarized. Immudb hash: %s",
            current_tag,
            alma_immudb_hash,
        )


if __name__ == "__main__":
    cli_main()
