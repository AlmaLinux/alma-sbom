import typing

def check_required_data(
        data_dict: typing.Dict[str, any],
        required_fields: typing.List[str],
    ) -> typing.Tuple[bool, typing.List[str]]:
    """
    Check if all the required fields exist in the specified data dictionary

    Args:
        data_dict (Dict[str, any]): A dictionary containing the data to be checked
        required_fields (List[str]): A list of required field names

    Returns:
        Tuple[bool, List[str]]:
            - bool: If all required fields exist, return True; otherwise, return False
            - List[str]: A list of missing field names
    """

    missing_fields = [field for field in required_fields if field not in data_dict]
    return not bool(missing_fields), missing_fields


def replace_patterns(input_str: str, patterns: typing.Dict[str, str]) -> str:
    """Convenience function to perform multiple string replacements."""

    output_str = input_str

    for search, replace in patterns.items():
        output_str = output_str.replace(search, replace)

    return output_str


def normalize_epoch_in_version(version: str) -> str:
    """Replace unset epochs in version strings with 0."""

    patterns = {
        'None:':   '0:',
        '(none):': '0:',
    }

    return replace_patterns(input_str=version,
                            patterns=patterns)


def normalize_epoch_in_purl(purl: str) -> str:
    """Replace unset epochs in PURLs with 0."""

    patterns = {
        'epoch=None':   'epoch=0',
        'epoch=(none)': 'epoch=0',
    }

    return replace_patterns(input_str=purl,
                            patterns=patterns)


def normalize_epoch_in_cpe(cpe: str) -> str:
    """Replace unset epochs in CPEs with 0."""

    patterns = {
        ':None\\:':   ':0\\:',
        ':(none)\\:': ':0\\:',
    }

    return replace_patterns(input_str=cpe,
                            patterns=patterns)


def normalize_epoch_in_prop(name: str, value: str) -> str:
    """Replace unset epochs in propertiy strings with 0."""

    if name != 'almalinux:package:epoch':
        return value

    return value.replace('None', '0').replace('(none)', '0')
