import typing

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
