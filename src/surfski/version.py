"""The package version. Its single source is `version` in pyproject.toml; installed
packages expose it through importlib.metadata. A bare source checkout that was never
installed reports a placeholder."""

from importlib import metadata

UNKNOWN = "0.0.0+unknown"


def get_version() -> str:
    try:
        return metadata.version("surfski")
    except metadata.PackageNotFoundError:
        return UNKNOWN


__version__ = get_version()
