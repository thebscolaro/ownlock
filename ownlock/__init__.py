"""ownlock — lightweight secrets manager."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("ownlock")
except PackageNotFoundError:
    __version__ = "0.0.0+dev"
