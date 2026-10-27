"""WiFuX — clean, un-packed rebuild (source layer).

This package replaces the obfuscated ``main.py`` blob with readable,
version-independent Python. The first module to land is :mod:`wifux.database`,
which brings the previously dormant data files (``router_models.json``,
``pins.csv``, ``vulnwsc.txt``) to life as a real lookup layer.

Pure standard library only — runs on any CPython 3.6+ (no marshal/bytecode
lock, unlike the original packed engine).
"""

__version__ = "2.1.0-dev"
__all__ = ["database"]
