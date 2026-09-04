"""Marks ``runtime`` as a package so its ``tests`` is not a TOP-LEVEL one.

Without this file, pytest's prepend import mode puts ``runtime/`` itself on
``sys.path`` (it is the first ancestor with no ``__init__.py``), which makes
``runtime/tests`` the top-level package named ``tests``. Several builtin apps
import their own fixtures under exactly that name (``from tests.fixtures import
...``, resolving against their own app root), so whichever suite is collected
first wins the name and the others fail to import at collection time.

It surfaced only on Windows, whose shard split happened to place two such suites
in one process. The defect was platform-independent; the observation was not.
"""
