"""Reach the container package the way the image does: by its build context.

The subject of this suite is imported as top-level ``container.*``, because that
is what it is inside the image -- ``/app`` is on ``sys.path`` and the package
sits at ``/app/container``. Eight modules import ``container.common``
absolutely, and the supervisor hands a
``from container.backup.sidecar import run_sidecar`` string to a child
interpreter, so that name is part of the image's contract rather than an
artifact of where the source used to live. Rewriting the imports to this
repository's package path would break the image at runtime, silently in the
supervisor's case.

``crew/runtime/`` therefore has no ``__init__.py``: it is a docker build
context, not a python package, and
``test_spawn_audit.py::test_container_image_assets_are_not_imported`` pins that
so the gateway can never import this tree by package path. Putting the build
context on ``sys.path`` here is what lets the tests resolve ``container`` while
that stays true.

pytest's prepend import mode happens to insert this same directory (it is the
first ancestor without an ``__init__.py``), so this file is belt and braces --
but the import root is a fact about the image, not about a pytest setting, and
it should be stated somewhere that survives a change to either.
"""

from __future__ import annotations

import sys
from pathlib import Path

_BUILD_CONTEXT = Path(__file__).resolve().parents[1]

# APPEND, never insert(0). This directory contains a ``tests`` package, and
# several builtin apps import their own fixtures as the TOP-LEVEL package name
# ``tests`` (``from tests.fixtures import ...``, relying on that app's own root
# being on sys.path). Putting this directory FIRST made our ``runtime/tests``
# win that name for the whole process, and every such app then failed to import
# its own fixtures. It only showed up on Windows, whose shard split happened to
# put both suites in one process while the Linux split did not -- so the ordering
# was wrong on every platform and observable on one.
#
# Appending is sufficient for what this is actually for: the container's own
# package is ``container``, which no other suite defines, so it resolves from
# anywhere on the path and needs no precedence.
if str(_BUILD_CONTEXT) not in sys.path:
    sys.path.append(str(_BUILD_CONTEXT))
