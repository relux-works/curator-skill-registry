"""Curator Skill Registry service."""
from __future__ import annotations

import os

__version__ = "0.1.0"

COMMAND_NAME = "curator-skill-registry"
HOME_ENV = "CURATOR_SKILL_REGISTRY_HOME"
LEGACY_COMMAND_NAME = "csk-registry"
LEGACY_HOME_ENV = "CSK_REGISTRY_HOME"


def home_from_env() -> str:
    """Return the configured data directory, preferring the current name."""
    return os.environ.get(HOME_ENV) or os.environ.get(LEGACY_HOME_ENV) or "./data"
