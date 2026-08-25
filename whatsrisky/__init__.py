"""whatsrisky - what's risky in this project?

The version lives here and nowhere else: pyproject.toml reads it through
[tool.hatch.version], so the package, the reports it writes and the wheel can
never disagree. Semantic versioning - the JSON report's schema_version is a
separate, independent contract.
"""

__version__ = "0.2.0"
