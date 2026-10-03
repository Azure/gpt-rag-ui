"""Configuration lookup errors shared by settings and provider consumers."""


class ConfigurationError(ValueError):
    """A required setting is absent or cannot be converted to its requested type."""
