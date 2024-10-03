"""Exceptions for this application"""

class ValidationError(Exception):
    """Indicates that an input could not be validated (e.g. it has the wrong format)"""

class PreconditionError(Exception):
    """Indicates that another action must be taken before the current one"""
