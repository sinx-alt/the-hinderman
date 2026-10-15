"""Sensitive-data inspection."""

from contracts import Finding, UserContext
from detectors.inspect import inspect

__all__ = ["Finding", "UserContext", "inspect"]
