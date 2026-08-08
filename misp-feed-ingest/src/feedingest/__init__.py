"""
Reference implementation of a MISP community-feed ingestion pipeline.

Sanitized and clean-room: written for this portfolio against public feeds only.
It contains no configuration, indicators or code from any employer environment.
"""

from .normalise import (Indicator, NormalisationError, canonical_type,
                        deduplicate, infer_type, is_noise, normalise_all,
                        normalise_record)
from .pipeline import ConfigError, FeedResult, load_sources, run

__all__ = ["Indicator", "NormalisationError", "ConfigError", "FeedResult",
           "run", "load_sources", "normalise_record", "normalise_all",
           "deduplicate", "infer_type", "canonical_type", "is_noise"]
__version__ = "0.1.0"
