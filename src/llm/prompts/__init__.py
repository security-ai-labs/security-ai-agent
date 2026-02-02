"""
Security analysis prompts for all languages
"""

from .base_prompts import (
    get_system_prompt,
    get_analysis_prompt,
    get_fix_prompt
)

__all__ = [
    'get_system_prompt',
    'get_analysis_prompt',
    'get_fix_prompt',
]