"""
Paquete de utilidades
"""
from .patterns import (
    SecurityPatterns,
    PerformancePatterns,
    CompliancePatterns,
    MaintainabilityPatterns,
    PatternAnalyzer
)

from .helpers import (
    generate_uuid,
    generate_hash,
    format_datetime,
    parse_datetime,
    truncate_text,
    sanitize_filename,
    ensure_directory,
    get_file_size,
    format_file_size,
    save_json,
    load_json,
    calculate_risk_score,
    get_severity_color,
    get_category_icon,
    format_duration,
    extract_code_context,
    get_recommendation_for_finding,
    get_impact_description,
    JsonEncoder
)

__all__ = [
    # Patterns
    "SecurityPatterns",
    "PerformancePatterns",
    "CompliancePatterns",
    "MaintainabilityPatterns",
    "PatternAnalyzer",
    
    # Helpers
    "generate_uuid",
    "generate_hash",
    "format_datetime",
    "parse_datetime",
    "truncate_text",
    "sanitize_filename",
    "ensure_directory",
    "get_file_size",
    "format_file_size",
    "save_json",
    "load_json",
    "calculate_risk_score",
    "get_severity_color",
    "get_category_icon",
    "format_duration",
    "extract_code_context",
    "get_recommendation_for_finding",
    "get_impact_description",
    "JsonEncoder"
]
