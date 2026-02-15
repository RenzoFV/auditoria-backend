"""
Paquete de routers
"""
from . import connection
from . import stored_procedures
from . import analysis
from . import reports
from . import dashboard

__all__ = [
    "connection",
    "stored_procedures",
    "analysis",
    "reports",
    "dashboard"
]
