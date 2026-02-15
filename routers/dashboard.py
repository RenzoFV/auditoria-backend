"""
Router para dashboard y estadísticas
"""
from fastapi import APIRouter, HTTPException, status
from loguru import logger

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get(
    "/summary",
    summary="Resumen para dashboard",
    description="Obtiene resumen general de auditorías y hallazgos"
)
async def get_dashboard_summary():
    """Obtener resumen para dashboard"""
    try:
        # TODO: Implementar consultas a Supabase
        # Por ahora retorna estructura de ejemplo
        
        return {
            "total_audits": 0,
            "total_sps_analyzed": 0,
            "total_findings": 0,
            "average_risk_score": 0.0,
            "recent_audits": [],
            "findings_by_category": {
                "security": 0,
                "performance": 0,
                "compliance": 0,
                "maintainability": 0
            },
            "findings_by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
        }
    
    except Exception as e:
        logger.error(f"❌ Error obteniendo resumen: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get(
    "/charts",
    summary="Datos para gráficos",
    description="Obtiene datos formateados para gráficos del dashboard"
)
async def get_dashboard_charts():
    """Obtener datos para gráficos"""
    try:
        # TODO: Implementar consultas a Supabase
        
        return {
            "findings_trend": [],
            "severity_distribution": [],
            "category_distribution": [],
            "top_vulnerable_sps": []
        }
    
    except Exception as e:
        logger.error(f"❌ Error obteniendo datos de gráficos: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
