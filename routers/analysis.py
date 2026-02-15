"""
Router para endpoints de análisis
"""
from fastapi import APIRouter, HTTPException, status, Query
from typing import Optional
from loguru import logger

from models.audit import (
    AnalysisRequest,
    AnalysisResponse,
    AnalysisStatus,
    EvidenceRequest,
    EvidenceResponse
)
from services.analyzer import analyzer_service

router = APIRouter(prefix="/api", tags=["Analysis"])


@router.post(
    "/analyze",
    response_model=AnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analizar stored procedures",
    description="Inicia análisis de SPs seleccionados con regex y/o Gemini AI"
)
async def analyze_stored_procedures(request: AnalysisRequest):
    """Analizar stored procedures"""
    try:
        logger.info(
            f"🔍 Iniciando análisis de {len(request.sp_ids)} SPs "
            f"(AI: {request.use_ai}, Tipo: {request.analysis_type})"
        )
        
        result = await analyzer_service.analyze_stored_procedures(
            connection_id=request.connection_id,
            sp_ids=request.sp_ids,
            analysis_type=request.analysis_type,
            use_ai=request.use_ai,
            save_to_db=request.save_to_db
        )
        
        return AnalysisResponse(
            analysis_id=result["analysis_id"],
            status=result["status"],
            analyzed_count=result["analyzed_count"],
            findings_summary=result["findings_summary"],
            findings=result["findings"],
            started_at=result["started_at"],
            completed_at=result.get("completed_at"),
            duration_seconds=result.get("duration_seconds")
        )
    
    except ValueError as e:
        logger.error(f"❌ Error de validación: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    
    except Exception as e:
        logger.error(f"❌ Error en análisis: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error durante el análisis: {str(e)}"
        )


@router.get(
    "/analysis/{analysis_id}",
    summary="Obtener estado del análisis",
    description="Consulta el estado y progreso de un análisis"
)
async def get_analysis_status(analysis_id: str):
    """Obtener estado de análisis"""
    analysis = analyzer_service.get_analysis_status(analysis_id)
    
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Análisis {analysis_id} no encontrado"
        )
    
    return {
        "analysis_id": analysis_id,
        "status": analysis["status"],
        "started_at": analysis["started_at"],
        "completed_at": analysis.get("completed_at"),
        "total_sps": analysis["total_sps"],
        "analyzed_sps": analysis["analyzed_sps"],
        "duration_seconds": analysis.get("duration_seconds"),
        "findings_count": len(analysis.get("findings", []))
    }


@router.post(
    "/evidence",
    response_model=EvidenceResponse,
    status_code=status.HTTP_200_OK,
    summary="Generar evidencia real",
    description="Obtiene evidencia real solo con SELECT para un hallazgo puntual"
)
async def generate_evidence(request: EvidenceRequest):
    """Generar evidencia real para un hallazgo"""
    try:
        result = analyzer_service.build_evidence_for_finding(
            connection_id=request.connection_id,
            sp_id=request.sp_id,
            finding_type=request.finding_type,
            code_snippet=request.code_snippet
        )

        return EvidenceResponse(
            sp_id=result["sp_id"],
            evidence_data=result["evidence_data"]
        )

    except ValueError as e:
        logger.error(f"❌ Error de validación: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

    except Exception as e:
        logger.error(f"❌ Error generando evidencia: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error durante la generación de evidencia: {str(e)}"
        )


@router.get(
    "/analysis/{analysis_id}/findings",
    summary="Obtener hallazgos del análisis",
    description="Retorna todos los hallazgos detectados en el análisis"
)
async def get_analysis_findings(
    analysis_id: str,
    severity: Optional[str] = Query(None, description="Filtrar por severidad"),
    category: Optional[str] = Query(None, description="Filtrar por categoría")
):
    """Obtener hallazgos de un análisis"""
    analysis = analyzer_service.get_analysis_status(analysis_id)
    
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Análisis {analysis_id} no encontrado"
        )
    
    findings = analysis.get("findings", [])
    
    # Filtrar por severidad
    if severity:
        findings = [f for f in findings if f.get("severity") == severity.lower()]
    
    # Filtrar por categoría
    if category:
        findings = [f for f in findings if f.get("category") == category.lower()]
    
    return {
        "analysis_id": analysis_id,
        "total_findings": len(findings),
        "findings": findings
    }


@router.get(
    "/analysis/{analysis_id}/summary",
    summary="Resumen del análisis",
    description="Obtiene resumen estadístico del análisis"
)
async def get_analysis_summary(analysis_id: str):
    """Obtener resumen de análisis"""
    analysis = analyzer_service.get_analysis_status(analysis_id)
    
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Análisis {analysis_id} no encontrado"
        )
    
    findings = analysis.get("findings", [])
    
    # Agrupar por categoría
    by_category = {}
    for finding in findings:
        cat = finding.get("category", "unknown")
        by_category[cat] = by_category.get(cat, 0) + 1
    
    # Agrupar por SP
    by_sp = {}
    for finding in findings:
        sp = finding.get("sp_name", "unknown")
        by_sp[sp] = by_sp.get(sp, 0) + 1
    
    # Top SPs con más problemas
    top_problematic_sps = sorted(
        by_sp.items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]
    
    return {
        "analysis_id": analysis_id,
        "status": analysis["status"],
        "total_sps_analyzed": analysis["analyzed_sps"],
        "total_findings": len(findings),
        "findings_summary": analysis.get("findings_summary"),
        "findings_by_category": by_category,
        "top_problematic_sps": [
            {"sp_name": sp, "findings_count": count}
            for sp, count in top_problematic_sps
        ],
        "duration_seconds": analysis.get("duration_seconds")
    }
