"""
Router para endpoints de reportes
"""
from fastapi import APIRouter, HTTPException, status, Query
from fastapi.responses import FileResponse
from typing import Optional
from loguru import logger
from pathlib import Path

from models.audit import (
    ReportGenerationRequest,
    ReportResponse,
    ReportFormat,
    AnalysisStatus
)
from services.report_generator import report_generator
from services.analyzer import analyzer_service

router = APIRouter(prefix="/api", tags=["Reports"])


@router.post(
    "/reports/generate",
    response_model=ReportResponse,
    summary="Generar reporte",
    description="Genera reporte en formato especificado (JSON, PDF, Excel)"
)
async def generate_report(request: ReportGenerationRequest):
    """Generar reporte de análisis"""
    try:
        logger.info(
            f"📄 Generando reporte {request.format.value} "
            f"para análisis {request.analysis_id}"
        )
        
        # Obtener datos del análisis
        # Priorizar datos enviados en el request, luego buscar en memoria
        analysis = request.analysis_data
        
        if not analysis:
            # Intentar obtener de memoria
            analysis = analyzer_service.get_analysis_status(request.analysis_id)
        
        if not analysis:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Análisis {request.analysis_id} no encontrado. Por favor, ejecuta el análisis nuevamente."
            )
        
        # Generar reporte directamente sin validar estado
        
        # Generar reporte
        result = await report_generator.generate_report(
            analysis_id=request.analysis_id,
            audit_db_id=request.analysis_id,  # Usar mismo ID si no hay audit_db_id
            report_format=request.format,
            analysis_data=analysis,
            include_code=request.include_code,
            include_recommendations=request.include_recommendations
        )
        
        return ReportResponse(**result)
    
    except HTTPException:
        raise
    
    except Exception as e:
        logger.error(f"❌ Error generando reporte: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al generar reporte: {str(e)}"
        )


@router.get(
    "/reports/{analysis_id}/json",
    summary="Descargar reporte JSON",
    description="Descarga reporte en formato JSON"
)
async def download_json_report(
    analysis_id: str,
    include_code: bool = Query(True, description="Incluir código"),
    include_recommendations: bool = Query(True, description="Incluir recomendaciones")
):
    """Descargar reporte JSON"""
    try:
        analysis = analyzer_service.get_analysis_status(analysis_id)
        
        if not analysis:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Análisis {analysis_id} no encontrado"
            )
        
        result = await report_generator.generate_report(
            analysis_id=analysis_id,
            audit_db_id=analysis_id,
            report_format=ReportFormat.JSON,
            analysis_data=analysis,
            include_code=include_code,
            include_recommendations=include_recommendations
        )
        
        file_path = result["file_path"]
        
        if not Path(file_path).exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Archivo de reporte no encontrado"
            )
        
        return FileResponse(
            path=file_path,
            media_type="application/json",
            filename=Path(file_path).name
        )
    
    except HTTPException:
        raise
    
    except Exception as e:
        logger.error(f"❌ Error descargando reporte JSON: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post(
    "/reports/{analysis_id}/pdf",
    summary="Generar y descargar PDF",
    description="Genera y descarga reporte en formato PDF"
)
async def download_pdf_report(
    analysis_id: str,
    include_code: bool = Query(True, description="Incluir código"),
    include_recommendations: bool = Query(True, description="Incluir recomendaciones")
):
    """Generar y descargar reporte PDF"""
    try:
        analysis = analyzer_service.get_analysis_status(analysis_id)
        
        if not analysis:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Análisis {analysis_id} no encontrado"
            )
        
        result = await report_generator.generate_report(
            analysis_id=analysis_id,
            audit_db_id=analysis_id,
            report_format=ReportFormat.PDF,
            analysis_data=analysis,
            include_code=include_code,
            include_recommendations=include_recommendations
        )
        
        file_path = result["file_path"]
        
        if not Path(file_path).exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Archivo de reporte no encontrado"
            )
        
        return FileResponse(
            path=file_path,
            media_type="application/pdf",
            filename=Path(file_path).name
        )
    
    except HTTPException:
        raise
    
    except Exception as e:
        logger.error(f"❌ Error generando PDF: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post(
    "/reports/{analysis_id}/excel",
    summary="Generar y descargar Excel",
    description="Genera y descarga reporte en formato Excel"
)
async def download_excel_report(
    analysis_id: str,
    include_code: bool = Query(False, description="Incluir código"),
    include_recommendations: bool = Query(True, description="Incluir recomendaciones")
):
    """Generar y descargar reporte Excel"""
    try:
        analysis = analyzer_service.get_analysis_status(analysis_id)
        
        if not analysis:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Análisis {analysis_id} no encontrado"
            )
        
        result = await report_generator.generate_report(
            analysis_id=analysis_id,
            audit_db_id=analysis_id,
            report_format=ReportFormat.EXCEL,
            analysis_data=analysis,
            include_code=include_code,
            include_recommendations=include_recommendations
        )
        
        file_path = result["file_path"]
        
        if not Path(file_path).exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Archivo de reporte no encontrado"
            )
        
        return FileResponse(
            path=file_path,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            filename=Path(file_path).name
        )
    
    except HTTPException:
        raise
    
    except Exception as e:
        logger.error(f"❌ Error generando Excel: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get(
    "/reports",
    summary="Listar reportes generados",
    description="Lista todos los reportes generados en el sistema"
)
async def list_reports(
    analysis_id: Optional[str] = Query(None, description="Filtrar por análisis")
):
    """Listar reportes generados"""
    try:
        # Por ahora retorna estructura básica
        # En producción, consultar a Supabase
        
        return {
            "total": 0,
            "reports": []
        }
    
    except Exception as e:
        logger.error(f"❌ Error listando reportes: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
