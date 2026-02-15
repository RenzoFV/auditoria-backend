"""
Router para endpoints de stored procedures
"""
from fastapi import APIRouter, HTTPException, Query, status
from typing import Optional
from loguru import logger

from models.audit import StoredProceduresResponse, StoredProcedureInfo
from services.sql_server import sql_service

router = APIRouter(prefix="/api", tags=["Stored Procedures"])


@router.get(
    "/stored-procedures",
    response_model=StoredProceduresResponse,
    summary="Listar stored procedures",
    description="Lista todos los stored procedures de la base de datos con paginación"
)
async def list_stored_procedures(
    connection_id: str = Query(..., description="ID de conexión activa"),
    schema: Optional[str] = Query(None, description="Filtrar por schema"),
    search: Optional[str] = Query(None, description="Buscar por nombre"),
    page: int = Query(1, ge=1, description="Número de página"),
    limit: int = Query(50, ge=1, le=500, description="Resultados por página")
):
    """Listar stored procedures con paginación"""
    try:
        logger.info(f"📋 Listando SPs (página {page}, límite {limit})")
        
        result = sql_service.list_stored_procedures(
            connection_id=connection_id,
            schema=schema,
            search=search,
            page=page,
            limit=limit
        )
        
        # Convertir a modelo Pydantic
        sps = [StoredProcedureInfo(**sp) for sp in result["stored_procedures"]]
        
        return StoredProceduresResponse(
            total=result["total"],
            page=result["page"],
            limit=result["limit"],
            stored_procedures=sps
        )
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    
    except Exception as e:
        logger.error(f"❌ Error listando SPs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al listar stored procedures: {str(e)}"
        )


@router.get(
    "/stored-procedures/{sp_id}",
    summary="Obtener stored procedure",
    description="Obtiene detalle de un stored procedure específico"
)
async def get_stored_procedure(
    sp_id: int,
    connection_id: str = Query(..., description="ID de conexión activa")
):
    """Obtener detalle de un SP"""
    try:
        sp = sql_service.get_stored_procedure(connection_id, sp_id)
        
        if not sp:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Stored procedure {sp_id} no encontrado"
            )
        
        return {
            "id": sp.object_id,
            "schema": sp.schema_name,
            "name": sp.procedure_name,
            "full_name": sp.full_name,
            "created_date": sp.create_date,
            "modified_date": sp.modify_date,
            "definition": sp.definition,
            "line_count": sp.line_count
        }
    
    except HTTPException:
        raise
    
    except Exception as e:
        logger.error(f"❌ Error obteniendo SP {sp_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get(
    "/schemas",
    summary="Listar schemas",
    description="Obtiene lista de schemas disponibles en la base de datos"
)
async def list_schemas(
    connection_id: str = Query(..., description="ID de conexión activa")
):
    """Listar schemas disponibles"""
    try:
        schemas = sql_service.get_schemas(connection_id)
        
        return {
            "total": len(schemas),
            "schemas": schemas
        }
    
    except Exception as e:
        logger.error(f"❌ Error listando schemas: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post(
    "/stored-procedures/refresh",
    summary="Refrescar lista de SPs",
    description="Re-extrae la lista completa de stored procedures"
)
async def refresh_stored_procedures(
    connection_id: str = Query(..., description="ID de conexión activa")
):
    """Refrescar lista de stored procedures"""
    try:
        # Re-obtener información de la base de datos
        db_info = sql_service.get_database_info(connection_id)
        
        return {
            "success": True,
            "message": "Lista de stored procedures refrescada",
            "total_sps": db_info["total_sps"]
        }
    
    except Exception as e:
        logger.error(f"❌ Error refrescando SPs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
