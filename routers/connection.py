"""
Router para endpoints de conexión a SQL Server
"""
from fastapi import APIRouter, HTTPException, status
from typing import List
from loguru import logger

from models.audit import (
    ConnectionRequest,
    ConnectionResponse,
    DatabaseInfo,
    ErrorResponse,
    UseDatabaseRequest
)
from services.sql_server import sql_service

router = APIRouter(prefix="/api", tags=["Connection"])


@router.post(
    "/connect",
    response_model=ConnectionResponse,
    status_code=status.HTTP_200_OK,
    summary="Conectar a SQL Server",
    description="Establece conexión con SQL Server usando diferentes métodos de autenticación"
)
async def connect_sqlserver(request: ConnectionRequest):
    """Conectar a base de datos SQL Server"""
    try:
        logger.info(f"📡 Intento de conexión a {request.server}/{request.database}")
        
        result = sql_service.connect_database(
            connection_type=request.connection_type,
            server=request.server,
            database=request.database,
            username=request.username,
            password=request.password,
            port=request.port
        )
        
        return ConnectionResponse(
            success=True,
            message="Conexión exitosa",
            database_info=DatabaseInfo(**result["database_info"]),
            connection_id=result["connection_id"]
        )
    
    except ValueError as e:
        logger.error(f"❌ Error de validación: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    
    except Exception as e:
        logger.error(f"❌ Error de conexión: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al conectar a {request.server}: {str(e)}"
        )


@router.get(
    "/connections",
    summary="Listar conexiones activas",
    description="Obtiene lista de conexiones activas al servidor"
)
async def list_connections():
    """Listar conexiones activas"""
    connections = sql_service.sql_connection.connections
    
    return {
        "total": len(connections),
        "connections": [
            {
                "connection_id": conn_id,
                "is_active": sql_service.sql_connection.test_connection(conn_id)
            }
            for conn_id in connections.keys()
        ]
    }


@router.get(
    "/databases",
    summary="Listar bases de datos",
    description="Obtiene lista de bases disponibles en el servidor"
)
async def list_databases(connection_id: str):
    """Listar bases de datos disponibles"""
    try:
        databases = sql_service.list_databases(connection_id)
        return {
            "total": len(databases),
            "databases": databases
        }
    except Exception as e:
        logger.error(f"❌ Error listando bases: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post(
    "/connections/{connection_id}/use-database",
    summary="Seleccionar base de datos",
    description="Cambia la base de datos activa en la conexión"
)
async def use_database(connection_id: str, request: UseDatabaseRequest):
    """Seleccionar base de datos"""
    try:
        db_info = sql_service.use_database(connection_id, request.database)
        return {
            "success": True,
            "database_info": DatabaseInfo(**db_info)
        }
    except Exception as e:
        logger.error(f"❌ Error seleccionando base: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.delete(
    "/connections/{connection_id}",
    summary="Cerrar conexión",
    description="Cierra una conexión específica por ID"
)
async def close_connection(connection_id: str):
    """Cerrar conexión específica"""
    success = sql_service.sql_connection.close_connection(connection_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Conexión {connection_id} no encontrada"
        )
    
    return {
        "success": True,
        "message": f"Conexión {connection_id} cerrada exitosamente"
    }


@router.get(
    "/connections/{connection_id}/test",
    summary="Probar conexión",
    description="Verifica si una conexión está activa"
)
async def test_connection(connection_id: str):
    """Probar si conexión está activa"""
    is_active = sql_service.sql_connection.test_connection(connection_id)
    
    return {
        "connection_id": connection_id,
        "is_active": is_active
    }
