"""
AuditDB Analyzer - FastAPI Backend
Auditoría de base de datos para sistema de autenticación Hass Perú
"""
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
from loguru import logger
import sys
from datetime import datetime
from pathlib import Path

from config.settings import settings
from routers import connection, stored_procedures, analysis, reports, dashboard

# ============================================
# CONFIGURACIÓN DE LOGGING
# ============================================

# Configurar loguru
logger.remove()  # Remover handler por defecto

# Console handler
logger.add(
    sys.stderr,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
    level=settings.LOG_LEVEL,
    colorize=True
)

# File handler (rotativo)
logger.add(
    settings.LOG_FILE,
    rotation=settings.LOG_ROTATION,
    retention=settings.LOG_RETENTION,
    format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function} - {message}",
    level=settings.LOG_LEVEL,
    enqueue=True
)


# ============================================
# LIFESPAN EVENTS
# ============================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Eventos de inicio y cierre de la aplicación"""
    # Startup
    logger.info("=" * 80)
    logger.info(f"🚀 Iniciando {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"📝 Entorno: {settings.APP_ENV}")
    logger.info(f"🔧 Debug: {settings.APP_DEBUG}")
    logger.info("=" * 80)
    
    # Verificar conexión a Supabase
    try:
        from config.database import db
        _ = db.client
        logger.success("✅ Conexión a Supabase establecida")
    except Exception as e:
        logger.error(f"❌ Error conectando a Supabase: {e}")
    
    # Verificar Gemini AI
    try:
        from services.gemini_service import gemini_service
        logger.success("✅ Gemini AI configurado")
    except Exception as e:
        logger.warning(f"⚠️ Gemini AI no disponible: {e}")
    
    logger.info(f"🌐 Servidor escuchando en http://{settings.APP_HOST}:{settings.APP_PORT}")
    logger.info("📚 Documentación API: http://localhost:8000/docs")
    logger.info("=" * 80)
    
    yield
    
    # Shutdown
    logger.info("=" * 80)
    logger.info("🛑 Deteniendo AuditDB Analyzer...")
    
    # Cerrar conexiones SQL Server activas
    try:
        from services.sql_server import sql_service
        for conn_id in list(sql_service.sql_connection.connections.keys()):
            sql_service.sql_connection.close_connection(conn_id)
        logger.info("✅ Conexiones SQL Server cerradas")
    except Exception as e:
        logger.error(f"❌ Error cerrando conexiones: {e}")
    
    logger.info("👋 AuditDB Analyzer detenido correctamente")
    logger.info("=" * 80)


# ============================================
# CREAR APLICACIÓN FASTAPI
# ============================================

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="""
    ## 🔍 AuditDB Analyzer
    
    Sistema de auditoría automatizada de bases de datos SQL Server con análisis 
    de seguridad, performance y cumplimiento.
    
    ### Características:
    
    * 🔌 **Conexión Multi-Método**: SQL Auth, Windows Auth, Azure AD
    * 📊 **Análisis Híbrido**: Detección con Regex + Google Gemini AI
    * 🔒 **Seguridad**: SQL Injection, Credenciales, Encriptación
    * ⚡ **Performance**: Cursores, Índices, Queries optimizables
    * 📋 **Cumplimiento**: Auditoría, GDPR, Datos personales
    * 📄 **Reportes**: JSON, PDF profesional, Excel multi-hoja
    * 💾 **Persistencia**: Almacenamiento en Supabase
    
    ### Desarrollado para:
    Auditoría de base de datos en el sistema de autenticación y control 
    de accesos de Hass Perú.
    """,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)


# ============================================
# MIDDLEWARE
# ============================================

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Logging de requests
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Middleware para logging de requests"""
    start_time = datetime.now()
    
    # Log request
    logger.info(
        f"📨 {request.method} {request.url.path} "
        f"| Client: {request.client.host if request.client else 'unknown'}"
    )
    
    # Procesar request
    response = await call_next(request)
    
    # Calcular duración
    duration = (datetime.now() - start_time).total_seconds()
    
    # Log response
    status_emoji = "✅" if response.status_code < 400 else "❌"
    logger.info(
        f"{status_emoji} {request.method} {request.url.path} "
        f"| Status: {response.status_code} "
        f"| Duration: {duration:.3f}s"
    )
    
    return response


# ============================================
# EXCEPTION HANDLERS
# ============================================

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handler para errores de validación"""
    logger.error(f"❌ Error de validación: {exc}")
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "success": False,
            "error": "Error de validación",
            "detail": exc.errors(),
            "timestamp": datetime.now().isoformat()
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handler para excepciones generales"""
    logger.error(f"❌ Error no controlado: {exc}", exc_info=True)
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "error": "Error interno del servidor",
            "detail": str(exc) if settings.APP_DEBUG else "Contacte al administrador",
            "timestamp": datetime.now().isoformat()
        }
    )


# ============================================
# INCLUIR ROUTERS
# ============================================

app.include_router(connection.router)
app.include_router(stored_procedures.router)
app.include_router(analysis.router)
app.include_router(reports.router)
app.include_router(dashboard.router)


# ============================================
# ENDPOINT PARA DESCARGAR ARCHIVOS
# ============================================

from fastapi.responses import FileResponse
from fastapi import HTTPException

@app.get(
    "/download/{file_type}/{filename}",
    tags=["Download"],
    summary="Descargar archivo de reporte",
    description="Descarga archivos de reportes generados"
)
async def download_file(file_type: str, filename: str):
    """Endpoint para descargar archivos de reportes"""
    try:
        # Validar tipo de archivo
        valid_types = ["jsons", "pdfs", "excels"]
        if file_type not in valid_types:
            raise HTTPException(
                status_code=400,
                detail=f"Tipo de archivo inválido. Use: {', '.join(valid_types)}"
            )
        
        # Construir ruta del archivo
        file_path = Path(settings.REPORTS_DIR) / file_type / filename
        
        # Verificar que el archivo existe
        if not file_path.exists():
            logger.error(f"Archivo no encontrado: {file_path}")
            raise HTTPException(
                status_code=404,
                detail="Archivo no encontrado"
            )
        
        # Determinar el media type según la extensión
        media_types = {
            ".json": "application/json",
            ".pdf": "application/pdf",
            ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        }
        
        file_extension = file_path.suffix
        media_type = media_types.get(file_extension, "application/octet-stream")
        
        logger.info(f"📥 Descargando archivo: {filename}")
        
        return FileResponse(
            path=str(file_path),
            media_type=media_type,
            filename=filename,
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error descargando archivo: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error al descargar archivo: {str(e)}"
        )


# ============================================
# ENDPOINTS RAÍZ
# ============================================

@app.get(
    "/",
    tags=["Root"],
    summary="Información de la API",
    description="Retorna información básica de la API"
)
async def root():
    """Endpoint raíz"""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
        "environment": settings.APP_ENV,
        "docs": "/docs",
        "redoc": "/redoc",
        "timestamp": datetime.now().isoformat()
    }


@app.get(
    "/health",
    tags=["Root"],
    summary="Health check",
    description="Verifica estado de salud de la aplicación"
)
async def health_check():
    """Health check endpoint"""
    
    # Verificar Supabase
    supabase_status = "ok"
    try:
        from config.database import db
        _ = db.client
    except Exception as e:
        supabase_status = f"error: {str(e)}"
    
    # Verificar Gemini
    gemini_status = "ok"
    try:
        from services.gemini_service import gemini_service
    except Exception as e:
        gemini_status = f"error: {str(e)}"
    
    is_healthy = supabase_status == "ok" and gemini_status == "ok"
    
    return {
        "status": "healthy" if is_healthy else "degraded",
        "timestamp": datetime.now().isoformat(),
        "services": {
            "api": "ok",
            "supabase": supabase_status,
            "gemini_ai": gemini_status
        },
        "version": settings.APP_VERSION
    }


@app.get(
    "/api/info",
    tags=["Root"],
    summary="Información de la API",
    description="Información detallada de endpoints disponibles"
)
async def api_info():
    """Información de la API"""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "endpoints": {
            "connection": {
                "POST /api/connect": "Conectar a SQL Server",
                "GET /api/connections": "Listar conexiones activas",
                "DELETE /api/connections/{id}": "Cerrar conexión"
            },
            "stored_procedures": {
                "GET /api/stored-procedures": "Listar stored procedures",
                "GET /api/stored-procedures/{id}": "Obtener detalle de SP",
                "GET /api/schemas": "Listar schemas"
            },
            "analysis": {
                "POST /api/analyze": "Analizar stored procedures",
                "GET /api/analysis/{id}": "Estado del análisis",
                "GET /api/analysis/{id}/findings": "Obtener hallazgos"
            },
            "reports": {
                "POST /api/reports/generate": "Generar reporte",
                "GET /api/reports/{id}/json": "Descargar JSON",
                "POST /api/reports/{id}/pdf": "Descargar PDF",
                "POST /api/reports/{id}/excel": "Descargar Excel"
            },
            "dashboard": {
                "GET /api/dashboard/summary": "Resumen para dashboard",
                "GET /api/dashboard/charts": "Datos para gráficos"
            }
        },
        "features": [
            "Multi-method SQL Server connection",
            "Hybrid analysis (Regex + Gemini AI)",
            "Security vulnerability detection",
            "Performance optimization suggestions",
            "Compliance checking",
            "Multi-format reporting (JSON, PDF, Excel)",
            "Supabase persistence"
        ]
    }


# ============================================
# MAIN (para desarrollo)
# ============================================

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        reload=settings.APP_DEBUG,
        log_level=settings.LOG_LEVEL.lower()
    )
