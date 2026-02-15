"""
Modelos Pydantic para la API
"""
from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any, Literal
from datetime import datetime
from enum import Enum


# ============================================
# ENUMS
# ============================================

class ConnectionType(str, Enum):
    """Tipos de conexión a SQL Server"""
    SQL_AUTH = "sql_auth"
    WINDOWS_AUTH = "windows_auth"
    AZURE_AD = "azure_ad"


class AnalysisType(str, Enum):
    """Tipos de análisis"""
    FULL = "full"
    QUICK = "quick"


class SeverityLevel(str, Enum):
    """Niveles de severidad"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CategoryType(str, Enum):
    """Categorías de hallazgos"""
    SECURITY = "security"
    PERFORMANCE = "performance"
    COMPLIANCE = "compliance"
    MAINTAINABILITY = "maintainability"


class ReportFormat(str, Enum):
    """Formatos de reporte"""
    JSON = "json"
    PDF = "pdf"
    EXCEL = "excel"


class AnalysisStatus(str, Enum):
    """Estados del análisis"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


# ============================================
# REQUEST MODELS
# ============================================

class ConnectionRequest(BaseModel):
    """Request para conectar a SQL Server"""
    connection_type: ConnectionType = Field(..., description="Tipo de autenticación")
    server: str = Field(..., description="Dirección del servidor")
    database: Optional[str] = Field(None, description="Nombre de la base de datos")
    username: Optional[str] = Field(None, description="Usuario (requerido para SQL Auth)")
    password: Optional[str] = Field(None, description="Contraseña (requerido para SQL Auth)")
    port: int = Field(1433, description="Puerto del servidor")
    encrypt: bool = Field(True, description="Usar conexión encriptada")
    trust_server_certificate: bool = Field(True, description="Confiar en certificado del servidor")
    
    @validator('username', 'password')
    def validate_sql_auth(cls, v, values):
        """Validar que username/password existan si es SQL Auth"""
        if 'connection_type' in values and values['connection_type'] == ConnectionType.SQL_AUTH:
            if not v:
                raise ValueError("Username y password son requeridos para SQL Authentication")
        return v


class UseDatabaseRequest(BaseModel):
    """Request para seleccionar base de datos"""
    database: str = Field(..., description="Nombre de la base de datos")


class AnalysisRequest(BaseModel):
    """Request para analizar stored procedures"""
    connection_id: str = Field(..., description="ID de la conexión activa")
    sp_ids: List[int] = Field(..., description="IDs de SPs a analizar", min_items=1)
    analysis_type: AnalysisType = Field(AnalysisType.FULL, description="Tipo de análisis")
    use_ai: bool = Field(True, description="Usar Gemini AI")
    save_to_db: bool = Field(True, description="Guardar resultados en Supabase")


class ReportGenerationRequest(BaseModel):
    """Request para generar reporte"""
    analysis_id: str = Field(..., description="ID del análisis")
    format: ReportFormat = Field(..., description="Formato del reporte")
    include_code: bool = Field(True, description="Incluir código en el reporte")
    include_recommendations: bool = Field(True, description="Incluir recomendaciones")
    analysis_data: Optional[Dict[str, Any]] = Field(None, description="Datos del análisis (opcional)")


# ============================================
# RESPONSE MODELS
# ============================================

class DatabaseInfo(BaseModel):
    """Información de la base de datos"""
    name: str
    server: str
    version: str
    total_sps: int


class ConnectionResponse(BaseModel):
    """Response de conexión exitosa"""
    success: bool
    message: str
    database_info: DatabaseInfo
    connection_id: str


class StoredProcedureInfo(BaseModel):
    """Información de un Stored Procedure"""
    id: int
    schema: str
    name: str
    full_name: str
    created_date: Optional[datetime]
    modified_date: Optional[datetime]
    definition_preview: str
    line_count: int
    parameters: List[str]
    is_analyzed: bool = False


class StoredProceduresResponse(BaseModel):
    """Response con lista de Stored Procedures"""
    total: int
    page: int
    limit: int
    stored_procedures: List[StoredProcedureInfo]


class FindingLocation(BaseModel):
    """Ubicación de un hallazgo"""
    line: int
    code_snippet: str
    column: Optional[int] = None


class Finding(BaseModel):
    """Hallazgo detectado"""
    id: str
    sp_id: Optional[int] = None
    sp_name: str
    category: CategoryType
    severity: SeverityLevel
    type: str
    title: str
    description: str
    context_explanation: Optional[str] = None
    location: FindingLocation
    impact: str
    recommendation: str
    records_preview: Optional[List[Dict[str, Any]]] = None
    records_source: Optional[str] = None
    evidence_data: Optional[Dict[str, Any]] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    detected_by: str
    evidence: Optional[str] = None
    exploit_example: Optional[str] = None


class FindingsSummary(BaseModel):
    """Resumen de hallazgos"""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    
    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info


class AnalysisResponse(BaseModel):
    """Response del análisis"""
    analysis_id: str
    status: AnalysisStatus
    analyzed_count: int
    findings_summary: FindingsSummary
    findings: List[Finding]
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None


class EvidenceRequest(BaseModel):
    """Request para evidencia real por hallazgo"""
    connection_id: str = Field(..., description="ID de la conexión activa")
    sp_id: int = Field(..., description="ID del stored procedure")
    finding_type: str = Field(..., description="Tipo de hallazgo")
    code_snippet: Optional[str] = Field(None, description="Fragmento de codigo")


class EvidenceResponse(BaseModel):
    """Response de evidencia real"""
    sp_id: int
    evidence_data: Dict[str, Any]


class ReportMetadata(BaseModel):
    """Metadata del reporte"""
    analysis_id: str
    generated_at: datetime
    database: str
    analyzed_sps: int
    total_findings: int
    generated_by: str = "AuditDB Analyzer v1.0"


class ReportResponse(BaseModel):
    """Response de generación de reporte"""
    success: bool
    report_id: str
    report_type: ReportFormat
    file_path: str
    file_size: int
    download_url: str


class DashboardSummary(BaseModel):
    """Resumen para dashboard"""
    total_audits: int
    total_sps_analyzed: int
    total_findings: int
    average_risk_score: float
    recent_audits: List[Dict[str, Any]]
    findings_by_category: Dict[str, int]
    findings_by_severity: FindingsSummary


# ============================================
# DATABASE MODELS
# ============================================

class AuditoriaDB(BaseModel):
    """Modelo de Auditoría en Supabase"""
    id: Optional[str] = None
    connection_info: Dict[str, Any]
    database_name: str
    total_sps: int
    analyzed_sps: int = 0
    total_findings: int = 0
    risk_score: float = 0.0
    status: AnalysisStatus = AnalysisStatus.PENDING
    started_at: datetime
    completed_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.now)


class StoredProcedureDB(BaseModel):
    """Modelo de Stored Procedure en Supabase"""
    id: Optional[str] = None
    audit_id: str
    schema_name: str
    sp_name: str
    full_name: str
    definition: str
    line_count: int
    created_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    is_analyzed: bool = False
    created_at: datetime = Field(default_factory=datetime.now)


class HallazgoDB(BaseModel):
    """Modelo de Hallazgo en Supabase"""
    id: Optional[str] = None
    audit_id: str
    sp_id: str
    category: CategoryType
    severity: SeverityLevel
    type: str
    title: str
    description: str
    location: Dict[str, Any]
    impact: str
    recommendation: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    detected_by: str
    evidence: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.now)


class ReporteDB(BaseModel):
    """Modelo de Reporte en Supabase"""
    id: Optional[str] = None
    audit_id: str
    report_type: ReportFormat
    file_path: str
    file_size: int
    generated_at: datetime = Field(default_factory=datetime.now)


# ============================================
# ERROR RESPONSES
# ============================================

class ErrorResponse(BaseModel):
    """Response de error"""
    success: bool = False
    error: str
    detail: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)
