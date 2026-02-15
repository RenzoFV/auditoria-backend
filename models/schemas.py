"""
Schemas para SQL Server queries
"""
from typing import List, Optional, Dict
from dataclasses import dataclass
from datetime import datetime


@dataclass
class StoredProcedureSchema:
    """Schema para Stored Procedure de SQL Server"""
    object_id: int
    schema_name: str
    procedure_name: str
    create_date: datetime
    modify_date: datetime
    definition: str
    
    @property
    def full_name(self) -> str:
        """Nombre completo del SP"""
        return f"{self.schema_name}.{self.procedure_name}"
    
    @property
    def line_count(self) -> int:
        """Contar líneas de código"""
        return len(self.definition.split('\n'))
    
    @property
    def definition_preview(self) -> str:
        """Preview del código (primeras 200 chars)"""
        return self.definition[:200] + "..." if len(self.definition) > 200 else self.definition


@dataclass
class ParameterSchema:
    """Schema para parámetros de SP"""
    parameter_name: str
    data_type: str
    max_length: Optional[int]
    is_output: bool


@dataclass
class DatabaseSchema:
    """Schema de información de la base de datos"""
    database_name: str
    server_name: str
    version: str
    collation: str
    compatibility_level: int
    total_objects: int


# ============================================
# QUERIES SQL
# ============================================

class SQLQueries:
    """Queries SQL predefinidos"""
    
    # Obtener versión del servidor
    GET_SERVER_VERSION = """
    SELECT 
        @@VERSION AS version,
        @@SERVERNAME AS server_name,
        DB_NAME() AS database_name
    """
    
    # Listar todos los stored procedures
    LIST_STORED_PROCEDURES = """
    SELECT 
        o.object_id,
        SCHEMA_NAME(o.schema_id) AS schema_name,
        o.name AS procedure_name,
        o.create_date,
        o.modify_date,
        m.definition
    FROM sys.objects o
    INNER JOIN sys.sql_modules m ON o.object_id = m.object_id
    WHERE o.type = 'P'
        AND o.is_ms_shipped = 0
        {where_clause}
    ORDER BY schema_name, procedure_name
    OFFSET {offset} ROWS
    FETCH NEXT {limit} ROWS ONLY
    """
    
    # Contar stored procedures
    COUNT_STORED_PROCEDURES = """
    SELECT COUNT(*) AS total
    FROM sys.objects o
    WHERE o.type = 'P'
        AND o.is_ms_shipped = 0
        {where_clause}
    """
    
    # Obtener definición de un SP específico
    GET_SP_DEFINITION = """
    SELECT 
        o.object_id,
        SCHEMA_NAME(o.schema_id) AS schema_name,
        o.name AS procedure_name,
        o.create_date,
        o.modify_date,
        m.definition
    FROM sys.objects o
    INNER JOIN sys.sql_modules m ON o.object_id = m.object_id
    WHERE o.object_id = ?
        AND o.type = 'P'
    """
    
    # Obtener parámetros de un SP
    GET_SP_PARAMETERS = """
    SELECT 
        p.name AS parameter_name,
        TYPE_NAME(p.user_type_id) AS data_type,
        p.max_length,
        p.is_output
    FROM sys.parameters p
    WHERE p.object_id = ?
    ORDER BY p.parameter_id
    """
    
    # Obtener schemas disponibles
    GET_SCHEMAS = """
    SELECT DISTINCT SCHEMA_NAME(schema_id) AS schema_name
    FROM sys.objects
    WHERE type = 'P'
        AND is_ms_shipped = 0
    ORDER BY schema_name
    """
    
    # Buscar SPs por nombre
    SEARCH_STORED_PROCEDURES = """
    SELECT 
        o.object_id,
        SCHEMA_NAME(o.schema_id) AS schema_name,
        o.name AS procedure_name,
        o.create_date,
        o.modify_date,
        m.definition
    FROM sys.objects o
    INNER JOIN sys.sql_modules m ON o.object_id = m.object_id
    WHERE o.type = 'P'
        AND o.is_ms_shipped = 0
        AND (
            o.name LIKE ?
            OR SCHEMA_NAME(o.schema_id) LIKE ?
        )
    ORDER BY schema_name, procedure_name
    """
    
    # Obtener información de la base de datos
    GET_DATABASE_INFO = """
    SELECT 
        DB_NAME() AS database_name,
        @@SERVERNAME AS server_name,
        @@VERSION AS version,
        (SELECT COUNT(*) FROM sys.objects WHERE type = 'P' AND is_ms_shipped = 0) AS total_sps
    """

    # Listar bases de datos disponibles
    LIST_DATABASES = """
    SELECT name
    FROM sys.databases
    WHERE state = 0
    ORDER BY name
    """
    
    # Test de conexión
    TEST_CONNECTION = "SELECT 1 AS test"
    
    @staticmethod
    def build_where_clause(schema: Optional[str] = None, search: Optional[str] = None) -> str:
        """Construir cláusula WHERE dinámica"""
        conditions = []
        
        if schema:
            conditions.append(f"AND SCHEMA_NAME(o.schema_id) = '{schema}'")
        
        if search:
            conditions.append(f"AND o.name LIKE '%{search}%'")
        
        return " ".join(conditions) if conditions else ""
