"""
Servicio de conexión y extracción de datos de SQL Server
"""
import pyodbc
from typing import Optional, List, Dict, Any
from datetime import datetime
from loguru import logger

from models.schemas import (
    StoredProcedureSchema,
    ParameterSchema,
    DatabaseSchema,
    SQLQueries
)
from models.audit import ConnectionType
from config.settings import settings
from utils.helpers import generate_uuid


class SQLServerConnection:
    """Manejo de conexión a SQL Server"""
    
    def __init__(self):
        self.connections: Dict[str, pyodbc.Connection] = {}
    
    def connect(
        self,
        connection_type: ConnectionType,
        server: str,
        database: Optional[str],
        username: Optional[str] = None,
        password: Optional[str] = None,
        port: int = 1433,
        driver: str = "ODBC Driver 17 for SQL Server",
        encrypt: bool = True,
        trust_server_certificate: bool = True
    ) -> tuple[str, pyodbc.Connection]:
        """
        Conectar a SQL Server con diferentes métodos de autenticación
        
        Returns:
            tuple: (connection_id, connection)
        """
        try:
            database_name = database or "master"

            # Construir connection string
            if connection_type == ConnectionType.SQL_AUTH:
                if not username or not password:
                    raise ValueError("Username y password requeridos para SQL Authentication")
                
                conn_str = (
                    f"DRIVER={{{driver}}};"
                    f"SERVER={server},{port};"
                    f"DATABASE={database_name};"
                    f"UID={username};"
                    f"PWD={password};"
                    f"Encrypt={'yes' if encrypt else 'no'};"
                    f"TrustServerCertificate={'yes' if trust_server_certificate else 'no'};"
                )
            
            elif connection_type == ConnectionType.WINDOWS_AUTH:
                conn_str = (
                    f"DRIVER={{{driver}}};"
                    f"SERVER={server},{port};"
                    f"DATABASE={database_name};"
                    f"Trusted_Connection=yes;"
                    f"Encrypt={'yes' if encrypt else 'no'};"
                    f"TrustServerCertificate={'yes' if trust_server_certificate else 'no'};"
                )
            
            elif connection_type == ConnectionType.AZURE_AD:
                conn_str = (
                    f"DRIVER={{{driver}}};"
                    f"SERVER={server},{port};"
                    f"DATABASE={database_name};"
                    f"Authentication=ActiveDirectoryInteractive;"
                    f"Encrypt=yes;"
                )
            
            else:
                raise ValueError(f"Tipo de conexión no soportado: {connection_type}")
            
            # Intentar conexión
            logger.info(f"🔌 Conectando a {server}/{database_name}...")
            connection = pyodbc.connect(conn_str, timeout=10)
            
            # Generar ID de conexión
            connection_id = generate_uuid()
            self.connections[connection_id] = connection
            
            logger.success(f"✅ Conexión exitosa: {connection_id}")
            return connection_id, connection
        
        except pyodbc.Error as e:
            logger.error(f"❌ Error de conexión SQL Server: {e}")
            raise
        except Exception as e:
            logger.error(f"❌ Error inesperado: {e}")
            raise
    
    def get_connection(self, connection_id: str) -> Optional[pyodbc.Connection]:
        """Obtener conexión por ID"""
        return self.connections.get(connection_id)
    
    def close_connection(self, connection_id: str) -> bool:
        """Cerrar conexión"""
        if connection_id in self.connections:
            try:
                self.connections[connection_id].close()
                del self.connections[connection_id]
                logger.info(f"🔌 Conexión cerrada: {connection_id}")
                return True
            except Exception as e:
                logger.error(f"❌ Error cerrando conexión: {e}")
                return False
        return False
    
    def test_connection(self, connection_id: str) -> bool:
        """Probar si la conexión está activa"""
        conn = self.get_connection(connection_id)
        if not conn:
            return False
        
        try:
            cursor = conn.cursor()
            cursor.execute(SQLQueries.TEST_CONNECTION)
            cursor.fetchone()
            cursor.close()
            return True
        except:
            return False


class SQLServerService:
    """Servicio para interactuar con SQL Server"""
    
    def __init__(self):
        self.sql_connection = SQLServerConnection()
    
    def connect_database(
        self,
        connection_type: ConnectionType,
        server: str,
        database: Optional[str],
        username: Optional[str] = None,
        password: Optional[str] = None,
        port: int = 1433
    ) -> Dict[str, Any]:
        """Conectar a base de datos y retornar información"""
        
        # Conectar
        connection_id, conn = self.sql_connection.connect(
            connection_type=connection_type,
            server=server,
            database=database,
            username=username,
            password=password,
            port=port
        )
        
        # Obtener información de la base de datos
        db_info = self.get_database_info(connection_id)
        
        return {
            "connection_id": connection_id,
            "database_info": db_info
        }
    
    def get_database_info(self, connection_id: str) -> Dict[str, Any]:
        """Obtener información de la base de datos"""
        conn = self.sql_connection.get_connection(connection_id)
        if not conn:
            raise ValueError(
                "Conexión no encontrada. Por favor, reconecta a la base de datos. "
                "Las conexiones se pierden al reiniciar el servidor."
            )
        
        cursor = conn.cursor()
        
        try:
            # Obtener versión e información
            cursor.execute(SQLQueries.GET_DATABASE_INFO)
            row = cursor.fetchone()
            
            if not row:
                raise Exception("No se pudo obtener información de la BD")
            
            # Extraer versión resumida
            version_full = row.version if hasattr(row, 'version') else str(row[2])
            version = version_full.split('\n')[0] if version_full else "Unknown"
            
            return {
                "name": row.database_name if hasattr(row, 'database_name') else row[0],
                "server": row.server_name if hasattr(row, 'server_name') else row[1],
                "version": version,
                "total_sps": row.total_sps if hasattr(row, 'total_sps') else row[3]
            }
        
        finally:
            cursor.close()

    def list_databases(self, connection_id: str) -> List[str]:
        """Listar bases de datos disponibles"""
        conn = self.sql_connection.get_connection(connection_id)
        if not conn:
            raise ValueError("Conexión no encontrada")

        cursor = conn.cursor()
        try:
            cursor.execute(SQLQueries.LIST_DATABASES)
            return [row[0] for row in cursor.fetchall()]
        finally:
            cursor.close()

    def use_database(self, connection_id: str, database: str) -> Dict[str, Any]:
        """Cambiar base de datos activa para la conexión"""
        conn = self.sql_connection.get_connection(connection_id)
        if not conn:
            raise ValueError("Conexión no encontrada")

        cursor = conn.cursor()
        try:
            cursor.execute(f"USE [{database}]")
            conn.commit()
        finally:
            cursor.close()

        return self.get_database_info(connection_id)
    
    def list_stored_procedures(
        self,
        connection_id: str,
        schema: Optional[str] = None,
        search: Optional[str] = None,
        page: int = 1,
        limit: int = 50
    ) -> Dict[str, Any]:
        """Listar stored procedures con paginación"""
        conn = self.sql_connection.get_connection(connection_id)
        if not conn:
            raise ValueError("Conexión no encontrada")
        
        offset = (page - 1) * limit
        where_clause = SQLQueries.build_where_clause(schema, search)
        
        cursor = conn.cursor()
        
        try:
            # Contar total
            count_query = SQLQueries.COUNT_STORED_PROCEDURES.format(where_clause=where_clause)
            cursor.execute(count_query)
            total = cursor.fetchone()[0]
            
            # Obtener SPs
            list_query = SQLQueries.LIST_STORED_PROCEDURES.format(
                where_clause=where_clause,
                offset=offset,
                limit=limit
            )
            cursor.execute(list_query)
            
            sps = []
            for row in cursor.fetchall():
                sp = StoredProcedureSchema(
                    object_id=row.object_id,
                    schema_name=row.schema_name,
                    procedure_name=row.procedure_name,
                    create_date=row.create_date,
                    modify_date=row.modify_date,
                    definition=row.definition or ""
                )
                
                # Obtener parámetros
                parameters = self._get_sp_parameters(conn, sp.object_id)
                
                sps.append({
                    "id": sp.object_id,
                    "schema": sp.schema_name,
                    "name": sp.procedure_name,
                    "full_name": sp.full_name,
                    "created_date": sp.create_date,
                    "modified_date": sp.modify_date,
                    "definition_preview": sp.definition_preview,
                    "line_count": sp.line_count,
                    "parameters": [f"{p.parameter_name} {p.data_type}" for p in parameters],
                    "is_analyzed": False
                })
            
            return {
                "total": total,
                "page": page,
                "limit": limit,
                "stored_procedures": sps
            }
        
        finally:
            cursor.close()

    def fetch_records(
        self,
        connection_id: str,
        query: str,
        max_rows: int = 10
    ) -> List[Dict[str, Any]]:
        """Ejecutar consulta SELECT y retornar hasta max_rows filas"""
        conn = self.sql_connection.get_connection(connection_id)
        if not conn:
            raise ValueError("Conexión no encontrada")

        if not query.strip().lower().startswith("select"):
            raise ValueError("Solo se permiten consultas SELECT")

        cursor = conn.cursor()
        try:
            cursor.execute(query)
            columns = [col[0] for col in cursor.description] if cursor.description else []
            rows = cursor.fetchmany(max_rows)

            results = []
            for row in rows:
                results.append({
                    columns[i]: row[i]
                    for i in range(len(columns))
                })
            return results
        finally:
            cursor.close()

    def get_table_columns(
        self,
        connection_id: str,
        schema: str,
        table: str
    ) -> List[str]:
        """Obtener columnas de una tabla (solo lectura)"""
        conn = self.sql_connection.get_connection(connection_id)
        if not conn:
            raise ValueError("Conexión no encontrada")

        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                SELECT COLUMN_NAME
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
                ORDER BY ORDINAL_POSITION
                """,
                (schema, table)
            )
            return [row[0] for row in cursor.fetchall()]
        finally:
            cursor.close()
    
    def get_stored_procedure(self, connection_id: str, sp_id: int) -> Optional[StoredProcedureSchema]:
        """Obtener un stored procedure específico"""
        conn = self.sql_connection.get_connection(connection_id)
        if not conn:
            raise ValueError("Conexión no encontrada")
        
        cursor = conn.cursor()
        
        try:
            cursor.execute(SQLQueries.GET_SP_DEFINITION, sp_id)
            row = cursor.fetchone()
            
            if not row:
                return None
            
            return StoredProcedureSchema(
                object_id=row.object_id,
                schema_name=row.schema_name,
                procedure_name=row.procedure_name,
                create_date=row.create_date,
                modify_date=row.modify_date,
                definition=row.definition or ""
            )
        
        finally:
            cursor.close()
    
    def _get_sp_parameters(self, conn: pyodbc.Connection, object_id: int) -> List[ParameterSchema]:
        """Obtener parámetros de un SP"""
        cursor = conn.cursor()
        
        try:
            cursor.execute(SQLQueries.GET_SP_PARAMETERS, object_id)
            
            parameters = []
            for row in cursor.fetchall():
                parameters.append(ParameterSchema(
                    parameter_name=row.parameter_name,
                    data_type=row.data_type,
                    max_length=row.max_length,
                    is_output=row.is_output
                ))
            
            return parameters
        
        finally:
            cursor.close()
    
    def get_schemas(self, connection_id: str) -> List[str]:
        """Obtener lista de schemas disponibles"""
        conn = self.sql_connection.get_connection(connection_id)
        if not conn:
            raise ValueError("Conexión no encontrada")
        
        cursor = conn.cursor()
        
        try:
            cursor.execute(SQLQueries.GET_SCHEMAS)
            return [row.schema_name for row in cursor.fetchall()]
        
        finally:
            cursor.close()


# Instancia global del servicio
sql_service = SQLServerService()
