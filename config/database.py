"""
Configuración de Supabase Database
"""
from supabase import create_client, Client
from typing import Optional
from loguru import logger
from config.settings import settings


class SupabaseDatabase:
    """Clase para manejar conexión con Supabase"""
    
    def __init__(self):
        self._client: Optional[Client] = None
    
    @property
    def client(self) -> Client:
        """Obtener cliente de Supabase (Singleton)"""
        if self._client is None:
            try:
                self._client = create_client(
                    settings.SUPABASE_URL,
                    settings.SUPABASE_KEY
                )
                logger.info("✅ Conexión a Supabase establecida")
            except Exception as e:
                logger.error(f"❌ Error conectando a Supabase: {e}")
                raise
        return self._client
    
    async def insert_auditoria(self, data: dict) -> dict:
        """Insertar nueva auditoría"""
        try:
            response = self.client.table("auditorias").insert(data).execute()
            logger.info(f"📝 Auditoría creada: {response.data[0]['id']}")
            return response.data[0]
        except Exception as e:
            logger.error(f"❌ Error insertando auditoría: {e}")
            raise
    
    async def insert_stored_procedure(self, data: dict) -> dict:
        """Insertar stored procedure"""
        try:
            response = self.client.table("stored_procedures").insert(data).execute()
            return response.data[0]
        except Exception as e:
            logger.error(f"❌ Error insertando SP: {e}")
            raise
    
    async def insert_hallazgo(self, data: dict) -> dict:
        """Insertar hallazgo"""
        try:
            response = self.client.table("hallazgos").insert(data).execute()
            return response.data[0]
        except Exception as e:
            logger.error(f"❌ Error insertando hallazgo: {e}")
            raise
    
    async def insert_reporte(self, data: dict) -> dict:
        """Insertar reporte"""
        try:
            response = self.client.table("reportes").insert(data).execute()
            logger.info(f"📄 Reporte registrado: {data['report_type']}")
            return response.data[0]
        except Exception as e:
            logger.error(f"❌ Error insertando reporte: {e}")
            raise
    
    async def get_auditoria(self, audit_id: str) -> Optional[dict]:
        """Obtener auditoría por ID"""
        try:
            response = self.client.table("auditorias").select("*").eq("id", audit_id).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"❌ Error obteniendo auditoría: {e}")
            return None
    
    async def get_hallazgos_by_audit(self, audit_id: str) -> list:
        """Obtener hallazgos de una auditoría"""
        try:
            response = self.client.table("hallazgos").select("*").eq("audit_id", audit_id).execute()
            return response.data
        except Exception as e:
            logger.error(f"❌ Error obteniendo hallazgos: {e}")
            return []
    
    async def update_auditoria(self, audit_id: str, data: dict) -> dict:
        """Actualizar auditoría"""
        try:
            response = self.client.table("auditorias").update(data).eq("id", audit_id).execute()
            return response.data[0]
        except Exception as e:
            logger.error(f"❌ Error actualizando auditoría: {e}")
            raise
    
    async def get_reportes_by_audit(self, audit_id: str) -> list:
        """Obtener reportes de una auditoría"""
        try:
            response = self.client.table("reportes").select("*").eq("audit_id", audit_id).execute()
            return response.data
        except Exception as e:
            logger.error(f"❌ Error obteniendo reportes: {e}")
            return []


# Instancia global del database
db = SupabaseDatabase()
