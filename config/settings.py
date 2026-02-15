"""
Configuración de Settings usando Pydantic
"""
from pydantic_settings import BaseSettings
from typing import List
from functools import lru_cache


class Settings(BaseSettings):
    """Configuración de la aplicación"""
    
    # SQL Server
    SQLSERVER_HOST: str = "localhost"
    SQLSERVER_PORT: int = 1433
    SQLSERVER_DATABASE: str = "BDERP_Agro_Hass"
    SQLSERVER_USER: str = "sa"
    SQLSERVER_PASSWORD: str = ""
    SQLSERVER_DRIVER: str = "ODBC Driver 17 for SQL Server"
    
    # Supabase
    SUPABASE_URL: str
    SUPABASE_KEY: str
    
    # Gemini AI
    GEMINI_API_KEY: str
    GEMINI_MODEL: str = "gemini-2.5-flash"
    GEMINI_MAX_TOKENS: int = 8192
    GEMINI_TEMPERATURE: float = 0.3
    
    # Application
    APP_NAME: str = "AuditDB Analyzer"
    APP_VERSION: str = "1.0.0"
    APP_ENV: str = "development"
    APP_DEBUG: bool = True
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    
    # CORS
    CORS_ORIGINS: str = "http://localhost:3000"
    CORS_ALLOW_CREDENTIALS: bool = True
    
    # Reports
    REPORTS_DIR: str = "./outputs"
    MAX_FILE_SIZE_MB: int = 50
    PDF_LOGO_PATH: str = "./assets/logo.png"
    
    # Security
    SECRET_KEY: str = "change-this-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "./logs/auditdb.log"
    LOG_ROTATION: str = "10 MB"
    LOG_RETENTION: str = "30 days"
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    ANALYSIS_RATE_LIMIT: int = 10
    
    @property
    def cors_origins_list(self) -> List[str]:
        """Convertir CORS_ORIGINS string a lista"""
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]
    
    @property
    def sqlserver_connection_string(self) -> str:
        """Generar connection string para SQL Server"""
        return (
            f"DRIVER={{{self.SQLSERVER_DRIVER}}};"
            f"SERVER={self.SQLSERVER_HOST},{self.SQLSERVER_PORT};"
            f"DATABASE={self.SQLSERVER_DATABASE};"
            f"UID={self.SQLSERVER_USER};"
            f"PWD={self.SQLSERVER_PASSWORD};"
            f"TrustServerCertificate=yes;"
        )
    
    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    """Obtener settings (singleton)"""
    return Settings()


# Instancia global de settings
settings = get_settings()
