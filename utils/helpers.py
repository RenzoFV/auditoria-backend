"""
Funciones auxiliares y helpers
"""
import uuid
import hashlib
import json
import os
from datetime import datetime
from typing import Any, Dict, Optional
from pathlib import Path
from loguru import logger


def generate_uuid() -> str:
    """Generar UUID único"""
    return str(uuid.uuid4())


def generate_hash(text: str) -> str:
    """Generar hash SHA256 de texto"""
    return hashlib.sha256(text.encode()).hexdigest()


def format_datetime(dt: Optional[datetime] = None) -> str:
    """Formatear datetime a string ISO"""
    if dt is None:
        dt = datetime.now()
    return dt.isoformat()


def parse_datetime(dt_str: str) -> datetime:
    """Parsear string ISO a datetime"""
    return datetime.fromisoformat(dt_str)


def truncate_text(text: str, max_length: int = 200) -> str:
    """Truncar texto con ellipsis"""
    if len(text) <= max_length:
        return text
    return text[:max_length] + "..."


def sanitize_filename(filename: str) -> str:
    """Sanitizar nombre de archivo"""
    # Remover caracteres no válidos
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    return filename


def ensure_directory(path: str) -> Path:
    """Asegurar que un directorio existe"""
    dir_path = Path(path)
    dir_path.mkdir(parents=True, exist_ok=True)
    return dir_path


def get_file_size(file_path: str) -> int:
    """Obtener tamaño de archivo en bytes"""
    return os.path.getsize(file_path)


def format_file_size(size_bytes: int) -> str:
    """Formatear tamaño de archivo a formato legible"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"


def save_json(data: Dict[str, Any], file_path: str) -> str:
    """Guardar datos como JSON"""
    ensure_directory(os.path.dirname(file_path))
    
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    
    logger.info(f"💾 JSON guardado: {file_path}")
    return file_path


def load_json(file_path: str) -> Dict[str, Any]:
    """Cargar JSON desde archivo"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def calculate_risk_score(findings_summary: Dict[str, int]) -> float:
    """
    Calcular score de riesgo basado en hallazgos
    
    Fórmula: (Critical * 10 + High * 7 + Medium * 4 + Low * 2 + Info * 0.5) / total
    """
    weights = {
        'critical': 10,
        'high': 7,
        'medium': 4,
        'low': 2,
        'info': 0.5
    }
    
    total_findings = sum(findings_summary.values())
    if total_findings == 0:
        return 0.0
    
    weighted_sum = sum(
        findings_summary.get(severity, 0) * weight
        for severity, weight in weights.items()
    )
    
    # Normalizar a escala 0-10
    max_possible = total_findings * 10
    risk_score = (weighted_sum / max_possible) * 10
    
    return round(risk_score, 1)


def get_severity_color(severity: str) -> str:
    """Obtener color hexadecimal para cada severidad"""
    colors = {
        'critical': '#DC2626',  # Rojo
        'high': '#EA580C',      # Naranja oscuro
        'medium': '#F59E0B',    # Amarillo
        'low': '#3B82F6',       # Azul
        'info': '#6B7280'       # Gris
    }
    return colors.get(severity.lower(), '#6B7280')


def get_category_icon(category: str) -> str:
    """Obtener emoji/icono para cada categoría"""
    icons = {
        'security': '🔒',
        'performance': '⚡',
        'compliance': '📋',
        'maintainability': '🔧'
    }
    return icons.get(category.lower(), '📌')


def format_duration(seconds: float) -> str:
    """Formatear duración en segundos a formato legible"""
    if seconds < 60:
        return f"{seconds:.1f} segundos"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} minutos"
    else:
        hours = seconds / 3600
        return f"{hours:.1f} horas"


def extract_code_context(code: str, line_number: int, context_lines: int = 3) -> str:
    """
    Extraer contexto de código alrededor de una línea específica
    
    Args:
        code: Código completo
        line_number: Número de línea (1-indexed)
        context_lines: Líneas de contexto antes y después
    
    Returns:
        Fragmento de código con contexto
    """
    if not code or line_number <= 0:
        return ""

    lines = code.split('\n')
    start = max(0, line_number - context_lines - 1)
    end = min(len(lines), line_number + context_lines)
    
    context = []
    for i in range(start, end):
        marker = ">>> " if i == line_number - 1 else "    "
        context.append(f"{marker}{i+1:4d} | {lines[i]}")
    
    return '\n'.join(context)


def get_recommendation_for_finding(finding_type: str) -> str:
    """Obtener recomendación específica para un tipo de hallazgo"""
    recommendations = {
        'sql_injection': 
            "Usar sp_executesql con parámetros o comandos parametrizados. "
            "NUNCA concatenar input del usuario directamente en queries SQL.",
        
        'plaintext_password': 
            "Implementar hashing de passwords con bcrypt o PBKDF2. "
            "Nunca almacenar o retornar contraseñas en texto plano.",
        
        'hardcoded_credentials': 
            "Mover credenciales a un sistema de gestión de secretos (Azure Key Vault, HashiCorp Vault). "
            "No hardcodear credenciales en el código.",
        
        'cursor_usage': 
            "Considerar reemplazar cursores con operaciones SET-based. "
            "Los cursores tienen mal rendimiento en grandes volúmenes.",
        
        'select_star': 
            "Especificar solo las columnas necesarias en SELECT. "
            "Evitar SELECT * para mejorar performance y claridad.",
        
        'non_sargable': 
            "Evitar funciones en columnas dentro de WHERE. "
            "Reescribir condiciones para permitir uso de índices.",
        
        'excessive_permissions': 
            "Aplicar principio de mínimo privilegio. "
            "Otorgar solo permisos específicos necesarios.",
        
        'no_audit_trail': 
            "Implementar tabla de auditoría para rastrear cambios. "
            "Registrar quién, cuándo y qué se modificó.",
        
        'sensitive_data_exposure': 
            "Implementar enmascaramiento de datos sensibles. "
            "Considerar cifrado a nivel de columna para PII.",
        
        'missing_where': 
            "SIEMPRE incluir cláusula WHERE en UPDATE/DELETE. "
            "Operaciones masivas pueden causar pérdida de datos.",
        
        'poor_naming': 
            "Usar nombres descriptivos para variables y parámetros. "
            "Ejemplo: @userId en vez de @p1.",
        
        'dead_code': 
            "Eliminar código comentado/muerto del SP. "
            "Mantener historial en control de versiones, no en comentarios."
    }
    
    return recommendations.get(
        finding_type,
        "Revisar documentación de mejores prácticas de SQL Server."
    )


def get_impact_description(severity: str, category: str) -> str:
    """Generar descripción de impacto basada en severidad y categoría"""
    if severity == 'critical':
        if category == 'security':
            return "Riesgo CRÍTICO de brecha de seguridad. Explotación directa posible."
        return "Impacto CRÍTICO en la operación del sistema."
    
    elif severity == 'high':
        if category == 'security':
            return "Alto riesgo de vulnerabilidad. Requiere atención inmediata."
        return "Impacto significativo en rendimiento o disponibilidad."
    
    elif severity == 'medium':
        return "Impacto moderado. Debe ser corregido en siguiente release."
    
    elif severity == 'low':
        return "Impacto menor. Considerar corrección para mejora continua."
    
    return "Impacto informativo. No requiere acción inmediata."


class JsonEncoder(json.JSONEncoder):
    """Encoder personalizado para JSON con soporte de datetime"""
    
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, bytes):
            return obj.decode('utf-8', errors='ignore')
        return super().default(obj)
