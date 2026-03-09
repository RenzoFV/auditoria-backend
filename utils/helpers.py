"""
Funciones auxiliares y helpers
"""
import uuid
import hashlib
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional
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



# ─────────────────────────────────────────────────────────────
# Glosario de términos técnicos detectables en el campo impacto
# Cada entrada: keyword (minúsculas) → {definition, example}
# ─────────────────────────────────────────────────────────────
IMPACT_KEYWORDS_GLOSSARY: Dict[str, Dict[str, str]] = {
    "interceptar": {
        "term": "Interceptar una respuesta",
        "definition": (
            "Consiste en que un tercero malicioso captura el tráfico de red entre "
            "el cliente y el servidor antes de que llegue a su destino, pudiendo "
            "leer o modificar la información en tránsito. También conocido como "
            "ataque Man-in-the-Middle (MitM)."
        ),
        "example": (
            "Un atacante conectado a la misma red Wi-Fi corporativa utiliza una "
            "herramienta como Wireshark para capturar los paquetes HTTP enviados "
            "por la aplicación. Si la respuesta del servidor incluye el campo "
            "'password' en texto plano, el atacante lo visualiza directamente en "
            "su pantalla sin necesidad de conocer ninguna credencial previa."
        ),
    },
    "man-in-the-middle": {
        "term": "Ataque Man-in-the-Middle (MitM)",
        "definition": (
            "El atacante se posiciona entre dos partes que se comunican (por ejemplo "
            "entre la aplicación web y la base de datos), interceptando y, "
            "opcionalmente, alterando los mensajes sin que ninguno de los extremos "
            "lo detecte."
        ),
        "example": (
            "Con la herramienta mitmproxy, un atacante redirige el tráfico de la "
            "aplicación hacia su equipo, modifica la respuesta JSON sustituyendo "
            "'admin: false' por 'admin: true', y reenvía el paquete alterado al "
            "cliente, otorgándose permisos de administrador."
        ),
    },
    "inyección sql": {
        "term": "Inyección SQL",
        "definition": (
            "Técnica mediante la cual un atacante inserta o 'inyecta' comandos SQL "
            "maliciosos dentro de los parámetros de entrada de una consulta, logrando "
            "que la base de datos ejecute instrucciones no previstas por el "
            "desarrollador."
        ),
        "example": (
            "Si el procedimiento almacenado construye la consulta como: "
            "\"EXEC('SELECT * FROM users WHERE name = ''' + @name + '''')\", "
            "un atacante puede enviar el valor: ''' OR 1=1 --  "
            "haciendo que se devuelvan TODOS los registros de la tabla, "
            "independientemente del nombre buscado."
        ),
    },
    "sql injection": {
        "term": "Inyección SQL",
        "definition": (
            "Técnica mediante la cual un atacante inserta comandos SQL maliciosos "
            "en los parámetros de entrada, logrando que la base de datos ejecute "
            "instrucciones no autorizadas."
        ),
        "example": (
            "Parámetro recibido: ' OR '1'='1  — esto convierte la cláusula WHERE "
            "en siempre verdadera, exponiendo todos los registros de la tabla."
        ),
    },
    "contraseña": {
        "term": "Exposición de contraseñas",
        "definition": (
            "Situación donde las credenciales de autenticación (contraseñas) quedan "
            "accesibles, ya sea porque se almacenan en texto plano, se retornan en "
            "respuestas de la API, o aparecen en logs del sistema."
        ),
        "example": (
            "La consulta 'SELECT usuario, password FROM usuarios' retorna filas como "
            "{'usuario': 'jperez', 'password': 'Hass2024!'}. Cualquier persona con "
            "acceso al reporte de auditoría o a los logs del sistema vería estas "
            "credenciales directamente."
        ),
    },
    "texto plano": {
        "term": "Almacenamiento en texto plano",
        "definition": (
            "Los datos sensibles (contraseñas, tokens, números de tarjeta) se guardan "
            "o transmiten sin ningún tipo de cifrado ni transformación, siendo legibles "
            "directamente por cualquiera que acceda al almacenamiento o al tráfico."
        ),
        "example": (
            "En la tabla 'usuarios', la columna 'password' contiene el valor literal "
            "'Hass2024!' en lugar de su hash bcrypt "
            "'$2b$12$K8qG...'. Si la base de datos es comprometida, el atacante "
            "obtiene las contraseñas reales sin necesidad de descifrarlas."
        ),
    },
    "escalada de privilegios": {
        "term": "Escalada de privilegios",
        "definition": (
            "Un usuario con permisos limitados logra obtener permisos superiores "
            "(por ejemplo, de usuario normal a administrador) explotando una "
            "configuración incorrecta o una vulnerabilidad del sistema."
        ),
        "example": (
            "Un empleado con rol 'solo lectura' ejecuta un stored procedure que "
            "tiene GRANT ALL sobre la base de datos, obteniendo capacidad de "
            "modificar o eliminar cualquier tabla, incluyendo las de auditoría."
        ),
    },
    "exfiltrar": {
        "term": "Exfiltración de datos",
        "definition": (
            "Transferencia no autorizada de datos desde el sistema hacia un destino "
            "externo controlado por el atacante. Puede ocurrir a través de la red, "
            "emails, o peticiones HTTP encubiertas."
        ),
        "example": (
            "Aprovechando una inyección SQL, el atacante ejecuta: "
            "'; INSERT INTO log_externo SELECT * FROM clientes_pii --  "
            "copiando todos los datos personales a una tabla que luego exporta."
        ),
    },
    # Variante sustantivada — apunta a la misma definición
    "exfiltración": {
        "term": "Exfiltración de datos",
        "definition": (
            "Transferencia no autorizada de datos desde el sistema hacia un destino "
            "externo controlado por el atacante. Puede ocurrir a través de la red, "
            "emails, o peticiones HTTP encubiertas."
        ),
        "example": (
            "Aprovechando una inyección SQL, el atacante ejecuta: "
            "'; INSERT INTO log_externo SELECT * FROM clientes_pii --  "
            "copiando todos los datos personales a una tabla que luego exporta. "
            "Con los registros exportados (DNI, email, teléfono) el atacante puede "
            "venderlos en foros clandestinos o usarlos para ataques de phishing "
            "dirigidos contra los clientes de la organización."
        ),
    },
    "datos personales": {
        "term": "Exposición de datos personales (PII)",
        "definition": (
            "Los datos de identificación personal (PII, del inglés Personally "
            "Identifiable Information) como DNI, correo electrónico o teléfono "
            "quedan accesibles a usuarios o sistemas no autorizados, ya sea porque "
            "se retornan sin filtrar en consultas SQL, se almacenan sin cifrado o "
            "se muestran en interfaces sin control de acceso."
        ),
        "example": (
            "La consulta 'SELECT dni, email, telefono FROM usuarios' retorna filas "
            "como {\"dni\": \"45123456\", \"email\": \"jperez@empresa.com\", "
            "\"telefono\": \"987654321\"}. Cualquier analista con acceso de lectura "
            "a la base de datos puede exportar esta tabla completa, configurando una "
            "violación directa del Art. 17 de la Ley N°29733 (deber de seguridad) "
            "que puede derivar en multas de hasta 100 UIT (S/ 515,000)."
        ),
    },
    "acceso no autorizado": {
        "term": "Acceso no autorizado",
        "definition": (
            "Un actor (usuario, proceso o sistema externo) accede a recursos, datos "
            "o funcionalidades para los cuales no tiene permiso explícito, "
            "vulnerando el principio de control de acceso."
        ),
        "example": (
            "Con el usuario 'sa' hardcodeado en el código fuente, cualquier "
            "desarrollador que lea el repositorio puede conectarse directamente "
            "a la base de datos de producción con permisos de administrador total."
        ),
    },
    "denegación de servicio": {
        "term": "Denegación de servicio (DoS)",
        "definition": (
            "Ataque cuyo objetivo es hacer que un sistema, servicio o red deje de "
            "estar disponible para sus usuarios legítimos, agotando recursos como "
            "CPU, memoria, conexiones o ancho de banda."
        ),
        "example": (
            "Un cursor anidado que itera sobre millones de registros sin filtro "
            "WHERE puede consumir el 100% de CPU del servidor SQL, provocando "
            "que todas las demás consultas de la aplicación fallen por timeout."
        ),
    },
    "brecha de seguridad": {
        "term": "Brecha de seguridad",
        "definition": (
            "Incidente en el que personas no autorizadas logran acceder, modificar, "
            "robar o destruir datos o sistemas. Puede resultar en pérdida de "
            "información confidencial, daño reputacional y sanciones legales."
        ),
        "example": (
            "Si un atacante explota la credencial hardcodeada encontrada, puede "
            "acceder a todas las tablas de la base de datos, exportar los registros "
            "de clientes y venderlos, configurando una brecha sujeta a sanciones "
            "bajo la Ley N°29733 de Protección de Datos Personales del Perú."
        ),
    },
    "credential stuffing": {
        "term": "Credential Stuffing",
        "definition": (
            "Ataque automatizado en que el atacante utiliza listas masivas de "
            "combinaciones usuario/contraseña obtenidas de otras filtraciones para "
            "intentar acceder a un sistema diferente, aprovechando que los usuarios "
            "reutilizan contraseñas."
        ),
        "example": (
            "Si las contraseñas en texto plano de este sistema son expuestas, se "
            "pueden cruzar con bases de datos de otras filtraciones. Un script "
            "automatizado prueba cada par usuario/contraseña contra el portal web "
            "de Hass Perú en cuestión de minutos."
        ),
    },
}


def get_impact_terms(impact_text: str) -> List[Dict[str, str]]:
    """
    Detectar términos técnicos en el texto de impacto y retornar
    sus definiciones y ejemplos concretos del glosario.

    Args:
        impact_text: Texto del campo 'impact' de un hallazgo

    Returns:
        Lista de dicts con {term, definition, example} para cada keyword encontrada
    """
    if not impact_text:
        return []

    normalized = impact_text.lower()
    found: List[Dict[str, str]] = []
    seen_terms: set = set()

    for keyword, data in IMPACT_KEYWORDS_GLOSSARY.items():
        if keyword in normalized and data["term"] not in seen_terms:
            found.append({
                "term": data["term"],
                "definition": data["definition"],
                "example": data["example"],
            })
            seen_terms.add(data["term"])

    return found


def get_impact_description(severity: str, category: str, finding_type: str = "") -> str:
    """Generar descripción de impacto basada en el tipo de hallazgo, severidad y categoría"""

    # Impactos específicos por tipo de hallazgo
    specific_impacts: Dict[str, str] = {
        "sql_injection": (
            "Un atacante puede inyectar comandos SQL maliciosos para leer, modificar "
            "o eliminar cualquier dato de la base de datos, incluyendo tablas de "
            "usuarios, auditoría y configuración del sistema."
        ),
        "plaintext_password": (
            "Las contraseñas quedan expuestas en texto plano. Cualquier persona con "
            "acceso a la base de datos, logs o tráfico de red puede interceptar la "
            "respuesta y obtener las credenciales de los usuarios directamente, sin "
            "necesidad de descifrarlas."
        ),
        "hardcoded_credentials": (
            "Las credenciales embebidas en el código son visibles para cualquier "
            "desarrollador con acceso al repositorio y permiten acceso no autorizado "
            "directo a la base de datos de producción."
        ),
        "excessive_permissions": (
            "Un usuario con permisos excesivos puede escalar privilegios y realizar "
            "operaciones destructivas (eliminar tablas, modificar datos de auditoría) "
            "que deberían estar restringidas."
        ),
        "sensitive_data_exposure": (
            "Datos personales (DNI, email, teléfono) quedan expuestos sin protección. "
            "Esto expone a la organización a sanciones bajo la Ley N°29733 y puede "
            "derivar en exfiltración de información de clientes."
        ),
        "no_audit_trail": (
            "Sin registro de auditoría, las acciones de los usuarios (modificaciones, "
            "eliminaciones) no quedan trazadas, imposibilitando detectar accesos no "
            "autorizados o recuperar datos ante un incidente."
        ),
        "cursor_usage": (
            "El uso excesivo de cursores puede degradar el rendimiento del servidor, "
            "generando tiempos de respuesta inaceptables o una denegación de servicio "
            "efectiva ante volúmenes de datos altos."
        ),
    }

    if finding_type and finding_type in specific_impacts:
        return specific_impacts[finding_type]

    # Fallback por severidad/categoría
    if severity == 'critical':
        if category == 'security':
            return (
                "Riesgo CRÍTICO: explotación directa posible. Un atacante podría "
                "obtener acceso completo al sistema o causar una brecha de seguridad "
                "con impacto inmediato en los datos y operaciones de la organización."
            )
        return "Impacto CRÍTICO en la operación del sistema. Puede causar indisponibilidad total."

    elif severity == 'high':
        if category == 'security':
            return (
                "Alto riesgo de vulnerabilidad. Sin corrección inmediata, un atacante "
                "podría obtener acceso no autorizado a datos sensibles o escalar "
                "privilegios dentro del sistema."
            )
        return "Impacto significativo en rendimiento o disponibilidad del servicio."

    elif severity == 'medium':
        return (
            "Impacto moderado. La vulnerabilidad es explotable bajo condiciones "
            "específicas y debe ser corregida en el siguiente ciclo de desarrollo."
        )

    elif severity == 'low':
        return (
            "Impacto menor. No representa riesgo inmediato, pero su acumulación "
            "puede incrementar la superficie de ataque."
        )

    return "Impacto informativo. No requiere acción inmediata pero se recomienda revisar."


class JsonEncoder(json.JSONEncoder):
    """Encoder personalizado para JSON con soporte de datetime"""
    
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, bytes):
            return obj.decode('utf-8', errors='ignore')
        return super().default(obj)
