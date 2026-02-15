"""
Patrones regex para detección de vulnerabilidades y problemas
"""
import re
from typing import List, Dict, Tuple
from models.audit import CategoryType, SeverityLevel


class SecurityPatterns:
    """Patrones de seguridad"""
    
    # Credenciales hardcodeadas
    HARDCODED_PASSWORD = [
        (r"(?i)(password|pwd|pass|clave)\s*=\s*['\"][\w@#$%^&*]+['\"]", 
         "Contraseña hardcodeada", "CWE-798", 9.1),
        (r"(?i)(user|usuario|uid)\s*=\s*['\"]sa['\"]", 
         "Usuario 'sa' hardcodeado", "CWE-798", 8.5),
        (r"(?i)server\s*=\s*['\"][\d.]+['\"].*password", 
         "Credenciales de servidor hardcodeadas", "CWE-798", 9.0),
    ]
    
    # SQL Injection
    SQL_INJECTION = [
        (r"EXEC\s*\(\s*@\w+\s*\+", 
         "SQL Injection potencial (concatenación dinámica)", "CWE-89", 9.8),
        (r"EXECUTE\s*\(\s*@\w+\s*\+", 
         "SQL Injection potencial (concatenación dinámica)", "CWE-89", 9.8),
        (r"(?i)exec\s+sp_executesql.*@\w+\s*\+", 
         "SQL Injection potencial (sp_executesql dinámico)", "CWE-89", 9.5),
        (r"(?i)SELECT.*FROM.*WHERE.*\+\s*@", 
         "SQL Injection potencial (WHERE dinámico)", "CWE-89", 9.3),
    ]
    
    # Contraseñas en texto plano
    PLAINTEXT_CREDENTIALS = [
        (r"(?i)SELECT.*password.*FROM", 
         "Retorno de passwords sin cifrar", "CWE-256", 8.8),
        (r"(?i)SELECT.*clave.*FROM", 
         "Retorno de claves sin cifrar", "CWE-256", 8.8),
        (r"(?i)INSERT.*VALUES.*password", 
         "Almacenamiento de password en texto plano", "CWE-256", 8.5),
    ]
    
    # Permisos excesivos
    EXCESSIVE_PERMISSIONS = [
        (r"(?i)GRANT\s+ALL", 
         "Permisos excesivos (GRANT ALL)", "CWE-269", 7.5),
        (r"(?i)GRANT\s+CONTROL", 
         "Permisos excesivos (GRANT CONTROL)", "CWE-269", 7.5),
        (r"(?i)WITH\s+GRANT\s+OPTION", 
         "Permisos delegables (WITH GRANT OPTION)", "CWE-269", 7.0),
    ]
    
    # Sin manejo de errores
    NO_ERROR_HANDLING = [
        (r"(?<!BEGIN\s)TRY(?!\s*\n)", 
         "Falta de manejo de errores (sin TRY-CATCH)", "CWE-755", 6.5),
    ]
    
    # Datos sensibles sin protección
    SENSITIVE_DATA = [
        (r"(?i)SELECT.*dni.*FROM", 
         "Exposición de DNI sin protección", "CWE-359", 7.2),
        (r"(?i)SELECT.*email.*FROM", 
         "Exposición de emails sin protección", "CWE-359", 6.8),
        (r"(?i)SELECT.*telefono.*FROM", 
         "Exposición de teléfonos sin protección", "CWE-359", 6.5),
    ]


class PerformancePatterns:
    """Patrones de performance"""
    
    # Cursores
    CURSORS = [
        (r"(?i)DECLARE\s+\w+\s+CURSOR", 
         "Uso de cursores (puede afectar performance)", None, 6.0),
        (r"(?i)CURSOR.*FOR.*SELECT.*FROM.*WHERE", 
         "Cursor con filtros complejos", None, 6.5),
        (r"(?i)DECLARE.*CURSOR.*DECLARE.*CURSOR", 
         "Cursores anidados (critico para performance)", None, 8.0),
    ]
    
    # SELECT *
    SELECT_STAR = [
        (r"(?i)SELECT\s+\*\s+FROM", 
         "SELECT * (seleccionar solo columnas necesarias)", None, 5.5),
        (r"(?i)SELECT\s+\*.*WHERE.*NOT\s+EXISTS", 
         "SELECT * con NOT EXISTS (performance crítica)", None, 7.0),
    ]
    
    # Funciones no-sargable
    NON_SARGABLE = [
        (r"(?i)WHERE\s+\w+\([a-zA-Z_]+\)", 
         "Función en WHERE (no-sargable)", None, 6.5),
        (r"(?i)WHERE.*SUBSTRING\(", 
         "SUBSTRING en WHERE (no-sargable)", None, 6.5),
        (r"(?i)WHERE.*CONVERT\(", 
         "CONVERT en WHERE (no-sargable)", None, 6.5),
    ]
    
    # Tablas temporales sin índices
    TEMP_TABLES = [
        (r"(?i)CREATE\s+TABLE\s+#\w+.*(?!.*INDEX)", 
         "Tabla temporal sin índices", None, 6.0),
        (r"(?i)INSERT\s+INTO\s+#\w+.*SELECT.*FROM.*WHERE", 
         "INSERT masivo en tabla temporal", None, 5.8),
    ]
    
    # Missing WHERE
    MISSING_WHERE = [
        (r"(?i)DELETE\s+FROM\s+\w+(?!\s+WHERE)", 
         "DELETE sin WHERE (peligroso)", None, 8.5),
        (r"(?i)UPDATE\s+\w+\s+SET.*(?!\s+WHERE)", 
         "UPDATE sin WHERE (peligroso)", None, 8.5),
    ]


class CompliancePatterns:
    """Patrones de cumplimiento"""
    
    # Falta de auditoría
    NO_AUDIT = [
        (r"(?i)INSERT\s+INTO.*(?!.*auditoria)", 
         "INSERT sin registro de auditoría", None, 6.0),
        (r"(?i)UPDATE.*(?!.*auditoria)", 
         "UPDATE sin registro de auditoría", None, 6.0),
        (r"(?i)DELETE.*(?!.*auditoria)", 
         "DELETE sin registro de auditoría", None, 7.0),
    ]
    
    # Sin logs
    NO_LOGGING = [
        (r"(?i)BEGIN\s+TRANSACTION.*COMMIT(?!.*LOG)", 
         "Transacción sin logging", None, 5.5),
    ]
    
    # Datos personales
    PERSONAL_DATA = [
        (r"(?i)CREATE\s+TABLE.*dni.*(?!ENCRYPTED)", 
         "DNI sin encriptación", None, 7.5),
        (r"(?i)CREATE\s+TABLE.*email.*(?!ENCRYPTED)", 
         "Email sin encriptación", None, 6.5),
    ]


class MaintainabilityPatterns:
    """Patrones de mantenibilidad"""
    
    # Código duplicado
    CODE_DUPLICATION = [
        (r"(SELECT.*FROM.*WHERE.*){3,}", 
         "Código duplicado detectado", None, 4.0),
    ]
    
    # Sin comentarios
    NO_COMMENTS = [
        (r"^(?!.*--.*$)(?!.*/\*.*\*/$)", 
         "Falta de comentarios", None, 3.0),
    ]
    
    # Nombres no descriptivos
    POOR_NAMING = [
        (r"(?i)@p\d+|@var\d+|@tmp\d+", 
         "Nombres de variables no descriptivos", None, 4.5),
        (r"(?i)DECLARE\s+@[a-z]\s", 
         "Variable con nombre de una sola letra", None, 4.0),
    ]
    
    # Código comentado (muerto)
    DEAD_CODE = [
        (r"^--\s*(SELECT|INSERT|UPDATE|DELETE)", 
         "Código comentado (posible código muerto)", None, 3.5),
    ]


class PatternAnalyzer:
    """Analizador de patrones"""
    
    @staticmethod
    def analyze(code: str) -> List[Dict]:
        """Analizar código con todos los patrones"""
        findings = []
        
        # Seguridad
        findings.extend(PatternAnalyzer._check_patterns(
            code, SecurityPatterns.HARDCODED_PASSWORD,
            CategoryType.SECURITY, SeverityLevel.CRITICAL,
            "hardcoded_credentials"
        ))
        
        findings.extend(PatternAnalyzer._check_patterns(
            code, SecurityPatterns.SQL_INJECTION,
            CategoryType.SECURITY, SeverityLevel.CRITICAL,
            "sql_injection"
        ))
        
        findings.extend(PatternAnalyzer._check_patterns(
            code, SecurityPatterns.PLAINTEXT_CREDENTIALS,
            CategoryType.SECURITY, SeverityLevel.HIGH,
            "plaintext_password"
        ))
        
        findings.extend(PatternAnalyzer._check_patterns(
            code, SecurityPatterns.EXCESSIVE_PERMISSIONS,
            CategoryType.SECURITY, SeverityLevel.HIGH,
            "excessive_permissions"
        ))
        
        findings.extend(PatternAnalyzer._check_patterns(
            code, SecurityPatterns.SENSITIVE_DATA,
            CategoryType.SECURITY, SeverityLevel.MEDIUM,
            "sensitive_data_exposure"
        ))
        
        return findings
    
    @staticmethod
    def _check_patterns(
        code: str,
        patterns: List[Tuple],
        category: CategoryType,
        severity: SeverityLevel,
        finding_type: str
    ) -> List[Dict]:
        """Verificar patrones específicos"""
        findings = []
        lines = code.split('\n')
        
        for pattern, title, cwe, cvss in patterns:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        'category': category,
                        'severity': severity,
                        'type': finding_type,
                        'title': title,
                        'line': line_num,
                        'code_snippet': line.strip(),
                        'cwe_id': cwe,
                        'cvss_score': cvss,
                        'detected_by': 'regex'
                    })
        
        return findings
    
    @staticmethod
    def calculate_complexity(code: str) -> int:
        """Calcular complejidad ciclomática"""
        complexity = 1  # Base
        
        # Contar estructuras de control
        complexity += len(re.findall(r'\bIF\b', code, re.IGNORECASE))
        complexity += len(re.findall(r'\bWHILE\b', code, re.IGNORECASE))
        complexity += len(re.findall(r'\bFOR\b', code, re.IGNORECASE))
        complexity += len(re.findall(r'\bCASE\b', code, re.IGNORECASE))
        complexity += len(re.findall(r'\bAND\b', code, re.IGNORECASE))
        complexity += len(re.findall(r'\bOR\b', code, re.IGNORECASE))
        
        return complexity
