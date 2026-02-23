"""
Servicio de integración con Google Gemini AI
"""
import google.generativeai as genai
from typing import Optional, Dict, Any
from loguru import logger

from config.settings import settings


class GeminiService:
    """Servicio para interactuar con Gemini AI"""
    
    def __init__(self):
        """Inicializar servicio de Gemini"""
        try:
            genai.configure(api_key=settings.GEMINI_API_KEY)
            self.model_name = settings.GEMINI_MODEL
            self.model = genai.GenerativeModel(self.model_name)
            self.fallback_models = self._build_fallback_models(self.model_name)
            logger.info(f"✅ Gemini AI inicializado: {self.model_name}")
        except Exception as e:
            logger.error(f"❌ Error inicializando Gemini: {e}")
            raise
    
    def analyze_stored_procedure(
        self,
        sp_name: str,
        sp_code: str,
        context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analizar stored procedure con Gemini AI
        
        Args:
            sp_name: Nombre del SP
            sp_code: Código del SP
            context: Contexto adicional del sistema
        
        Returns:
            Dict con hallazgos detectados por IA
        """
        try:
            # Construir prompt
            prompt = self._build_analysis_prompt(sp_name, sp_code, context)
            
            logger.info(f"🤖 Analizando {sp_name} con Gemini AI...")
            
            # Llamar a Gemini con fallback de modelos
            response = self._generate_with_fallback(prompt)
            
            # Parsear respuesta
            analysis = self._parse_gemini_response(response.text)
            
            logger.success(f"✅ Análisis AI completado para {sp_name}")
            return analysis
        
        except Exception as e:
            logger.error(f"❌ Error en análisis AI de {sp_name}: {e}")
            return {
                "error": str(e),
                "findings": []
            }
    
    def _build_analysis_prompt(
        self,
        sp_name: str,
        sp_code: str,
        context: Optional[str]
    ) -> str:
        """Construir prompt para Gemini"""
        
        base_prompt = f"""
Eres un experto en auditoría de seguridad de bases de datos SQL Server.

Analiza el siguiente stored procedure llamado "{sp_name}" del sistema de autenticación 
y control de accesos de Hass Perú (empresa agroindustrial).

CONTEXTO DEL SISTEMA:
{context or "Sistema de autenticación y control de accesos para empresa agroindustrial"}

CÓDIGO DEL STORED PROCEDURE:
```sql
{sp_code}
```

INSTRUCCIONES:
Analiza el código SOLO buscando vulnerabilidades de SEGURIDAD:

- SQL Injection (concatenación dinámica, EXEC con strings)
- Credenciales hardcodeadas o en texto plano
- Exposición de datos sensibles (passwords, DNI, emails)
- Permisos excesivos
- Falta de validación de entrada
- Autenticación/autorización débil

FORMATO DE RESPUESTA:
Para cada hallazgo encontrado, responde en este formato exacto:

---FINDING---
SEVERITY: [CRITICAL|HIGH|MEDIUM|LOW|INFO]
CATEGORY: [SECURITY]
TYPE: [nombre_tipo_hallazgo]
TITLE: [Título breve del hallazgo]
LINE: [número de línea aproximado]
DESCRIPTION: [Descripción detallada del problema]
CONTEXT_EXPLANATION: [Explicación clara y entendible del riesgo en este SP]
IMPACT: [Impacto potencial en el sistema]
RECOMMENDATION: [Recomendación específica de corrección]
CODE_SNIPPET: [Fragmento de código problemático]
EXPLOIT_EXAMPLE: [Ejemplo entendible, en texto claro, de cómo se podría explotar]
NORMATIVE_REFERENCE: [Ley, norma o control afectado (ej: OWASP A03:2021 Injection, COBIT APO13, COBIT DSS05, ISO/IEC 27001:2022 A.9.2, ISO/IEC 27001:2022 A.10.1, Ley N 29733 Art.17/Art.19, Normativa institucional Hass Peru)]
---END---

Si NO encuentras problemas significativos, responde:
---NO_FINDINGS---

IMPORTANTE:
- Sé específico con números de línea
- Prioriza severidad según riesgo real
- Da recomendaciones accionables
- Enfócate en lo MÁS crítico primero
- En CONTEXT_EXPLANATION y EXPLOIT_EXAMPLE, usa lenguaje claro (no pongas solo SQL ni listas de líneas)
- En cada hallazgo incluye NORMATIVE_REFERENCE con la normativa o control mas aplicable

MARCO NORMATIVO / REFERENCIAL PARA MAPEAR HALLAZGOS:
- OWASP Top 10 (2021): A03:2021 Injection
- COBIT: APO13 (Gestion de la Seguridad de la Informacion), DSS04.08 (Continuidad: backup y recuperacion), DSS05 (Gestion de los Servicios de Seguridad)
- ISO/IEC 27001:2022: A.6.1.2, A.9.1/A.9.2/A.9.4, A.10.1, A.12.1/A.12.3/A.12.4, A.14.2.1, A.18
- Ley N 29733 (Peru) - Proteccion de Datos Personales: Art.17 (Medidas de seguridad), Art.19 (Confidencialidad)
- Normativa institucional Hass Peru: acceso restringido a personal TI autorizado, no compartir credenciales, contrasenas con hash + salt, minimo privilegio con revision periodica, logs de auditoria, backups periodicos y recuperacion
"""
        
        return base_prompt

    def _build_fallback_models(self, primary: str) -> list:
        """Definir modelos alternativos cuando el principal no esta disponible"""
        candidates = [
            "gemini-2.5-flash",
            "gemini-1.5-flash-latest",
            "gemini-1.0-pro"
        ]
        return [name for name in candidates if name != primary]

    def _is_model_not_found_error(self, error: Exception) -> bool:
        """Detectar errores de modelo no disponible"""
        text = str(error).lower()
        return "not found" in text or "not supported" in text

    def _generate_with_fallback(self, prompt: str):
        """Generar contenido intentando modelos alternativos si es necesario"""
        last_error = None
        model_candidates = [self.model_name] + self.fallback_models

        for candidate in model_candidates:
            try:
                if candidate != self.model_name:
                    self.model_name = candidate
                    self.model = genai.GenerativeModel(self.model_name)
                    logger.warning(f"⚠️ Cambiando a modelo alternativo: {self.model_name}")

                return self.model.generate_content(
                    prompt,
                    generation_config=genai.GenerationConfig(
                        max_output_tokens=settings.GEMINI_MAX_TOKENS,
                        temperature=settings.GEMINI_TEMPERATURE,
                    )
                )
            except Exception as e:
                last_error = e
                if not self._is_model_not_found_error(e):
                    raise

                logger.warning(
                    f"⚠️ Modelo {candidate} no disponible para generateContent: {e}"
                )

        raise last_error
    
    def _parse_gemini_response(self, response_text: str) -> Dict[str, Any]:
        """Parsear respuesta de Gemini a formato estructurado"""
        
        if "---NO_FINDINGS---" in response_text:
            return {
                "has_findings": False,
                "findings": [],
                "summary": "No se encontraron problemas significativos"
            }
        
        findings = []
        
        # Buscar hallazgos en la respuesta
        finding_blocks = response_text.split("---FINDING---")
        
        for block in finding_blocks[1:]:  # Skip first empty split
            if "---END---" not in block:
                continue
            
            finding_text = block.split("---END---")[0].strip()
            finding = self._parse_finding_block(finding_text)
            
            if finding:
                findings.append(finding)
        
        return {
            "has_findings": len(findings) > 0,
            "findings": findings,
            "finding_count": len(findings),
            "raw_response": response_text
        }
    
    def _parse_finding_block(self, block: str) -> Optional[Dict[str, Any]]:
        """Parsear bloque individual de hallazgo"""
        try:
            lines = block.split('\n')
            finding = {}
            
            for line in lines:
                line = line.strip()
                if ':' not in line:
                    continue
                
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if key == 'severity':
                    finding['severity'] = value.lower()
                elif key == 'category':
                    finding['category'] = value.lower()
                elif key == 'type':
                    finding['type'] = value
                elif key == 'title':
                    finding['title'] = value
                elif key == 'line':
                    try:
                        finding['line'] = int(value)
                    except:
                        finding['line'] = 0
                elif key == 'description':
                    finding['description'] = value
                elif key == 'context_explanation':
                    finding['context_explanation'] = value
                elif key == 'impact':
                    finding['impact'] = value
                elif key == 'recommendation':
                    finding['recommendation'] = value
                elif key == 'code_snippet':
                    finding['code_snippet'] = value
                elif key == 'exploit_example':
                    finding['exploit_example'] = value
                elif key == 'normative_reference':
                    finding['normative_reference'] = value
            
            # Validar que tenga campos mínimos
            required = ['severity', 'category', 'title']
            if all(k in finding for k in required):
                return finding
            
            return None
        
        except Exception as e:
            logger.warning(f"⚠️ Error parseando hallazgo: {e}")
            return None
    
    def quick_security_check(self, sp_code: str) -> Dict[str, bool]:
        """
        Verificación rápida de seguridad (sin análisis completo)
        
        Returns:
            Dict con flags de problemas detectados
        """
        checks = {
            "has_dynamic_sql": "EXEC(" in sp_code or "EXECUTE(" in sp_code,
            "has_sql_injection_risk": "+@" in sp_code or "CONCAT" in sp_code,
            "returns_passwords": "password" in sp_code.lower() and "SELECT" in sp_code,
            "has_hardcoded_creds": any(
                pattern in sp_code.lower() 
                for pattern in ["password=", "pwd=", "user='sa'"]
            ),
            "missing_error_handling": "TRY" not in sp_code or "CATCH" not in sp_code,
            "has_cursors": "CURSOR" in sp_code.upper(),
            "uses_select_star": "SELECT *" in sp_code
        }
        
        return checks


# Instancia global del servicio
gemini_service = GeminiService()
