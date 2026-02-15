"""
Servicio de análisis de stored procedures (Regex + AI)
"""
from typing import List, Dict, Any, Optional
import re
from datetime import datetime
from loguru import logger

from services.sql_server import sql_service
from services.gemini_service import gemini_service
from utils.patterns import PatternAnalyzer
from utils.helpers import (
    generate_uuid,
    extract_code_context,
    get_recommendation_for_finding,
    get_impact_description,
    calculate_risk_score
)
from models.audit import (
    AnalysisType,
    AnalysisStatus,
    CategoryType,
    SeverityLevel,
    Finding,
    FindingLocation,
    FindingsSummary
)
from config.database import db


class AnalyzerService:
    """Servicio principal de análisis"""
    
    def __init__(self):
        self.active_analyses: Dict[str, Dict[str, Any]] = {}
    
    async def analyze_stored_procedures(
        self,
        connection_id: str,
        sp_ids: List[int],
        analysis_type: AnalysisType = AnalysisType.FULL,
        use_ai: bool = True,
        save_to_db: bool = True
    ) -> Dict[str, Any]:
        """
        Analizar stored procedures seleccionados
        
        Args:
            connection_id: ID de conexión SQL Server
            sp_ids: IDs de SPs a analizar
            analysis_type: Tipo de análisis (full/quick)
            use_ai: Usar Gemini AI
            save_to_db: Guardar en Supabase
        
        Returns:
            Dict con resultados del análisis
        """
        analysis_id = generate_uuid()
        started_at = datetime.now()
        
        logger.info(f"🔍 Iniciando análisis {analysis_id} de {len(sp_ids)} SPs")
        
        # Obtener información de la base de datos
        db_info = sql_service.get_database_info(connection_id)
        
        # Registrar análisis activo
        self.active_analyses[analysis_id] = {
            "status": AnalysisStatus.IN_PROGRESS,
            "started_at": started_at,
            "total_sps": len(sp_ids),
            "analyzed_sps": 0,
            "findings": [],
            "database_name": db_info["name"],
            "server": db_info["server"]
        }
        
        # Crear registro en Supabase si se requiere
        audit_db_id = None
        if save_to_db:
            audit_db_id = await self._create_audit_record(
                connection_id=connection_id,
                total_sps=len(sp_ids),
                started_at=started_at
            )
        
        all_findings = []
        analyzed_count = 0
        
        try:
            for sp_id in sp_ids:
                # Obtener SP de SQL Server
                sp = sql_service.get_stored_procedure(connection_id, sp_id)
                
                if not sp:
                    logger.warning(f"⚠️ SP {sp_id} no encontrado")
                    continue
                
                logger.info(f"📝 Analizando: {sp.full_name}")
                
                # Analizar con regex
                regex_findings = self._analyze_with_regex(sp)
                
                # Analizar con AI si está habilitado
                ai_findings = []
                if use_ai and analysis_type == AnalysisType.FULL:
                    ai_findings = await self._analyze_with_ai(sp)
                
                # Combinar hallazgos
                sp_findings = self._merge_findings(
                    connection_id=connection_id,
                    sp_id=sp.object_id,
                    sp_name=sp.full_name,
                    sp_code=sp.definition,
                    regex_findings=regex_findings,
                    ai_findings=ai_findings
                )
                
                all_findings.extend(sp_findings)
                analyzed_count += 1
                
                # Guardar SP y hallazgos en DB
                if save_to_db and audit_db_id:
                    sp_db_id = await self._save_sp_to_db(audit_db_id, sp)
                    await self._save_findings_to_db(audit_db_id, sp_db_id, sp_findings)
                
                # Actualizar progreso
                self.active_analyses[analysis_id]["analyzed_sps"] = analyzed_count
                
                logger.success(f"✅ {sp.full_name}: {len(sp_findings)} hallazgos")
            
            # Calcular resumen
            findings_summary = self._calculate_findings_summary(all_findings)
            risk_score = calculate_risk_score({
                'critical': findings_summary.critical,
                'high': findings_summary.high,
                'medium': findings_summary.medium,
                'low': findings_summary.low,
                'info': findings_summary.info
            })
            
            completed_at = datetime.now()
            duration = (completed_at - started_at).total_seconds()
            
            # Actualizar análisis (convertir findings_summary a dict)
            self.active_analyses[analysis_id].update({
                "status": AnalysisStatus.COMPLETED,
                "completed_at": completed_at,
                "duration_seconds": duration,
                "findings": all_findings,
                "findings_summary": findings_summary.dict() if hasattr(findings_summary, 'dict') else findings_summary.model_dump()
            })
            
            # Actualizar en Supabase
            if save_to_db and audit_db_id:
                await db.update_auditoria(audit_db_id, {
                    "status": AnalysisStatus.COMPLETED.value,
                    "analyzed_sps": analyzed_count,
                    "total_findings": len(all_findings),
                    "risk_score": risk_score,
                    "completed_at": completed_at.isoformat()
                })
            
            logger.success(
                f"🎉 Análisis completado en {duration:.1f}s: "
                f"{len(all_findings)} hallazgos"
            )
            
            return {
                "analysis_id": analysis_id,
                "audit_db_id": audit_db_id,
                "status": AnalysisStatus.COMPLETED,
                "database_name": db_info["name"],
                "server": db_info["server"],
                "analyzed_count": analyzed_count,
                "findings_summary": findings_summary.dict() if hasattr(findings_summary, 'dict') else findings_summary.model_dump(),
                "findings": all_findings,
                "started_at": started_at,
                "completed_at": completed_at,
                "duration_seconds": duration,
                "risk_score": risk_score
            }
        
        except Exception as e:
            logger.error(f"❌ Error en análisis: {e}")
            
            self.active_analyses[analysis_id]["status"] = AnalysisStatus.FAILED
            
            if save_to_db and audit_db_id:
                await db.update_auditoria(audit_db_id, {
                    "status": AnalysisStatus.FAILED.value
                })
            
            raise
    
    def _analyze_with_regex(self, sp) -> List[Dict[str, Any]]:
        """Analizar SP con patrones regex"""
        return PatternAnalyzer.analyze(sp.definition)
    
    async def _analyze_with_ai(self, sp) -> List[Dict[str, Any]]:
        """Analizar SP con Gemini AI"""
        try:
            ai_result = gemini_service.analyze_stored_procedure(
                sp_name=sp.full_name,
                sp_code=sp.definition,
                context="Sistema de autenticación Hass Perú"
            )
            
            return ai_result.get("findings", [])
        
        except Exception as e:
            logger.error(f"⚠️ Error en análisis AI: {e}")
            return []
    
    def _merge_findings(
        self,
        connection_id: str,
        sp_id: int,
        sp_name: str,
        sp_code: str,
        regex_findings: List[Dict],
        ai_findings: List[Dict]
    ) -> List[Dict[str, Any]]:
        """Combinar hallazgos de regex y AI, eliminando duplicados"""
        merged = []
        finding_counter = 1
        
        # Procesar hallazgos de regex
        for finding in regex_findings:
            evidence_data, records_preview, records_source = self._build_evidence_data(
                connection_id=connection_id,
                sp_code=sp_code,
                code_snippet=finding.get("code_snippet", ""),
                finding_type=finding.get("type", "unknown"),
                limit=5
            )
            merged.append({
                "id": f"finding-{finding_counter}",
                "sp_id": sp_id,
                "sp_name": sp_name,
                "category": finding.get("category", CategoryType.SECURITY).value,
                "severity": finding.get("severity", SeverityLevel.MEDIUM).value,
                "type": finding.get("type", "unknown"),
                "title": finding.get("title", "Problema detectado"),
                "description": finding.get("description", finding.get("title", "")),
                "context_explanation": finding.get(
                    "description", finding.get("title", "")
                ),
                "location": {
                    "line": finding.get("line", 0),
                    "code_snippet": finding.get("code_snippet", "")
                },
                "impact": get_impact_description(
                    finding.get("severity", SeverityLevel.MEDIUM).value,
                    finding.get("category", CategoryType.SECURITY).value
                ),
                "recommendation": get_recommendation_for_finding(
                    finding.get("type", "unknown")
                ),
                "cwe_id": finding.get("cwe_id"),
                "cvss_score": finding.get("cvss_score"),
                "detected_by": "regex",
                    "evidence": extract_code_context(sp_code, finding.get("line", 0)),
                "exploit_example": "",
                "records_preview": records_preview,
                "records_source": records_source,
                "evidence_data": evidence_data
            })
            finding_counter += 1
        
        # Procesar hallazgos de AI
        for finding in ai_findings:
            if finding.get("category", "").lower() != "security":
                continue
            evidence_data, records_preview, records_source = self._build_evidence_data(
                connection_id=connection_id,
                sp_code=sp_code,
                code_snippet=finding.get("code_snippet", ""),
                finding_type=finding.get("type", "ai_detected"),
                limit=5
            )
            merged.append({
                "id": f"finding-{finding_counter}",
                "sp_id": sp_id,
                "sp_name": sp_name,
                "category": finding.get("category", "security"),
                "severity": finding.get("severity", "medium"),
                "type": finding.get("type", "ai_detected"),
                "title": finding.get("title", "Problema detectado por IA"),
                "description": finding.get("description", ""),
                "context_explanation": finding.get(
                    "context_explanation", finding.get("description", "")
                ),
                "location": {
                    "line": finding.get("line", 0),
                    "code_snippet": finding.get("code_snippet", "")
                },
                "impact": finding.get("impact", "Impacto pendiente de evaluación"),
                "recommendation": finding.get("recommendation", "Revisar con equipo de seguridad"),
                "cwe_id": None,
                "cvss_score": None,
                "detected_by": "gemini_ai",
                    "evidence": extract_code_context(sp_code, finding.get("line", 0)),
                    "exploit_example": finding.get("exploit_example", ""),
                "records_preview": records_preview,
                "records_source": records_source,
                "evidence_data": evidence_data
            })
            finding_counter += 1
        
        return merged

    def build_evidence_for_finding(
        self,
        connection_id: str,
        sp_id: int,
        finding_type: str,
        code_snippet: Optional[str]
    ) -> Dict[str, Any]:
        """Generar evidencia real para un hallazgo puntual"""
        try:
            sp = sql_service.get_stored_procedure(connection_id, sp_id)
        except ValueError as e:
            if "Conexión no encontrada" in str(e):
                raise ValueError(
                    "Conexión SQL no disponible. Reconecta a la base de datos antes de generar evidencia. "
                    "(Las conexiones se pierden al reiniciar el servidor)"
                )
            raise
        
        if not sp:
            raise ValueError("Stored procedure no encontrado")

        evidence_data, records_preview, records_source = self._build_evidence_data(
            connection_id=connection_id,
            sp_code=sp.definition,
            code_snippet=code_snippet or "",
            finding_type=finding_type,
            limit=5
        )

        evidence_data["records_preview"] = records_preview
        evidence_data["records_source"] = records_source

        return {
            "sp_id": sp_id,
            "evidence_data": evidence_data
        }

    def _build_evidence_data(
        self,
        connection_id: str,
        sp_code: str,
        code_snippet: str,
        finding_type: str,
        limit: int = 10
    ) -> tuple[Dict[str, Any], List[Dict[str, Any]], Optional[str]]:
        """Construir evidencia CONTEXTUAL según el tipo de vulnerabilidad"""
        
        # Log para debug
        logger.info(f"🔍 Generando evidencia para: {finding_type}")
        
        # Analizar contexto del código vulnerable
        context = self._analyze_vulnerability_context(code_snippet, sp_code, finding_type)
        
        # Normalizar finding_type para detección flexible
        finding_lower = finding_type.lower()
        
        # Detectar tipo de vulnerabilidad por palabras clave
        is_sql_injection = any(keyword in finding_lower for keyword in [
            "sql injection", "inyección", "concatenación", "exec(", "execute(", 
            "sql dinámico", "dynamic sql", "parámetro de búsqueda"
        ])
        
        is_password = any(keyword in finding_lower for keyword in [
            "password", "contraseña", "clave", "plaintext", "texto plano",
            "credencial", "sin cifrar", "sin encriptar"
        ])
        
        is_sensitive_data = any(keyword in finding_lower for keyword in [
            "sensiti", "exposición", "dni", "email", "datos personales",
            "información confidencial", "privacidad"
        ]) and not is_password  # No confundir con passwords
        
        # Generar evidencia específica según el tipo
        if is_sql_injection:
            logger.info("→ Generando evidencia de SQL Injection")
            return self._build_sql_injection_evidence(connection_id, context, sp_code, code_snippet, limit)
        
        elif is_password:
            logger.info("→ Generando evidencia de contraseñas en texto plano")
            return self._build_password_evidence(connection_id, context, sp_code, limit)
        
        elif is_sensitive_data:
            logger.info("→ Generando evidencia de exposición de datos sensibles")
            return self._build_sensitive_data_evidence(connection_id, context, sp_code, limit)
        
        # Fallback genérico (para otros tipos)
        logger.info("→ Generando evidencia genérica")
        return self._build_generic_evidence(connection_id, context, sp_code, code_snippet, finding_type, limit)

    def _analyze_vulnerability_context(
        self,
        code_snippet: str,
        sp_code: str,
        finding_type: str
    ) -> Dict[str, Any]:
        """Analizar el contexto específico de la vulnerabilidad"""
        context = {
            "tables": [],
            "parameters": [],
            "columns_involved": [],
            "operation": None,
            "vulnerable_clause": None
        }
        
        # Extraer tablas
        code = code_snippet or sp_code
        context["tables"] = self._extract_table_candidates(code)
        
        # Extraer parámetros (@variable)
        param_pattern = re.compile(r"@(\w+)")
        context["parameters"] = list(set(param_pattern.findall(code)))
        
        # Identificar operación (SELECT, WHERE, JOIN, etc.)
        if re.search(r"\bWHERE\b", code, re.I):
            context["operation"] = "WHERE"
            where_match = re.search(r"(?i)WHERE\s+(.*?)(?:ORDER|GROUP|$)", code, re.DOTALL)
            if where_match:
                context["vulnerable_clause"] = where_match.group(1).strip()
        elif re.search(r"\bJOIN\b", code, re.I):
            context["operation"] = "JOIN"
        elif re.search(r"\bSELECT\b", code, re.I):
            context["operation"] = "SELECT"
        
        # Extraer columnas mencionadas en el código vulnerable
        col_pattern = re.compile(r"(?:\.|\[)(\w+)(?:\]|\s|,|=)")
        context["columns_involved"] = list(set(col_pattern.findall(code)))[:10]
        
        return context

    def _build_sql_injection_evidence(
        self,
        connection_id: str,
        context: Dict[str, Any],
        sp_code: str,
        code_snippet: str,
        limit: int
    ) -> tuple[Dict[str, Any], List[Dict[str, Any]], Optional[str]]:
        """Evidencia específica para SQL Injection"""
        
        if not context["tables"]:
            return self._build_generic_evidence(connection_id, context, sp_code, code_snippet, "sql_injection", limit)
        
        # Usar la primera tabla como objetivo
        table = context["tables"][0]
        schema, table_name = self._split_table_name(table)
        full_table = f"[{schema}].[{table_name}]" if schema and table_name else None
        
        if not full_table or not self._is_safe_table_name(full_table):
            return self._build_generic_evidence(connection_id, context, sp_code, code_snippet, "sql_injection", limit)
        
        # Obtener columnas de la tabla
        try:
            columns = sql_service.get_table_columns(connection_id, schema, table_name)
        except:
            columns = []
        
        # Identificar qué columnas están involucradas en la vulnerabilidad
        involved_columns = []
        for col in context["columns_involved"]:
            if col in columns:
                involved_columns.append(col)
        
        # Si no hay columnas específicas, tomar las primeras de la tabla
        if not involved_columns:
            involved_columns = columns[:3]
        
        # Demostrar el impacto del SQL Injection
        total_records = self._fetch_single_value(connection_id, f"SELECT COUNT(*) AS total FROM {full_table}", "total")
        
        # Conteos solo de columnas involucradas
        record_counts = [{
            "table": full_table,
            "total_records": total_records,
            "sensitive_counts": {},
            "columns_affected": involved_columns[:5]
        }]
        
        # Muestra de datos que podrían filtrarse
        sample_query = self._build_masked_sample_query(full_table, involved_columns[:5], limit)
        masked_samples = []
        records_preview = []
        records_source = None
        
        if sample_query:
            try:
                rows = sql_service.fetch_records(connection_id, sample_query, max_rows=limit)
                masked_samples.append({"table": full_table, "rows": rows})
                records_preview = rows
                records_source = full_table
            except Exception as e:
                logger.warning(f"⚠️ Error obteniendo muestra: {e}")
        
        # Escenario de ataque específico
        params = context["parameters"]
        vulnerable_param = params[0] if params else "parámetro"
        attack_scenario = (
            f"Un atacante manipula el parámetro @{vulnerable_param} con payloads como "
            f"\"' OR '1'='1\" o \"'; DROP TABLE--\" para alterar la consulta SQL. "
            f"Esto permite acceder sin autenticación a {total_records} registros de {full_table}, "
            f"exponiendo columnas: {', '.join(involved_columns[:5])}."
        )
        
        evidence_data = {
            "tables": [full_table],
            "selected_columns": involved_columns,
            "sensitive_columns": [],  # SQL Injection no se trata de columnas sensibles sino de manipulación
            "keyword_counts": {},
            "record_counts": record_counts,
            "masked_samples": masked_samples,
            "attack_scenario": attack_scenario,
            "vulnerability_context": {
                "type": "SQL Injection",
                "vulnerable_parameters": params,
                "affected_columns": involved_columns[:5],
                "operation": context["operation"],
                "clause": context["vulnerable_clause"]
            }
        }
        
        return evidence_data, records_preview, records_source

    def _build_password_evidence(
        self,
        connection_id: str,
        context: Dict[str, Any],
        sp_code: str,
        limit: int
    ) -> tuple[Dict[str, Any], List[Dict[str, Any]], Optional[str]]:
        """Evidencia específica para contraseñas en texto plano"""
        
        if not context["tables"]:
            return self._build_generic_evidence(connection_id, context, sp_code, "", "plaintext_password", limit)
        
        # Buscar tablas con columnas de contraseñas
        password_findings = []
        
        for table in context["tables"][:2]:
            schema, table_name = self._split_table_name(table)
            full_table = f"[{schema}].[{table_name}]" if schema and table_name else None
            
            if not full_table or not self._is_safe_table_name(full_table):
                continue
            
            try:
                columns = sql_service.get_table_columns(connection_id, schema, table_name)
            except:
                continue
            
            # Buscar SOLO columnas de contraseña
            password_columns = [col for col in columns if any(
                pwd in col.lower() for pwd in ["password", "clave", "pwd", "pass", "contrase"]
            )]
            
            if not password_columns:
                continue
            
            # Conteo de contraseñas
            total_records = self._fetch_single_value(connection_id, f"SELECT COUNT(*) AS total FROM {full_table}", "total")
            
            sensitive_counts = {}
            for col in password_columns[:3]:
                if self._is_safe_identifier(col):
                    query = f"SELECT COUNT(DISTINCT [{col}]) AS distinct_count, COUNT([{col}]) AS non_null FROM {full_table}"
                    result = self._fetch_single_row(connection_id, query)
                    if result:
                        sensitive_counts[col] = {
                            "distinct": result.get("distinct_count", 0),
                            "non_null": result.get("non_null", 0)
                        }
            
            # Muestra SOLO de contraseñas (enmascaradas)
            sample_query = self._build_masked_sample_query(full_table, password_columns[:2], limit)
            rows = []
            if sample_query:
                try:
                    rows = sql_service.fetch_records(connection_id, sample_query, max_rows=limit)
                except:
                    pass
            
            password_findings.append({
                "table": full_table,
                "password_columns": password_columns[:3],
                "total_records": total_records,
                "sensitive_counts": sensitive_counts,
                "sample_rows": rows
            })
        
        if not password_findings:
            return self._build_generic_evidence(connection_id, context, sp_code, "", "plaintext_password", limit)
        
        # Consolidar evidencia
        first_finding = password_findings[0]
        attack_scenario = (
            f"Las contraseñas en {first_finding['table']} se almacenan en texto plano "
            f"en las columnas: {', '.join(first_finding['password_columns'])}. "
            f"Cualquier usuario con acceso SELECT puede leer las {first_finding['total_records']} contraseñas "
            f"directamente, comprometiendo la seguridad de todas las cuentas."
        )
        
        evidence_data = {
            "tables": [f["table"] for f in password_findings],
            "selected_columns": first_finding["password_columns"],
            "sensitive_columns": first_finding["password_columns"],
            "keyword_counts": {"password": len(first_finding["password_columns"])},
            "record_counts": [{
                "table": f["table"],
                "total_records": f["total_records"],
                "sensitive_counts": f["sensitive_counts"]
            } for f in password_findings],
            "masked_samples": [{
                "table": f["table"],
                "rows": f["sample_rows"]
            } for f in password_findings],
            "attack_scenario": attack_scenario,
            "vulnerability_context": {
                "type": "Plaintext Password Storage",
                "password_columns_found": first_finding["password_columns"],
                "total_passwords_exposed": first_finding["total_records"]
            }
        }
        
        records_preview = first_finding["sample_rows"]
        records_source = first_finding["table"]
        
        return evidence_data, records_preview, records_source

    def _build_sensitive_data_evidence(
        self,
        connection_id: str,
        context: Dict[str, Any],
        sp_code: str,
        limit: int
    ) -> tuple[Dict[str, Any], List[Dict[str, Any]], Optional[str]]:
        """Evidencia para exposición de datos sensibles"""
        
        # Extraer qué columnas SELECT devuelve el SP
        selected_columns = self._extract_selected_columns(sp_code)
        
        if not context["tables"] or not selected_columns:
            return self._build_generic_evidence(connection_id, context, sp_code, "", "sensitive_data_exposure", limit)
        
        table = context["tables"][0]
        schema, table_name = self._split_table_name(table)
        full_table = f"[{schema}].[{table_name}]" if schema and table_name else None
        
        if not full_table or not self._is_safe_table_name(full_table):
            return self._build_generic_evidence(connection_id, context, sp_code, "", "sensitive_data_exposure", limit)
        
        try:
            all_columns = sql_service.get_table_columns(connection_id, schema, table_name)
        except:
            all_columns = []
        
        # Identificar cuáles de las columnas SELECT son sensibles
        exposed_sensitive = []
        for col in selected_columns:
            if col in all_columns and any(
                key in col.lower() for key in ["password", "dni", "tarjeta", "cvv", "salario", "cuenta"]
            ):
                exposed_sensitive.append(col)
        
        if not exposed_sensitive:
            # Si SELECT * o no hay sensibles explícitas, buscar todas las sensibles de la tabla
            exposed_sensitive = self._pick_sensitive_columns(all_columns)
        
        # Conteos
        total_records = self._fetch_single_value(connection_id, f"SELECT COUNT(*) AS total FROM {full_table}", "total")
        
        sensitive_counts = {}
        for col in exposed_sensitive[:5]:
            if self._is_safe_identifier(col):
                query = f"SELECT COUNT(DISTINCT [{col}]) AS distinct_count, COUNT([{col}]) AS non_null FROM {full_table}"
                result = self._fetch_single_row(connection_id, query)
                if result:
                    sensitive_counts[col] = {
                        "distinct": result.get("distinct_count", 0),
                        "non_null": result.get("non_null", 0)
                    }
        
        # Muestra
        sample_query = self._build_masked_sample_query(full_table, exposed_sensitive[:5], limit)
        rows = []
        if sample_query:
            try:
                rows = sql_service.fetch_records(connection_id, sample_query, max_rows=limit)
            except:
                pass
        
        attack_scenario = (
            f"El SP expone sin restricciones las columnas sensibles: {', '.join(exposed_sensitive[:5])} "
            f"de {full_table}. Un usuario malicioso puede ejecutar el SP y extraer "
            f"{total_records} registros con información confidencial para robo de identidad, "
            f"fraude financiero o ingeniería social."
        )
        
        evidence_data = {
            "tables": [full_table],
            "selected_columns": selected_columns,
            "sensitive_columns": exposed_sensitive,
            "keyword_counts": {},
            "record_counts": [{
                "table": full_table,
                "total_records": total_records,
                "sensitive_counts": sensitive_counts
            }],
            "masked_samples": [{"table": full_table, "rows": rows}],
            "attack_scenario": attack_scenario,
            "vulnerability_context": {
                "type": "Sensitive Data Exposure",
                "exposed_columns": exposed_sensitive[:5],
                "selected_by_sp": selected_columns[:10]
            }
        }
        
        return evidence_data, rows, full_table

    def _build_generic_evidence(
        self,
        connection_id: str,
        context: Dict[str, Any],
        sp_code: str,
        code_snippet: str,
        finding_type: str,
        limit: int
    ) -> tuple[Dict[str, Any], List[Dict[str, Any]], Optional[str]]:
        """Evidencia genérica para vulnerabilidades sin contexto específico"""
        
        tables = context["tables"]
        if not tables:
            logger.warning("⚠️ No se encontraron tablas en el código vulnerable")
            return {
                "tables": [],
                "selected_columns": [],
                "sensitive_columns": [],
                "keyword_counts": {},
                "record_counts": [],
                "masked_samples": [],
                "attack_scenario": f"Vulnerabilidad detectada: {finding_type}. No se pudieron extraer tablas del código para análisis automático.",
                "vulnerability_context": {
                    "type": "Generic Vulnerability",
                    "finding_type": finding_type,
                    "note": "Análisis manual recomendado - contexto insuficiente para evidencia automática"
                }
            }, [], None
        
        table = tables[0]
        schema, table_name = self._split_table_name(table)
        full_table = f"[{schema}].[{table_name}]" if schema and table_name else None
        
        if not full_table or not self._is_safe_table_name(full_table):
            logger.warning(f"⚠️ Tabla inválida o insegura: {table}")
            return {
                "tables": [],
                "selected_columns": [],
                "sensitive_columns": [],
                "keyword_counts": {},
                "record_counts": [],
                "masked_samples": [],
                "attack_scenario": f"Vulnerabilidad detectada: {finding_type}. La tabla detectada no pudo ser validada para consultas.",
                "vulnerability_context": {
                    "type": "Generic Vulnerability",
                    "finding_type": finding_type,
                    "detected_table": table
                }
            }, [], None
        
        # Intentar obtener información básica de la tabla
        try:
            columns = sql_service.get_table_columns(connection_id, schema, table_name)
        except Exception as e:
            logger.warning(f"⚠️ No se pudieron obtener columnas de {full_table}: {e}")
            columns = []
        
        # Obtener conteo total
        total_records = self._fetch_single_value(
            connection_id, 
            f"SELECT COUNT(*) AS total FROM {full_table}", 
            "total"
        )
        
        # Intentar identificar columnas relevantes
        involved_columns = context["columns_involved"][:5] if context["columns_involved"] else []
        sample_columns = [col for col in involved_columns if col in columns]
        
        # Si no hay columnas específicas, usar las primeras de la tabla
        if not sample_columns and columns:
            sample_columns = columns[:5]
        
        # Generar muestra si hay columnas disponibles
        rows = []
        if sample_columns:
            sample_query = self._build_masked_sample_query(full_table, sample_columns, limit)
            if sample_query:
                try:
                    rows = sql_service.fetch_records(connection_id, sample_query, max_rows=limit)
                except Exception as e:
                    logger.warning(f"⚠️ Error al obtener muestra de {full_table}: {e}")
        
        # Escenario basado en lo que se pudo detectar
        attack_scenario = (
            f"Vulnerabilidad: {finding_type}. "
            f"La tabla {full_table} contiene {total_records} registros que podrían ser afectados. "
        )
        
        if involved_columns:
            attack_scenario += f"Columnas involucradas: {', '.join(involved_columns)}. "
        
        attack_scenario += "Se recomienda revisión manual del código para evaluar el impacto completo."
        
        evidence_data = {
            "tables": [full_table],
            "selected_columns": sample_columns,
            "sensitive_columns": [],
            "keyword_counts": {},
            "record_counts": [{
                "table": full_table,
                "total_records": total_records,
                "sensitive_counts": {},
                "columns_affected": sample_columns
            }],
            "masked_samples": [{"table": full_table, "rows": rows}] if rows else [],
            "attack_scenario": attack_scenario,
            "vulnerability_context": {
                "type": "Generic Vulnerability",
                "finding_type": finding_type,
                "table_analyzed": full_table,
                "columns_detected": sample_columns[:5]
            }
        }
        
        return evidence_data, rows, full_table

    def _pick_table_for_finding(self, code_snippet: str, sp_code: str) -> Optional[str]:
        """Elegir la tabla mas relevante desde un snippet o el SP completo"""
        for source in [code_snippet, sp_code]:
            candidates = self._extract_table_candidates(source)
            if candidates:
                return candidates[0]
        return None

    def _extract_table_candidates(self, code: str) -> List[str]:
        """Extraer tablas desde FROM/JOIN simples"""
        if not code:
            return []

        pattern = re.compile(r"(?i)\b(from|join)\s+([\w\[\]\.]+)")
        ignore = {
            "openjson",
            "openrowset",
            "opendatasource",
            "openquery",
            "json_value",
            "json_query"
        }
        tables = []
        for match in pattern.finditer(code):
            table = match.group(2)
            if table.startswith("#") or table.startswith("@"):
                continue
            if table.strip("[]").lower() in ignore:
                continue
            tables.append(table)

        seen = set()
        unique = []
        for table in tables:
            key = table.lower()
            if key in seen:
                continue
            seen.add(key)
            unique.append(table)
        return unique

    def _is_safe_table_name(self, table: str) -> bool:
        """Validar que el nombre de tabla sea seguro para consulta simple"""
        return bool(re.match(r"^[\w\[\]\.]+$", table))

    def _split_table_name(self, table: str) -> tuple[Optional[str], Optional[str]]:
        """Separar schema y tabla, normalizando brackets"""
        clean = table.replace("[", "").replace("]", "")
        parts = [part for part in clean.split(".") if part]
        if not parts:
            return None, None
        if len(parts) == 1:
            return "dbo", parts[0]
        if len(parts) == 2:
            return parts[0], parts[1]
        return parts[-2], parts[-1]

    def _extract_selected_columns(self, code: str) -> List[str]:
        """Extraer columnas desde SELECT ... FROM"""
        if not code:
            return []
        pattern = re.compile(r"(?is)select\s+(?:distinct\s+)?(?:top\s+\d+\s+)?(.*?)\s+from\s", re.MULTILINE)
        columns = []
        for match in pattern.finditer(code):
            segment = match.group(1)
            for raw_col in segment.split(","):
                token = raw_col.strip()
                if not token or token == "*" or token.endswith(".*"):
                    continue
                token = re.sub(r"(?i)\s+as\s+.*$", "", token)
                token = token.split()[0]
                if "(" in token:
                    continue
                token = token.split(".")[-1].strip("[]")
                if token and token not in columns:
                    columns.append(token)
        return columns

    def _count_sensitive_keywords(self, code: str) -> Dict[str, int]:
        """Contar palabras clave sensibles en el SP"""
        keywords = ["password", "clave", "dni", "tarjeta", "cvv", "email", "salario", "telefono"]
        counts = {}
        lower = code.lower() if code else ""
        for key in keywords:
            counts[key] = len(re.findall(rf"\b{re.escape(key)}\b", lower))
        return counts

    def _pick_sensitive_columns(self, columns: List[str]) -> List[str]:
        """Detectar columnas sensibles por nombre"""
        keywords = [
            "password", "clave", "dni", "tarjeta", "cvv", "email",
            "salario", "telefono", "numero", "cuenta", "ruc"
        ]
        sensitive = []
        for col in columns:
            name = col.lower()
            if any(key in name for key in keywords):
                sensitive.append(col)
        return sensitive

    def _pick_sample_columns(
        self,
        selected_columns: List[str],
        sensitive_columns: List[str],
        available_columns: List[str]
    ) -> List[str]:
        """Elegir columnas para muestra enmascarada"""
        available_map = {col.lower(): col for col in available_columns}

        def filter_available(cols: List[str]) -> List[str]:
            return [available_map[c.lower()] for c in cols if c.lower() in available_map]

        if sensitive_columns:
            filtered = filter_available(sensitive_columns)
            if filtered:
                return filtered[:6]

        if selected_columns:
            filtered = filter_available(selected_columns)
            if filtered:
                return filtered[:6]

        return available_columns[:6]

    def _build_masked_sample_query(
        self,
        table: str,
        columns: List[str],
        limit: int
    ) -> str:
        """Construir query de muestra enmascarada"""
        expressions = []
        for col in columns:
            if not self._is_safe_identifier(col):
                continue
            expressions.append(self._mask_sql_expression(col))
        if not expressions:
            return ""
        return f"SELECT TOP {limit} {', '.join(expressions)} FROM {table}"

    def _mask_sql_expression(self, column: str) -> str:
        """Generar expresion SQL de enmascarado por tipo de columna"""
        col_ref = f"[{column}]"
        value = f"CONVERT(VARCHAR(255), {col_ref})"
        name = column.lower()

        if any(key in name for key in ["password", "clave", "pwd", "pass"]):
            return (
                f"CASE WHEN {col_ref} IS NULL THEN NULL "
                f"WHEN LEN({value}) <= 2 THEN {value} "
                f"ELSE LEFT({value}, 2) + '****' END AS [{column}]"
            )

        if "dni" in name:
            return (
                f"CASE WHEN {col_ref} IS NULL THEN NULL "
                f"WHEN LEN({value}) <= 3 THEN {value} "
                f"ELSE LEFT({value}, 3) + '*****' END AS [{column}]"
            )

        if any(key in name for key in ["tarjeta", "card"]):
            return (
                f"CASE WHEN {col_ref} IS NULL THEN NULL "
                f"WHEN LEN({value}) <= 8 THEN {value} "
                f"ELSE LEFT({value}, 4) + REPLICATE('*', LEN({value}) - 8) + RIGHT({value}, 4) END AS [{column}]"
            )

        if "cvv" in name:
            return f"CASE WHEN {col_ref} IS NULL THEN NULL ELSE '***' END AS [{column}]"

        if "email" in name:
            return (
                f"CASE WHEN {col_ref} IS NULL THEN NULL "
                f"WHEN LEN({value}) <= 4 THEN {value} "
                f"ELSE LEFT({value}, 2) + '***' + RIGHT({value}, 2) END AS [{column}]"
            )

        if any(key in name for key in ["telefono", "phone"]):
            return (
                f"CASE WHEN {col_ref} IS NULL THEN NULL "
                f"WHEN LEN({value}) <= 5 THEN {value} "
                f"ELSE LEFT({value}, 3) + '****' + RIGHT({value}, 2) END AS [{column}]"
            )

        return (
            f"CASE WHEN {col_ref} IS NULL THEN NULL "
            f"WHEN LEN({value}) <= 4 THEN {value} "
            f"ELSE LEFT({value}, 2) + '****' + RIGHT({value}, 2) END AS [{column}]"
        )

    def _fetch_single_row(self, connection_id: str, query: str) -> Dict[str, Any]:
        """Obtener una fila unica de una consulta SELECT"""
        try:
            rows = sql_service.fetch_records(connection_id, query, max_rows=1)
            return rows[0] if rows else {}
        except Exception as e:
            logger.warning(f"⚠️ Consulta fallida: {e}")
            return {}

    def _fetch_single_value(self, connection_id: str, query: str, key: str) -> int:
        """Obtener un valor numerico desde una consulta"""
        row = self._fetch_single_row(connection_id, query)
        value = row.get(key)
        try:
            return int(value) if value is not None else 0
        except (TypeError, ValueError):
            return 0

    def _is_safe_identifier(self, name: str) -> bool:
        return bool(re.match(r"^[A-Za-z0-9_]+$", name))
    
    def _calculate_findings_summary(self, findings: List[Dict]) -> FindingsSummary:
        """Calcular resumen de hallazgos por severidad"""
        summary = FindingsSummary()
        
        for finding in findings:
            severity = finding.get("severity", "info")
            
            if severity == "critical":
                summary.critical += 1
            elif severity == "high":
                summary.high += 1
            elif severity == "medium":
                summary.medium += 1
            elif severity == "low":
                summary.low += 1
            else:
                summary.info += 1
        
        return summary
    
    async def _create_audit_record(
        self,
        connection_id: str,
        total_sps: int,
        started_at: datetime
    ) -> str:
        """Crear registro de auditoría en Supabase"""
        db_info = sql_service.get_database_info(connection_id)
        
        audit_data = {
            "connection_info": {
                "connection_id": connection_id,
                "server": db_info["server"]
            },
            "database_name": db_info["name"],
            "total_sps": total_sps,
            "analyzed_sps": 0,
            "total_findings": 0,
            "risk_score": 0.0,
            "status": AnalysisStatus.IN_PROGRESS.value,
            "started_at": started_at.isoformat()
        }
        
        result = await db.insert_auditoria(audit_data)
        return result["id"]
    
    async def _save_sp_to_db(self, audit_id: str, sp) -> str:
        """Guardar SP en Supabase"""
        sp_data = {
            "audit_id": audit_id,
            "schema_name": sp.schema_name,
            "sp_name": sp.procedure_name,
            "full_name": sp.full_name,
            "definition": sp.definition,
            "line_count": sp.line_count,
            "created_date": sp.create_date.isoformat() if sp.create_date else None,
            "modified_date": sp.modify_date.isoformat() if sp.modify_date else None,
            "is_analyzed": True
        }
        
        result = await db.insert_stored_procedure(sp_data)
        return result["id"]
    
    async def _save_findings_to_db(
        self,
        audit_id: str,
        sp_id: str,
        findings: List[Dict]
    ):
        """Guardar hallazgos en Supabase"""
        for finding in findings:
            finding_data = {
                "audit_id": audit_id,
                "sp_id": sp_id,
                "category": finding["category"],
                "severity": finding["severity"],
                "type": finding["type"],
                "title": finding["title"],
                "description": finding["description"],
                "location": finding["location"],
                "impact": finding["impact"],
                "recommendation": finding["recommendation"],
                "cwe_id": finding.get("cwe_id"),
                "cvss_score": finding.get("cvss_score"),
                "detected_by": finding["detected_by"],
                "evidence": finding.get("evidence")
            }
            
            await db.insert_hallazgo(finding_data)
    
    def get_analysis_status(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """Obtener estado de un análisis"""
        return self.active_analyses.get(analysis_id)


# Instancia global del servicio
analyzer_service = AnalyzerService()
