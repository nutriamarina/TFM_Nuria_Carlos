# Sandbox de Análisis de Malware con IA
 
Sistema de análisis dinámico de malware que combina **CAPE Sandbox** como motor de ejecución con un **LLM local (Llama 3 vía Ollama)** para generar informes de análisis en lenguaje natural, a partir del `report.json` que genera CAPE.
 
Trabajo de Fin de Máster — Máster Universitario en Ciberseguridad, UNIR.
 
## Componentes de este repositorio
 
- **Analizador** (`analizador_tfm_final.py`): filtra y resume el `report.json` de CAPE, elimina ruido e información no relevante, realiza una pre-clasificación heurística y construye el prompt que se envía al LLM.
- **API server**: expone los endpoints que conectan la web con CAPE y con el analizador, y gestiona el envío de muestras, la consulta de estado y la generación de informes.
- **Web**: interfaz para enviar muestras a analizar, hacer seguimiento del análisis y consultar tanto el informe técnico de CAPE como el informe generado por IA.
> Nota: este repositorio no incluye CAPE Sandbox ni Ollama; son dependencias externas que deben estar instaladas y en ejecución por separado.
