"""
api_server_final.py — Servidor Flask para generación de informes IA
Coloca este archivo en el mismo directorio que analizador_tfm_final.py

Instalación (una vez):
    sudo /home/nuria/llm/venv/bin/pip install flask

Ejecución:
    sudo /home/nuria/llm/venv/bin/python3 api_server_final.py
"""

import os
import sys
from flask import Flask, Response, stream_with_context, jsonify
import ollama

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analizador_tfm_final import (
    filtrar_reporte_cape,
    construir_prompt,
    BASE_PATH,
    SYSTEM_MSG,
)

app = Flask(__name__)

OLLAMA_MODEL = "llama3"
AI_REPORT_PATH = "/opt/CAPEv2/storage/analyses/{id}/reports/ai_report.md"


@app.route("/report/<int:task_id>/load", methods=["GET"])
def load_report(task_id):
    """Devuelve el informe IA guardado en disco, si existe."""
    path = AI_REPORT_PATH.format(id=task_id)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return Response(f.read(), content_type="text/plain; charset=utf-8")
    return jsonify({"error": "No hay informe guardado"}), 404


@app.route("/report/<int:task_id>", methods=["GET"])
def generate_report(task_id):
    """Genera el informe con Ollama (streaming) y lo guarda en disco al terminar."""
    ruta = BASE_PATH.format(id=task_id)
    datos = filtrar_reporte_cape(ruta)

    if datos is None:
        return jsonify({"error": f"No se pudo leer el reporte para el análisis {task_id}"}), 404

    prompt = construir_prompt(datos)

    def stream_response():
        full_text = ""
        try:
            stream = ollama.chat(
                model=OLLAMA_MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_MSG},
                    {"role": "user", "content": prompt},
                ],
                stream=True,
                options={
                    "temperature": 0.0,
                    "num_predict": 4000,
                    "num_ctx": 8192,
                },
            )
            for chunk in stream:
                if "error" in chunk:
                    error_msg = f"\n\n❌ [ERROR INTERNO DE OLLAMA]: {chunk['error']}"
                    print(error_msg)
                    yield error_msg
                    break
                content = chunk.get("message", {}).get("content", "")
                if content:
                    full_text += content
                    yield content

            if full_text:
                path = AI_REPORT_PATH.format(id=task_id)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(full_text)

        except Exception as e:
            yield f"\n\n❌ Error al conectar con Ollama: {e}"

    return Response(
        stream_with_context(stream_response()),
        content_type="text/plain; charset=utf-8",
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"},
    )


@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


if __name__ == "__main__":
    print(f"🚀 API server arrancando en http://0.0.0.0:5001")
    print(f"   Modelo: {OLLAMA_MODEL}")
    print(f"   Informes guardados en: {AI_REPORT_PATH}")
    app.run(host="0.0.0.0", port=5001, debug=False)
