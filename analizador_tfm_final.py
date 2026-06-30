"""
analizador_tfm_final.py — Generador de informes de malware con IA a partir de CAPE Sandbox
Versión fusionada:
  - Extracción completa: behavior.summary, archivos dropeados, SMTP, familia CAPE
  - Pre-clasificación heurística como señal AUXILIAR (no autoritativa)
  - Clasificación derivada de DETECCION_CAPE → firmas → heurística (en ese orden)
  - Sección 0 visible + instrucciones prescriptivas por sección para que el LLM no omita nada
  - num_predict 4000 + num_ctx 8192
"""

import json
import os
import sys
import argparse
import ollama

BASE_PATH = "/opt/CAPEv2/storage/analyses/{id}/reports/report.json"


def resolver_ruta(arg_ruta: str) -> str:
    if arg_ruta.isdigit():
        return BASE_PATH.format(id=arg_ruta)
    return arg_ruta


# ─────────────────────────────────────────────────────────────────────────────
# PRE-CLASIFICACIÓN HEURÍSTICA EN PYTHON
# Señal auxiliar: ancla el LLM pero no es autoritativa.
# La clasificación final SIEMPRE debe basarse en DETECCION_CAPE.
# ─────────────────────────────────────────────────────────────────────────────

CATEGORIAS_MALWARE = {
    "ransomware": {
        "kw": [
            "ransom", "mass_file_modif", "file_encrypt", "shadow_copy",
            "vssadmin", "wbadmin", "bcdedit", "inhibit_recovery",
            "encrypt_file", "ransomware_",
        ],
        "ttps": {"T1486", "T1490", "T1485", "T1489"},
        "peso": 3,
    },
    "infostealer": {
        "kw": [
            "stealer", "credential", "keylog", "clipboard", "browser_cred",
            "password", "cookie_theft", "infostealer", "formgrab", "hawkeye",
            "screenshot_", "webcam",
        ],
        "ttps": {"T1003", "T1056", "T1539", "T1555", "T1113", "T1115", "T1125"},
        "peso": 3,
    },
    "loader_downloader": {
        "kw": [
            "downloader", "dropper", "loader", "download_file", "ingress_tool",
            "shellcode", "stage2",
        ],
        "ttps": {"T1105", "T1204", "T1566"},
        "peso": 2,
    },
    "rat": {
        "kw": [
            # Solo nombres de familias RAT conocidas o términos técnicamente precisos.
            # "backdoor", "remote_access", "remote_admin" eliminados: aparecen en descripciones
            # de casi cualquier malware que haga red y sesgan el score hacia RAT.
            "njrat", "darkcomet", "asyncrat", "remcos", "quasar", "nanocore",
            "netwire", "revenge", "orcusrat", "dcrat", "warzone",
            "reverse_shell", "remote_shell", "reverse_tcp",
            "rat_",  # prefijo en nombres de firmas CAPE (ej: rat_njrat, rat_asyncrat)
        ],
        "ttps": {"T1219"},
        "peso": 3,
    },
    "trojan_injector": {
        "kw": [
            "inject", "hollow", "process_inject", "dll_inject",
            "reflective_load", "unhook", "process_hollow",
        ],
        "ttps": {"T1055", "T1574", "T1620"},
        "peso": 2,
    },
    "miner": {
        "kw": [
            "miner", "mining", "cryptojack", "xmrig", "monero", "resource_hijack",
        ],
        "ttps": {"T1496"},
        "peso": 3,
    },
    "banker": {
        "kw": [
            "banker", "banking", "webinject", "formgrab", "browser_hook",
        ],
        "ttps": {"T1185"},
        "peso": 3,
    },
    "worm": {
        "kw": [
            "worm", "propagat", "lateral_move", "removable_media", "net_spread",
        ],
        "ttps": {"T1091", "T1210", "T1570"},
        "peso": 3,
    },
}


def pre_clasificar(
    firmas: list,
    ttps_lista: list,
    payloads: list,
) -> dict:
    scores = {k: 0 for k in CATEGORIAS_MALWARE}
    evidencias: dict[str, list[str]] = {k: [] for k in CATEGORIAS_MALWARE}

    for firma in firmas:
        nombre_l = firma.get("nombre", "").lower()
        # Solo se compara contra el NOMBRE de la firma (identificador programático),
        # nunca contra la descripción: términos como "backdoor" o "remote_access"
        # aparecen en descripciones genéricas de firmas de red y sesgan hacia RAT.
        sev = max(firma.get("severidad", 1), 1)
        for tipo, cfg in CATEGORIAS_MALWARE.items():
            for kw in cfg["kw"]:
                if kw in nombre_l:
                    puntos = sev * cfg["peso"]
                    scores[tipo] += puntos
                    evidencias[tipo].append(f"firma:'{firma['nombre']}'(sev={sev})")
                    break

    for ttp_str in ttps_lista:
        ttp_id = ttp_str.split(":")[0].strip()
        for tipo, cfg in CATEGORIAS_MALWARE.items():
            if ttp_id in cfg["ttps"] or ttp_id.split(".")[0] in cfg["ttps"]:
                scores[tipo] += cfg["peso"]
                evidencias[tipo].append(f"TTP:{ttp_id}")
                break

    for pl in payloads:
        tipo_p = pl.get("type", "").lower()
        if any(x in tipo_p for x in ["shellcode", "loader", "unpacked", "dropper"]):
            scores["loader_downloader"] += 4
            evidencias["loader_downloader"].append(f"payload:{pl.get('type')}")

 

    max_score = max(scores.values()) if any(scores.values()) else 0
    top_tipo = max(scores, key=scores.get) if max_score > 0 else "indeterminado"
    top3 = sorted(
        [(t, s) for t, s in scores.items() if s > 0],
        key=lambda x: x[1],
        reverse=True,
    )[:3]

    return {
        "clasificacion": top_tipo,
        "confianza": (
            "alta" if max_score >= 9 else "media" if max_score >= 4 else "baja"
        ),
        "top3": top3,
        "evidencias": {k: v for k, v in evidencias.items() if v},
    }


# ─────────────────────────────────────────────────────────────────────────────
# TABLA MITRE ATT&CK
# ─────────────────────────────────────────────────────────────────────────────

MITRE_NAMES: dict[str, str] = {
    "T1001": "Data Obfuscation", "T1003": "OS Credential Dumping",
    "T1005": "Data from Local System", "T1007": "System Service Discovery",
    "T1010": "Application Window Discovery", "T1012": "Query Registry",
    "T1016": "System Network Configuration Discovery",
    "T1018": "Remote System Discovery",
    "T1021": "Remote Services", "T1027": "Obfuscated Files or Information",
    "T1033": "System Owner/User Discovery", "T1036": "Masquerading",
    "T1040": "Network Sniffing",
    "T1047": "Windows Management Instrumentation",
    "T1049": "System Network Connections Discovery",
    "T1053": "Scheduled Task/Job", "T1055": "Process Injection",
    "T1056": "Input Capture", "T1057": "Process Discovery",
    "T1059": "Command and Scripting Interpreter",
    "T1068": "Exploitation for Privilege Escalation",
    "T1070": "Indicator Removal", "T1071": "Application Layer Protocol",
    "T1074": "Data Staged", "T1078": "Valid Accounts",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1087": "Account Discovery", "T1090": "Proxy",
    "T1091": "Replication Through Removable Media",
    "T1095": "Non-Application Layer Protocol",
    "T1105": "Ingress Tool Transfer", "T1106": "Native API",
    "T1112": "Modify Registry", "T1113": "Screen Capture",
    "T1115": "Clipboard Data", "T1119": "Automated Collection",
    "T1120": "Peripheral Device Discovery", "T1123": "Audio Capture",
    "T1124": "System Time Discovery", "T1125": "Video Capture",
    "T1132": "Data Encoding", "T1134": "Access Token Manipulation",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1185": "Browser Session Hijacking",
    "T1197": "BITS Jobs", "T1204": "User Execution",
    "T1216": "System Script Proxy Execution",
    "T1218": "System Binary Proxy Execution",
    "T1219": "Remote Access Software",
    "T1220": "XSL Script Processing",
    "T1480": "Execution Guardrails",
    "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact", "T1489": "Service Stop",
    "T1490": "Inhibit System Recovery", "T1491": "Defacement",
    "T1496": "Resource Hijacking",
    "T1497": "Virtualization/Sandbox Evasion",
    "T1518": "Software Discovery", "T1529": "System Shutdown/Reboot",
    "T1531": "Account Access Removal",
    "T1539": "Steal Web Session Cookie",
    "T1543": "Create or Modify System Process",
    "T1546": "Event Triggered Execution",
    "T1547": "Boot or Logon Autostart Execution",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1552": "Unsecured Credentials", "T1553": "Subvert Trust Controls",
    "T1555": "Credentials from Password Stores",
    "T1558": "Steal or Forge Kerberos Tickets",
    "T1559": "Inter-Process Communication",
    "T1560": "Archive Collected Data", "T1562": "Impair Defenses",
    "T1564": "Hide Artifacts", "T1566": "Phishing",
    "T1568": "Dynamic Resolution", "T1569": "System Services",
    "T1570": "Lateral Tool Transfer", "T1574": "Hijack Execution Flow",
    "T1592": "Gather Victim Host Information",
    "T1614": "System Location Discovery",
    "T1620": "Reflective Code Loading", "T1622": "Debugger Evasion",
    "T1027.002": "Obfuscation: Software Packing",
    "T1027.004": "Obfuscation: Compile After Delivery",
    "T1053.005": "Scheduled Task",
    "T1055.001": "DLL Injection",
    "T1055.002": "Portable Executable Injection",
    "T1055.004": "Asynchronous Procedure Call",
    "T1055.012": "Process Hollowing",
    "T1059.001": "PowerShell", "T1059.003": "Windows Command Shell",
    "T1059.005": "Visual Basic",
    "T1071.001": "Web Protocols", "T1071.004": "DNS",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1547.004": "Winlogon Helper DLL",
    "T1562.001": "Disable or Modify Tools",
    "T1562.004": "Disable or Modify System Firewall",
    "T1574.002": "DLL Side-Loading",
}

APIS_CRITICAS: dict[str, list[str]] = {
    "cifrado_ransomware": [
        "CryptEncrypt", "BCryptEncrypt", "CryptAcquireContext",
        "CryptGenKey", "CryptImportKey", "FindFirstFile", "FindNextFile",
    ],
    "robo_credenciales": [
        "LsaOpenSecret", "SamOpenDatabase", "CryptUnprotectData",
        "GetClipboardData", "NtlmCredentials", "LsaRetrievePrivateData",
    ],
    "inyeccion_proceso": [
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "QueueUserAPC", "RtlCreateUserThread",
        "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
    ],
    "red_c2": [
        "WinHttpOpen", "InternetOpenUrl", "WSAConnect",
        "URLDownloadToFile", "HttpSendRequest", "WinHttpSendRequest",
    ],
    "persistencia": [
        "RegSetValueEx", "CreateServiceA", "CreateServiceW",
        "SetWindowsHookEx", "RegisterStartupEntry",
    ],
    "evasion_sandbox": [
        "NtQueryInformationProcess", "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent", "NtSetInformationThread",
        "ZwQuerySystemInformation", "GetTickCount",
    ],
}

RUTAS_RUIDO = [
    "\\cape\\", "\\cuckoo\\", "\\agent.py", "tmpxxx",
    "analyzer.py", "\\tmp\\", "\\capemon",
]

EVASION_CATS = {
    "anti-analysis", "anti-sandbox", "anti-vm", "anti-debug",
    "anti-emulation", "evasion", "antiav", "anti-av",
}
EVASION_PREFIXES = (
    "antivm_", "antisandbox_", "antidbg_", "antidebug_",
    "vmdetect_", "checks_debugger", "antianalysis_",
)


# ─────────────────────────────────────────────────────────────────────────────
# EXTRACCIÓN Y FILTRADO DEL JSON DE CAPE
# ─────────────────────────────────────────────────────────────────────────────

def filtrar_reporte_cape(ruta_json: str) -> dict | None:
    if not os.path.exists(ruta_json):
        print(f"❌ Error: El archivo no existe en {ruta_json}")
        return None
    try:
        with open(ruta_json, "r", encoding="utf-8") as f:
            data = json.load(f)
    except PermissionError:
        print(
            f"❌ Permisos insuficientes para leer {ruta_json}. "
            "Intenta ejecutar con 'sudo'."
        )
        return None
    except Exception as e:
        print(f"❌ Error al abrir el JSON: {e}")
        return None

    categoria = data.get("target", {}).get("category", "file")
    es_url = categoria == "url"

    # ── 1. Metadatos básicos ──────────────────────────────────────────────
    if es_url:
        url_analizada = (
            data.get("url_analysis", {}).get("url")
            or data.get("info", {}).get("url", "Desconocida")
        )
        metadata = {
            "tipo_analisis": "URL",
            "url": url_analizada,
            "malscore": data.get("malscore", "N/A"),
            "malstatus": data.get("malstatus", "N/A"),
        }
    else:
        tf = data.get("target", {}).get("file", {})
        metadata = {
            "tipo_analisis": "Archivo",
            "nombre_archivo": tf.get("name", "Desconocido"),
            "tamano_bytes": tf.get("size", 0),
            "tipo_archivo": tf.get("type", "Desconocido"),
            "sha256": tf.get("sha256", "N/A"),
            "md5": tf.get("md5", "N/A"),
            "malscore": data.get("malscore", "N/A"),
            "malstatus": data.get("malstatus", "N/A"),
        }

    # ── 2. Familia detectada por CAPE (campo detections) ─────────────────
    detecciones_familia: dict = {}
    if data.get("detections"):
        detecciones_familia["cape_deteccion"] = data["detections"]
    if data.get("detections2"):
        detecciones_familia["cape_deteccion_2"] = data["detections2"]
    if data.get("info", {}).get("category"):
        detecciones_familia["categoria_analisis"] = data["info"]["category"]

    # ── 3. Firmas de comportamiento ───────────────────────────────────────
    firmas_todas: list[dict] = []
    firmas_malware: list[dict] = []
    for sig in data.get("signatures", []):
        nombre = sig.get("name", "")
        if not nombre or nombre.startswith("flare_capa_") or nombre.endswith("_libs"):
            continue
        cats = {c.lower() for c in sig.get("categories", [])}
        es_evasion = bool(cats & EVASION_CATS) or nombre.lower().startswith(EVASION_PREFIXES)
        entry = {
            "nombre": nombre,
            "descripcion": sig.get("description", ""),
            "severidad": sig.get("severity", 0),
            "categorias": sig.get("categories", []),
        }
        firmas_todas.append(entry)
        if not es_evasion:
            firmas_malware.append(entry)
    firmas_todas.sort(key=lambda x: x["severidad"], reverse=True)
    firmas_malware.sort(key=lambda x: x["severidad"], reverse=True)

    # ── 4. TTPs MITRE ATT&CK ──────────────────────────────────────────────
    sig_artefactos: dict[str, list[str]] = {}
    for sig in data.get("signatures", []):
        sig_name = sig.get("name", "")
        if not sig_name:
            continue
        arts: list[str] = []
        for item in (sig.get("data") or []) + (sig.get("new_data") or []):
            if isinstance(item, dict):
                for v in item.values():
                    if isinstance(v, str) and len(v) > 2:
                        arts.append(v)
            elif isinstance(item, str) and len(item) > 2:
                arts.append(item)
        if arts:
            sig_artefactos[sig_name] = list(dict.fromkeys(arts))[:3]

    ttps_detectados: list[str] = []
    seen_ids: set[str] = set()
    for t in data.get("ttps", []):
        sig_nombre = t.get("signature", "")
        arts = sig_artefactos.get(sig_nombre, [])
        ids = (
            t.get("ttps", []) if isinstance(t.get("ttps"), list) else [t.get("ttp", "")]
        )
        for ttp_id in ids:
            if ttp_id and ttp_id not in seen_ids:
                seen_ids.add(ttp_id)
                mitre_name = MITRE_NAMES.get(ttp_id, MITRE_NAMES.get(ttp_id.split(".")[0], ""))
                entry = f"{ttp_id}: {mitre_name}" if mitre_name else ttp_id
                if sig_nombre:
                    entry += f" [firma:{sig_nombre}]"
                if arts:
                    entry += f" [artefacto:{' | '.join(arts[:2])}]"
                ttps_detectados.append(entry)

    # ── 5. Procesos ───────────────────────────────────────────────────────
    procesos: list[dict] = []
    seen_proc_names: set[str] = set()
    for proc in data.get("behavior", {}).get("processes", []):
        if len(procesos) >= 5:
            break
        nombre_proc = proc.get("process_name", "")
        ruta_proc = proc.get("module_path", "")
        if any(r in ruta_proc.lower() for r in RUTAS_RUIDO):
            continue
        if nombre_proc in seen_proc_names:
            continue
        seen_proc_names.add(nombre_proc)
        procesos.append({
            "pid": proc.get("process_id"),
            "nombre": nombre_proc,
            "ruta": ruta_proc,
        })

    # ── 6. Comportamiento detallado (behavior.summary) ────────────────────
    summary = data.get("behavior", {}).get("summary", {})
    comportamiento: dict = {}

    archivos_escritos = [
        f for f in summary.get("write_files", [])
        if not any(r in f.lower() for r in RUTAS_RUIDO)
    ]
    if archivos_escritos:
        comportamiento["archivos_escritos"] = archivos_escritos[:10]

    archivos_eliminados = [
        f for f in summary.get("delete_files", [])
        if not any(r in f.lower() for r in RUTAS_RUIDO)
    ]
    if archivos_eliminados:
        comportamiento["archivos_eliminados"] = archivos_eliminados[:8]

    reg_escritas = summary.get(
        "write_keys", summary.get("keys_written", summary.get("registry_keys_written", []))
    )
    if reg_escritas:
        comportamiento["registro_escrito"] = reg_escritas[:10]

    mutexes = [m for m in summary.get("mutexes", []) if len(m) > 2]
    if mutexes:
        comportamiento["mutexes"] = mutexes[:10]

    comandos = summary.get("executed_commands", [])
    if comandos:
        comportamiento["comandos_ejecutados"] = comandos[:20]

    servicios = summary.get("created_services", [])
    if servicios:
        comportamiento["servicios_creados"] = servicios[:10]

    apis_todas = summary.get("resolved_apis", [])
    if apis_todas:
        apis_por_cat: dict[str, list[str]] = {}
        for cat, api_list in APIS_CRITICAS.items():
            encontradas = [
                a for a in apis_todas
                if any(k.lower() in a.lower() for k in api_list)
            ]
            if encontradas:
                apis_por_cat[cat] = encontradas[:8]
        if apis_por_cat:
            comportamiento["apis_criticas_por_categoria"] = apis_por_cat

    # ── 7. Archivos dropeados ─────────────────────────────────────────────
    archivos_dropeados: list[dict] = []
    for d in (data.get("dropped") or [])[:10]:
        ruta_d = d.get("path", "")
        if not any(r in ruta_d.lower() for r in RUTAS_RUIDO):
            # CAPE almacena name como lista en algunos informes
            nombre_raw = d.get("name", "") or ""
            if isinstance(nombre_raw, list):
                nombre_raw = nombre_raw[0] if nombre_raw else ""
            # El campo type puede ser una cadena muy larga (ej: descripciones MSI)
            tipo_raw = d.get("type", "") or ""
            tipo_corto = tipo_raw[:80] + "…" if len(tipo_raw) > 80 else tipo_raw
            archivos_dropeados.append({
                "nombre": nombre_raw,
                "tipo": tipo_corto,
                "sha256": d.get("sha256", ""),
                "ruta": ruta_d,
            })
    if archivos_dropeados:
        comportamiento["archivos_dropeados"] = archivos_dropeados

    # ── 8. Actividad de red ───────────────────────────────────────────────
    red: dict = {}

    net_top = data.get("network", {})
    if isinstance(net_top, dict):
        dns_top = net_top.get("dns", [])
        if dns_top:
            red["dns"] = [
                {"dominio": d.get("request", ""), "tipo": d.get("type", "")}
                for d in dns_top[:20]
            ]

        http_top = net_top.get("http", [])
        if http_top:
            red["http"] = [
                {
                    "url": f"http://{r.get('host', '')}{r.get('path', '')}",
                    "metodo": r.get("method", ""),
                    "status": r.get("status", ""),
                }
                for r in http_top[:20]
            ]

        hosts_top = net_top.get("hosts", [])
        if hosts_top:
            ips_vistas: set[str] = set()
            hosts_unicos = []
            for h in hosts_top:
                ip = h.get("ip", "")
                if ip and ip not in ips_vistas:
                    ips_vistas.add(ip)
                    hosts_unicos.append({"ip": ip, "puertos": h.get("ports", [])})
                    if len(hosts_unicos) >= 10:
                        break
            red["hosts"] = hosts_unicos

        conexiones: list[dict] = []
        seen_conns: set[str] = set()

        for c in net_top.get("tcp", []):
            ip = c.get("dst", "")
            key = f"tcp:{ip}:{c.get('dport', '')}"
            if key not in seen_conns:
                seen_conns.add(key)
                conexiones.append({"ip": ip, "puerto": c.get("dport", ""), "proto": "tcp"})
            if len(conexiones) >= 10:
                break

        for c in net_top.get("udp", []):
            ip = c.get("dst", "")
            key = f"udp:{ip}:{c.get('dport', '')}"
            if key not in seen_conns:
                seen_conns.add(key)
                conexiones.append({"ip": ip, "puerto": c.get("dport", ""), "proto": "udp"})
            if len(conexiones) >= 20:
                break

        if conexiones:
            red["tcp_udp"] = conexiones

        smtp_top = net_top.get("smtp", [])
        if smtp_top:
            red["smtp"] = [
                {
                    "dst": s.get("dst", ""),
                    "de": s.get("mail_from", s.get("from", "")),
                    "para": s.get("mail_to", s.get("to", "")),
                }
                for s in smtp_top[:10]
            ]

    # Fallback: behavior.network_map (algunas versiones de CAPE)
    if not red:
        network_map = data.get("behavior", {}).get("network_map", {})
        dns_nm = network_map.get("dns_intents", [])
        if dns_nm:
            red["dns"] = [
                {"dominio": d.get("hostname") or d.get("request", ""), "tipo": d.get("type", "")}
                for d in dns_nm[:20]
            ]
        http_nm = network_map.get("http_requests", [])
        if http_nm:
            red["http"] = [
                {"url": r.get("url", ""), "metodo": r.get("method", ""), "status": r.get("status", "")}
                for r in http_nm[:20]
            ]
        endpoints = network_map.get("endpoint_map", [])
        if endpoints:
            red["tcp_udp"] = [
                {"ip": e.get("ip", ""), "puerto": e.get("port", ""), "proto": e.get("protocol", "")}
                for e in endpoints[:20]
            ]
        winsessions = network_map.get("winhttp_sessions", [])
        if winsessions:
            red["winhttp_sessions"] = [
                {"servidor": s.get("server_name", ""), "user_agent": s.get("user_agent", "")}
                for s in winsessions[:10]
            ]

    if es_url:
        cmds = data.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        urls_cmds = [c for c in cmds if "http" in c.lower()][:10]
        if urls_cmds:
            red["urls_en_comandos"] = urls_cmds

    # ── 9. Payloads CAPE ─────────────────────────────────────────────────
    payloads: list[dict] = []
    for p in data.get("CAPE", {}).get("payloads", [])[:5]:
        entry: dict = {
            "sha256": p.get("sha256", ""),
            "md5": p.get("md5", ""),
            "type": p.get("cape_type", p.get("type_string", p.get("type", ""))),
            "size": p.get("size", 0),
        }
        if p.get("process_name"):
            entry["process_name"] = p["process_name"]
        if p.get("target_process"):
            entry["target_process"] = p["target_process"]
        if p.get("pid"):
            entry["pid"] = p["pid"]
        payloads.append(entry)

    # ── Pre-clasificación heurística (señal auxiliar) ─────────────────────
    # Se usa firmas_malware (sin evasión) para no contaminar el score con firmas anti-análisis
    clasificacion = pre_clasificar(firmas_malware[:25], ttps_detectados[:20], payloads)

    # ── Resultado final ───────────────────────────────────────────────────
    resultado: dict = {
        "metadata": metadata,
        "clasificacion_heuristica": clasificacion,
        "alertas_comportamiento": firmas_malware[:5],
        "ttps_mitre": ttps_detectados[:20],
        "procesos_en_ejecucion": procesos,
        "comportamiento_detallado": comportamiento,
        "actividad_red": red if red else {"info": "Sin actividad de red registrada"},
    }
    if payloads:
        resultado["payloads_cape"] = payloads
    if detecciones_familia:
        resultado["detecciones_familia"] = detecciones_familia

    return resultado


# ─────────────────────────────────────────────────────────────────────────────
# CONSTRUCCIÓN DEL RESUMEN COMPACTO
# ─────────────────────────────────────────────────────────────────────────────

def construir_resumen_compacto(datos: dict) -> str:
    meta = datos.get("metadata", {})
    clasi = datos.get("clasificacion_heuristica", {})
    comp = datos.get("comportamiento_detallado", {})
    red = datos.get("actividad_red", {})
    lines = []

    if meta.get("tipo_analisis") == "URL":
        lines.append(f"URL: {meta.get('url')} | MALSCORE: {meta.get('malscore')} | STATUS: {meta.get('malstatus')}")
    else:
        lines.append(f"ARCHIVO: {meta.get('nombre_archivo')} | SHA256: {meta.get('sha256')} | MD5: {meta.get('md5')} | MALSCORE: {meta.get('malscore')} | STATUS: {meta.get('malstatus')}")
    # Fuentes autoritativas primero — solo se muestran si tienen familia real
    det_fam = datos.get("detecciones_familia", {})
    cape_det = det_fam.get("cape_deteccion") or det_fam.get("cape_deteccion_2")
    if cape_det:
        lines.append(f"DETECCION_CAPE: {cape_det}")

    # Red aquí — antes de los bloques largos — para que nunca quede truncada por el contexto
    if red.get("dns"):
        lines.append(f"\nDNS: {', '.join(d.get('dominio', '') for d in red['dns'][:12])}")
    if red.get("http"):
        lines.append(f"HTTP: {' | '.join(r.get('url', '') for r in red['http'][:8])}")
    if red.get("hosts"):
        lines.append("HOSTS: " + ", ".join(
            f"{h.get('ip')}" + (f"(puertos:{h.get('puertos',[])})" if h.get("puertos") else "")
            for h in red['hosts'][:12]
        ))
    tcp_conns = [c for c in red.get("tcp_udp", []) if c.get("proto") == "tcp"]
    udp_conns = [c for c in red.get("tcp_udp", []) if c.get("proto") == "udp"]
    if tcp_conns:
        lines.append("TCP: " + ", ".join(
            f"{c.get('ip')}:{c.get('puerto')}" for c in tcp_conns[:10]
        ))
    if udp_conns:
        lines.append("UDP: " + ", ".join(
            f"{c.get('ip')}:{c.get('puerto')}" for c in udp_conns[:10]
        ))
    if red.get("http_hosts"):
        lines.append(f"HTTP_HOSTS: {', '.join(red['http_hosts'][:8])}")
    if red.get("winhttp_sessions"):
        lines.append("WINHTTP: " + ", ".join(
            s.get("servidor", "") for s in red["winhttp_sessions"][:5]
        ))
    if red.get("smtp"):
        lines.append("SMTP: " + " | ".join(
            f"dst={s.get('dst','')} de={s.get('de','')} para={s.get('para','')}"
            for s in red["smtp"][:5]
        ))

    lines.append("\nACCIONES_MALICIOSAS (top 5, sin evasión de sandbox):")
    for s in datos.get("alertas_comportamiento", []):
        lines.append(f"  [sev={s['severidad']}] {s['nombre']}: {s.get('descripcion','')[:150]}")

    lines.append("\nTTPs_MITRE_ATTACK:")
    for ttp in datos.get("ttps_mitre", []):
        lines.append(f"  {ttp}")

    lines.append("\nPROCESOS (top 5):")
    for p in datos.get("procesos_en_ejecucion", []):
        lines.append(f"  PID={p.get('pid')} {p.get('nombre')} {p.get('ruta','')}")

    if comp.get("archivos_escritos"):
        lines.append(f"\nARCHIVOS_ESCRITOS: {' | '.join(comp['archivos_escritos'][:8])}")
    if comp.get("archivos_eliminados"):
        lines.append(f"ARCHIVOS_ELIMINADOS: {' | '.join(comp['archivos_eliminados'][:5])}")
    if comp.get("registro_escrito"):
        lines.append(f"REGISTRO_ESCRITO: {' | '.join(comp['registro_escrito'][:8])}")
    if comp.get("mutexes"):
        lines.append(f"MUTEXES: {', '.join(comp['mutexes'][:5])}")
    if comp.get("comandos_ejecutados"):
        # Truncar comandos muy largos (Base64 PowerShell, etc.) para no saturar el contexto
        cmds = []
        for cmd in comp["comandos_ejecutados"][:6]:
            cmds.append(cmd[:300] + "…[truncado]" if len(cmd) > 300 else cmd)
        lines.append(f"COMANDOS: {' | '.join(cmds)}")
    if comp.get("apis_criticas_por_categoria"):
        for cat, apis in comp["apis_criticas_por_categoria"].items():
            lines.append(f"APIs_{cat.upper()}: {', '.join(apis[:5])}")
    if comp.get("archivos_dropeados"):
        lines.append("ARCHIVOS_DROPEADOS: " + " | ".join(
            f"{d.get('nombre','')}({d.get('tipo','')})" for d in comp["archivos_dropeados"][:5]
        ))

    for pl in datos.get("payloads_cape", []):
        parts = [f"PAYLOAD: {pl.get('type', 'desconocido')}"]
        if pl.get("sha256"):
            parts.append(f"SHA256: {pl['sha256'][:32]}...")
        if pl.get("md5"):
            parts.append(f"MD5: {pl['md5']}")
        if pl.get("process_name"):
            parts.append(f"proceso: {pl['process_name']}")
        if pl.get("target_process"):
            parts.append(f"inyectado_en: {pl['target_process']}")
        if pl.get("pid"):
            parts.append(f"PID: {pl['pid']}")
        if pl.get("size"):
            parts.append(f"size: {pl['size']}B")
        lines.append("\n" + " | ".join(parts))

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# GENERACIÓN DEL INFORME CON IA
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_MSG = (
    "Eres un Analista de Malware Senior con más de 10 años de experiencia en DFIR, "
    "reverse engineering y análisis de sandboxes (CAPE/Cuckoo). "
    "Tus informes son técnicamente precisos, concisos y siempre basados en evidencia concreta. "
    "NUNCA inventas información. Si un campo del JSON está vacío, lo indicas explícitamente. "
    "Siempre citas el nombre exacto del campo del JSON que soporta cada afirmación. "
    "IDIOMA OBLIGATORIO: redacta el informe íntegramente en español. "
    "Mantén en inglés únicamente: nombres de técnicas MITRE, APIs de Windows, "
    "nombres de familias de malware y términos técnicos sin traducción estándar en ciberseguridad."
)


def construir_prompt(datos: dict) -> str:
    clasi = datos.get("clasificacion_heuristica", {})
    top3 = clasi.get("top3", [])
    top3_str = ", ".join(f"{t}(score={s})" for t, s in top3) if top3 else "sin señal"
    evid = clasi.get("evidencias", {})
    evidencias_str = "\n".join(
        f"    [{tipo}]: {'; '.join(evs[:3])}" for tipo, evs in evid.items()
    ) or "    (sin evidencias heurísticas)"

    resumen = construir_resumen_compacto(datos)

    # Bloque heurístico: se suprime SOLO cuando hay familia real detectada
    # (categoria_analisis: "file"/"url" no cuenta — no es una familia de malware)
    det_fam = datos.get("detecciones_familia", {})
    tiene_cape = bool(det_fam.get("cape_deteccion") or det_fam.get("cape_deteccion_2"))
    if tiene_cape:
        bloque_heuristica = (
            f"SEÑAL HEURÍSTICA PYTHON (IGNORAR COMPLETAMENTE): {clasi.get('clasificacion', 'indeterminado').upper()}\n"
            f"  ⛔ Los datos contienen DETECCION_CAPE.\n"
            f"     Clasifica EXCLUSIVAMENTE a partir de esas fuentes autoritativas.\n"
            f"     La clasificación heurística Python es irrelevante y NO debe aparecer en el informe."
        )
    else:
        bloque_heuristica = (
            f"SEÑAL HEURÍSTICA AUXILIAR (única fuente disponible — úsala con precaución):\n"
            f"  Candidato: {clasi.get('clasificacion', 'indeterminado').upper()} | "
            f"Confianza: {clasi.get('confianza', 'baja')} | Ranking: {top3_str}\n"
            f"  Evidencias que la generaron:\n"
            f"{evidencias_str}\n"
            f"  ⚠ Esta señal puede ser INCORRECTA. Confirma siempre con las firmas y TTPs."
        )

    return f"""Analiza los datos del sandbox CAPE que aparecen a continuación y genera un informe forense completo en español.

IDIOMA: Redacta el informe íntegramente en español. Mantén en inglés solo nombres de técnicas MITRE, APIs de Windows y nombres de familias de malware.

══════════════════════════ DATOS DEL ANÁLISIS ══════════════════════════
{resumen}
════════════════════════════════════════════════════════════════════════

{bloque_heuristica}

═══════════════════════════ REGLAS OBLIGATORIAS ════════════════════════

REGLA CRÍTICA — VALORES REALES:
  Los valores reales están en el bloque DATOS DEL ANÁLISIS arriba.
  Cópialos LITERALMENTE tal como aparecen.
  NUNCA escribas placeholders como [hash], [ruta específica], [dominio] ni nada entre corchetes.
  Si un dato no existe en el bloque, escribe "No registrado en este análisis".
Escribe las explicaciones en español
R1 — CLASIFICA A PARTIR DE LOS DATOS, NUNCA DE LA CLASIFICACIÓN HEURÍSTICA PYTHON:
  Orden de prioridad inamovible:
    1. DETECCION_CAPE → autoridad máxima: si tiene valor, esa ES la familia. Punto.
    2. Firmas de sev≥2 + TTPs MITRE → determinan el TIPO genérico cuando 1 y 2 están vacíos.
    3. Señal heurística Python → SOLO si las tres fuentes anteriores están completamente vacías.
  No existe ninguna circunstancia en que la heurística Python prevalezca sobre DETECCION_CAPE.

R2 — SOLO VALORES QUE APARECEN EN LOS DATOS:
  Incorrecto: "El malware cifra archivos en [ruta]"
  Correcto: "La firma 'ransomware_file_modifications' (sev=3) + TTP T1486 confirman cifrado; archivos afectados: C:\\Users\\victim\\doc.encrypted"

R3 — EVIDENCIA CONCRETA PARA CADA AFIRMACIÓN:
  Incorrecto: "El malware podría exfiltrar credenciales"
  Correcto: "La firma 'infostealer_browser_creds' (sev=3) + API CryptUnprotectData + dominio track.evil.com en DNS confirman exfiltración"

R4 — ANALIZA EL COMPORTAMIENTO ESPECÍFICO DE ESTA MUESTRA:
  Examina ARCHIVOS_ESCRITOS, ARCHIVOS_ELIMINADOS, REGISTRO_ESCRITO, COMANDOS, APIs_*, MUTEXES, ARCHIVOS_DROPEADOS.
  Cada observación debe conectarse directamente con el tipo de malware que concluyas.
  No uses frases genéricas aplicables a cualquier muestra.

════════════════════════════════════════════════════════════════════════

ESTRUCTURA DEL INFORME — Desarrolla TODAS las secciones en orden:

## 1. RESUMEN EJECUTIVO
- Nombre del archivo/URL: copia el valor exacto de la línea "ARCHIVO:" o "URL:" del bloque de datos
- SHA256: copia el hash exacto (o "N/A" para análisis de URL)
- MD5: copia el valor exacto (o "N/A" para análisis de URL)
- Malscore: copia el valor exacto de "MALSCORE:"
- Clasificación: resultado del VEREDICTO de la sección 0
- Objetivo operativo e impacto potencial: una frase basada exclusivamente en los datos

## 2. ANÁLISIS DE COMPORTAMIENTO
El bloque ACCIONES_MALICIOSAS contiene las 5 firmas más severas ya filtradas (sin técnicas de evasión de sandbox).
Para cada firma escribe exactamente:
▶ [nombre exacto de la firma] (sev=[X]) → [acción concreta que realiza] → [relación directa con el tipo de malware clasificado en sección 0]
NUNCA incluyas aquí técnicas de anti-análisis, anti-vm ni evasión de sandbox.

## 3. ARTEFACTOS DEL SISTEMA
a) Archivos escritos: copia las rutas exactas de ARCHIVOS_ESCRITOS. Indica si apuntan a AppData, System32, Startup o rutas temporales. Si no hay datos, escribe "No registrado en este análisis".
b) Archivos eliminados: copia las rutas exactas de ARCHIVOS_ELIMINADOS. Indica qué huellas cubren. Si no hay datos, escribe "No registrado en este análisis".
c) Registro: copia las claves exactas de REGISTRO_ESCRITO. Indica si son Run Keys u otro mecanismo de persistencia. Si no hay datos, escribe "No registrado en este análisis".
d) Comandos: copia los comandos de COMANDOS (los muy largos aparecen truncados con "[truncado]"). Explica qué hace cada uno; si hay Base64 o URLs visibles en el fragmento, indícalas explícitamente. Si no hay datos, escribe "No registrado en este análisis".

## 4. PROCESOS EN EJECUCIÓN
El bloque PROCESOS contiene los 5 procesos más relevantes (sin duplicados ni ruido de CAPE).
Para cada proceso escribe exactamente:
▶ PID=[valor exacto] | Nombre=[nombre exacto] | Ruta=[ruta exacta]
  Rol: ¿malware principal, proceso legítimo abusado (LOLBin) o proceso inyectado? Justifica con los datos.

## 5. ACTIVIDAD DE RED
OBLIGATORIO: esta sección SIEMPRE debe generarse. Busca en el bloque de datos las líneas que empiecen por DNS:, HTTP:, HOSTS:, TCP:, UDP:, SMTP:, WINHTTP: o HTTP_HOSTS:.
Si ninguna de esas líneas existe en los datos, escribe "Sin actividad de red registrada en este análisis."
Si alguna existe, copia su contenido y analiza cada una. NO omitas esta sección.

DNS: copia cada dominio exacto de la línea "DNS:" — indica si es C2, descarga, exfiltración o legítimo.
HOSTS: copia cada IP exacta con sus puertos de la línea "HOSTS:" — indica si es C2, canal de datos o legítimo.
TCP: copia cada IP:puerto exacto de la línea "TCP:" — indica si es beacon C2, exfiltración o legítimo.
UDP: copia cada IP:puerto exacto de la línea "UDP:" — esta línea es independiente de TCP; indica si es C2, exfiltración DNS-over-UDP u otro propósito. Si la línea "UDP:" existe en los datos, DEBE aparecer en el informe.

## 6. TTPs MITRE ATT&CK
Lista cada entrada del bloque TTPs_MITRE_ATTACK como una viñeta independiente, en el mismo orden
en que aparecen en los datos. SIN tablas, SIN columnas, SIN agrupar por táctica.
Para cada TTP escribe EXACTAMENTE en este formato:

▶ [ID exacto]: [nombre de la técnica]
  Firma: [valor exacto del campo "firma:" de esa entrada, o "No especificada"]
  Evidencia: [valor exacto del campo "artefacto:" de esa entrada, o "No registrada"]
  Qué permite al atacante: [una frase concreta basada en los datos de esta muestra]

## 7. PAYLOADS CAPE
Si existe el campo PAYLOAD en los datos, escribe para cada uno:
▶ Tipo: [valor exacto] | SHA256: [valor exacto] | MD5: [valor exacto]
  Proceso origen: [proceso exacto] | Inyectado en: [proceso exacto o "N/A"] | PID: [valor exacto]
  Relevancia forense: qué indica este payload sobre el comportamiento del malware
Si no hay payloads: "No se extrajeron payloads en este análisis."

## 8. RECOMENDACIONES DE RESPUESTA AL INCIDENTE
Basadas ÚNICAMENTE en los IOCs de la sección 8. Mínimo 3 acciones concretas por apartado:
a) CONTENCIÓN INMEDIATA:
   - Terminar proceso PID=[valor exacto] ([nombre exacto]) porque [razón técnica basada en los datos]
   - Aislar el equipo de la red si se detectó actividad hacia [IP o dominio concreto de los datos]
   - [otras acciones de contención basadas en los datos]
b) ERRADICACIÓN:
   - Eliminar archivo [ruta exacta de ARCHIVOS_ESCRITOS o ARCHIVOS_DROPEADOS] porque [qué función cumple]
   - Eliminar clave de registro [clave exacta de REGISTRO_ESCRITO] porque [qué persiste]
   - [otras acciones de erradicación — una por cada artefacto relevante]
c) BLOQUEO DE RED:
Si existen datos de red:
   - Bloquear IP [valor exacto] puerto [puerto exacto] en firewall perimetral
   - Bloquear resolución DNS de [dominio exacto] en el DNS corporativo
   - [otras reglas de bloqueo basadas en los datos de actividad_red]
   i no existen datos de red, eliminar este campo
d) HARDENING ESPECÍFICO (una medida por cada táctica MITRE detectada):
   - Para [TTP exacto]: [medida de hardening concreta que lo mitiga]
"""


def generar_reporte_ia(datos: dict) -> str:
    tipo_analisis = datos.get("metadata", {}).get("tipo_analisis", "Archivo")
    print(f"🤖 Enviando a Ollama (llama3) — análisis de {tipo_analisis}...")

    prompt = construir_prompt(datos)

    try:
        partes: list[str] = []
        for chunk in ollama.chat(
            model="llama3",
            messages=[
                {"role": "system", "content": SYSTEM_MSG},
                {"role": "user", "content": prompt},
            ],
            options={
                "temperature": 0.0,
                "num_predict": 4000,
                "num_ctx": 8192,
            },
            stream=True,
        ):
            token = chunk["message"]["content"]
            print(token, end="", flush=True)
            partes.append(token)
        print()  # salto de línea al finalizar
        return "".join(partes)
    except Exception as e:
        return f"❌ Error en la comunicación con Ollama: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analizador de reportes CAPE — versión final fusionada"
    )
    parser.add_argument(
        "reporte",
        help="ID numérico del análisis CAPE (ej: 14) o ruta completa al report.json",
    )
    parser.add_argument(
        "-o", "--output",
        default="reporte_ia.txt",
        help="Archivo de salida (por defecto: reporte_ia.txt)",
    )
    parser.add_argument(
        "--debug-json",
        action="store_true",
        help="Guarda también el JSON filtrado enviado al LLM (útil para depuración)",
    )
    args = parser.parse_args()

    ruta = resolver_ruta(args.reporte)
    print(f"🔍 Ruta del reporte: {ruta}")
    print("🔍 Extrayendo y filtrando datos de CAPE...")

    datos = filtrar_reporte_cape(ruta)
    if not datos:
        sys.exit(1)

    # Mostrar fuentes autoritativas primero
    det_fam = datos.get("detecciones_familia", {})
    cape_det = det_fam.get("cape_deteccion") or det_fam.get("cape_deteccion_2")
    if cape_det:
        print(f"\n✅ DETECCIÓN CAPE (familia confirmada): {cape_det}")

    clasi = datos.get("clasificacion_heuristica", {})
    tiene_autoridad = bool(cape_det)
    if not tiene_autoridad:
        print(f"\n📊 Clasificación heurística (sin detección autoritativa): "
              f"{clasi.get('clasificacion', 'N/A').upper()} "
              f"(confianza: {clasi.get('confianza', 'N/A')})")
        if clasi.get("top3"):
            print(f"   Top-3: {', '.join(f'{t}(score={s})' for t, s in clasi['top3'])}")
        if clasi.get("evidencias"):
            print("   Evidencias encontradas:")
            for tipo, evs in clasi["evidencias"].items():
                print(f"     [{tipo}] {'; '.join(evs[:3])}")
    else:
        print(f"   (Heurística Python ignorada: {clasi.get('clasificacion','?').upper()} — "
              f"prevalece la detección autoritativa)")

    if args.debug_json:
        debug_path = args.output.replace(".txt", "_debug.json")
        with open(debug_path, "w", encoding="utf-8") as f:
            json.dump(datos, f, indent=2, ensure_ascii=False)
        print(f"\n🔧 JSON filtrado guardado en '{debug_path}' para inspección")

    print("\n✅ Datos extraídos. Generando informe con IA...")
    print("\n" + "=" * 25 + " REPORTE DE IA " + "=" * 25)
    reporte = generar_reporte_ia(datos)
    print("=" * 65)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(reporte)
    print(f"\n💾 Reporte guardado en '{args.output}'")


if __name__ == "__main__":
    main()
