"""
Backend Flask para el Sistema Heurístico de Análisis de Phishing.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import tldextract
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import imaplib
import email as email_lib
import re
import requests
from email.header import decode_header
from email.utils import parseaddr

app = Flask(__name__)
CORS(app)

SERVIDORES_IMAP = {
    "gmail.com":        "imap.gmail.com",
    "outlook.com":      "outlook.office365.com",
    "hotmail.com":      "outlook.office365.com",
    "hotmail.es":       "outlook.office365.com",
    "live.com":         "outlook.office365.com",
    "msn.com":          "outlook.office365.com",
    "yahoo.com":        "imap.mail.yahoo.com",
    "yahoo.es":         "imap.mail.yahoo.com",
    "ymail.com":        "imap.mail.yahoo.com",
}
 
def obtener_servidor_imap(usuario: str):
    """Devuelve el servidor IMAP correspondiente al dominio del correo.
    Lanza ValueError si el proveedor no está soportado."""
    dominio = usuario.split("@")[-1].lower().strip() if "@" in usuario else ""
    servidor = SERVIDORES_IMAP.get(dominio)
    if not servidor:
        soportados = ", ".join(sorted(set(SERVIDORES_IMAP.values())))
        raise ValueError(
            f"Proveedor '@{dominio}' no soportado. "
            f"Proveedores válidos: Gmail, Outlook/Hotmail/Live, Yahoo."
        )
    return servidor

# ────────────────────────────────────────────────
# Configuración del modelo - edita esta ruta
# ────────────────────────────────────────────────
RUTA_MODELO = ""

try:
    from simpletransformers.classification import ClassificationModel
    modelo_ia = ClassificationModel("distilbert", RUTA_MODELO, use_cuda=False)
    MODELO_DISPONIBLE = True
    print(f"✅ Modelo IA cargado desde: {RUTA_MODELO}")
except Exception as e:
    modelo_ia = None
    MODELO_DISPONIBLE = False
    print(f"⚠️  Modelo IA no disponible: {e}")

try:
    from deep_translator import GoogleTranslator
    TRADUCTOR_DISPONIBLE = True
    print("✅ Traductor cargado (deep-translator)")
except ImportError:
    TRADUCTOR_DISPONIBLE = False
    print("⚠️  deep-translator no instalado. Instálalo con: pip install deep-translator")


def traducir_al_ingles(texto: str) -> str:
    if not TRADUCTOR_DISPONIBLE or not texto.strip():
        return texto
    try:
        MAX_CHARS = 4500
        if len(texto) <= MAX_CHARS:
            return GoogleTranslator(source="auto", target="en").translate(texto)
        bloques = [texto[i:i+MAX_CHARS] for i in range(0, len(texto), MAX_CHARS)]
        return " ".join(
            GoogleTranslator(source="auto", target="en").translate(b) for b in bloques
        )
    except Exception as e:
        print(f"⚠️  Error al traducir: {e}. Se usará el texto original.")
        return texto


# ────────────────────────────────────────────────
# Funciones auxiliares (extraídas de sistemaHeuristica.py)
# ────────────────────────────────────────────────

def decodificar_texto(texto):
    if not texto:
        return ""
    partes = decode_header(texto)
    texto_limpio = ""
    for string, charset in partes:
        if isinstance(string, bytes):
            try:
                texto_limpio += string.decode(charset or "utf-8", errors="ignore")
            except Exception:
                texto_limpio += string.decode("utf-8", errors="ignore")
        else:
            texto_limpio += string
    return texto_limpio


def extraer_ip_remitente(headers):
    if not headers:
        return None
    ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    for header in reversed(headers):
        ips = re.findall(ip_pattern, header)
        for ip in ips:
            if ip.startswith("0"):
                continue
            if not ip.startswith(("10.", "192.168.", "127.", "172.16.")):
                return ip
    return None


def obtener_info_geografica(msg):
    received = msg.get_all("Received")
    ip = extraer_ip_remitente(received)
    if ip:
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
            return r.get("country", "N/A"), ip
        except Exception:
            pass
    return "Desconocido", "Desconocido"


def verificar_autenticacion(msg):
    auth_header = msg.get("Authentication-Results", "")
    if not auth_header:
        return "Desconocido", "Desconocido"
    spf = re.search(r"spf=(\w+)", auth_header)
    dkim = re.search(r"dkim=(\w+)", auth_header)
    return (spf.group(1) if spf else "None"), (dkim.group(1) if dkim else "None")


def extraer_nombre_aplicacion(texto):
    patron_es = r"cuenta\s+(?:de|en|de su|en su)\s+([a-zA-Z0-9]+)"
    patron_en = r"\b([a-zA-Z0-9]+)\s+account\b"
    match = re.findall(patron_es, texto, re.IGNORECASE)
    resultados = re.findall(patron_en, texto, re.IGNORECASE)
    todas = list(set(match)) + list(set(resultados))
    basura = ["your", "this", "my", "an", "the", "user", "de", "su", "email"]
    return list(set([e for e in todas if e.lower() not in basura]))


def motor_reglas(asunto, cuerpo_min, nombre_rem, remitente, empresas_esperadas):
    puntos = 0
    alertas = []

    flag_http = flag_evasion_barras = flag_acortador = False
    flag_numeros_dominio = flag_subdominios_excesivos = False
    flag_ip_numerica = flag_servicio_gratuito = False
    flag_discrepancia_empresa = flag_discrepancia_remitente = False
    tiene_enlace_oficial = False

    asunto = str(asunto) if asunto else ""
    remitente = str(remitente) if remitente else ""

    info_rem = tldextract.extract(remitente)
    urls = re.findall(r"(https?://[^\s<>\"]+)", cuerpo_min)

    terminos_urgencia = r"\b(urgente|inmediato|suspender|bloqueo|24 horas|límite|ahora|urgent|immediate|deadline|expire|hoy|mañana|today|tomorrow|24 hour)\b"
    verbos_accion = r"\b(clic aquí|click aqui|clic here|click here|verificar|verify|actualizar|update|entrar|login|acceder|remove|eliminar|secure|account|signin)\b"
    terminos_dinero_negativo = r"\b(pago|factura|deuda|multa|cobrar|embargo|bill|invoice|fine|penalty|payment)\b"
    terminos_dinero_positivo = r"\b(premio|regalo|ganador|herencia|reembolso|oferta|offer|sorteo|gift|winner|refund|lottery|prize)\b"

    if len(asunto) > 6 and asunto.isupper():
        puntos += 20
        alertas.append("Asunto escrito completamente en mayúsculas.")

    if re.search(r"[^\x00-\x7F]", nombre_rem):
        puntos += 70
        alertas.append("El remitente contiene caracteres extraños o alfabetos no latinos.")

    if re.search(r"(estimado|querido|dear)\s+(cliente|usuario|user|customer)", cuerpo_min):
        puntos += 25
        alertas.append("Uso de saludo genérico en lugar de tu nombre real.")

    if re.search(verbos_accion, cuerpo_min):
        puntos += 20
        alertas.append("El correo te incita a realizar una acción inmediata.")

    tlds_peligrosos = ["tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "bid", "casa", "monster"]
    if info_rem.suffix.lower() in tlds_peligrosos:
        puntos += 40
        alertas.append("El remitente usa un correo de terminación no fiable.")

    emisorOficial = False
    if empresas_esperadas:
        if not any(emp.lower() == info_rem.domain.lower() for emp in empresas_esperadas):
            puntos += 30
            alertas.append(f"Discrepancia: El correo habla de {empresas_esperadas} pero se envía desde '@{info_rem.domain}.{info_rem.suffix}'.")
        else:
            emisorOficial = True
            puntos -= 100

    tiene_urgencia = bool(re.search(terminos_urgencia, cuerpo_min))
    dinero_negativo = bool(re.search(terminos_dinero_negativo, cuerpo_min))
    dinero_positivo = bool(re.search(terminos_dinero_positivo, cuerpo_min))

    if tiene_urgencia and dinero_negativo and not emisorOficial:
        puntos += 60
        alertas.append("Táctica de miedo: urgencia combinada con amenazas económicas desde fuente no oficial.")

    if tiene_urgencia and dinero_positivo and not emisorOficial:
        puntos += 60
        alertas.append("Táctica de gancho: promesa de premio urgente desde fuente no oficial.")

    for url in urls:
        ext_url = tldextract.extract(url)
        dominio_url = ext_url.domain.lower()
        subdominios = ext_url.subdomain
        url_parseada = urlparse(url)

        if url.startswith("http://"):
            flag_http = True
        if re.search(r"https?:///{1,}", url):
            flag_evasion_barras = True
        if any(ac in url for ac in ["bit.ly", "t.co", "goo.gl", "tinyurl"]):
            flag_acortador = True
        if len(re.findall(r"[0-9]", dominio_url)) > 1:
            flag_numeros_dominio = True
        if subdominios.count(".") > 2 or subdominios.count("-") > 2 or "@" in url:
            flag_subdominios_excesivos = True

        servicios_abusados = ["docs.google.com/forms", "linktr.ee", "typeform.com", "canva.com", "firebaseapp.com"]
        if any(s in url for s in servicios_abusados) and empresas_esperadas:
            flag_servicio_gratuito = True

        if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
            flag_ip_numerica = True

        if empresas_esperadas:
            if not any(emp.lower() == dominio_url for emp in empresas_esperadas):
                flag_discrepancia_empresa = True

        if dominio_url != info_rem.domain:
            flag_discrepancia_remitente = True

        TLDs_veraces = ["edu", "gov", "gob", "mil", "int", "bank", "ac"]
        if any(t in ext_url.suffix.lower() for t in TLDs_veraces):
            tiene_enlace_oficial = True

    if flag_evasion_barras:
        puntos += 60
        alertas.append("Intento de evasión de seguridad detectado en alguna URL.")
    if flag_acortador:
        puntos += 35
        alertas.append("Uso de acortador de enlaces para ocultar el destino final.")
    if flag_numeros_dominio:
        puntos += 30
        alertas.append("Algún dominio contiene números anómalos.")
    if flag_subdominios_excesivos:
        puntos += 30
        alertas.append("Alguna URL contiene un patrón sospechoso (muchos subdominios o símbolos).")
    if flag_ip_numerica:
        puntos += 60
        alertas.append("Algún enlace apunta directamente a una dirección IP numérica.")
    if flag_servicio_gratuito:
        puntos += 60
        alertas.append("Uso de un servicio gratuito simulando ser una comunicación oficial.")
    if flag_discrepancia_empresa:
        puntos += 20
        alertas.append("Se menciona una empresa que no se encuentra en el dominio de algunos enlaces.")
    if flag_discrepancia_remitente:
        puntos += 20
        alertas.append("El dominio del remitente no coincide con el destino de algunos enlaces.")
    if tiene_enlace_oficial:
        puntos -= 60

    if cuerpo_min:
        soup = BeautifulSoup(cuerpo_min, "html.parser")
        for enlace in soup.find_all("a"):
            url_real = enlace.get("href", "").strip()
            texto_visible = enlace.get_text(strip=True).lower()
            if re.search(r"\.[a-z]{2,}", texto_visible):
                dominio_visible = texto_visible.replace("http://", "").replace("https://", "").split("/")[0].replace("www.", "")
                dominio_real = urlparse(url_real).netloc.replace("www.", "")
                if dominio_real and dominio_visible not in dominio_real:
                    puntos += 70
                    alertas.append(f"PELIGRO: El enlace dice ir a '{dominio_visible}' pero realmente lleva a '{dominio_real}'.")

    alertas = list(dict.fromkeys(alertas))
    return puntos, alertas


def extraer_cuerpo(msg):
    cuerpo_texto = ""
    cuerpo_html = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            if "attachment" not in content_disposition:
                charset = part.get_content_charset() or "utf-8"
                payload = part.get_payload(decode=True)
                if payload:
                    decoded = payload.decode(charset, errors="ignore").replace("\xa0", " ")
                    if content_type == "text/plain":
                        cuerpo_texto += decoded
                    elif content_type == "text/html":
                        cuerpo_html += decoded
    else:
        content_type = msg.get_content_type()
        charset = msg.get_content_charset() or "utf-8"
        payload = msg.get_payload(decode=True)
        if payload:
            decoded = payload.decode(charset, errors="ignore").replace("\xa0", " ")
            if content_type == "text/html":
                cuerpo_html = decoded
            else:
                cuerpo_texto = decoded
    return cuerpo_texto, cuerpo_html


# ────────────────────────────────────────────────
# Rutas de la API
# ────────────────────────────────────────────────

@app.route("/api/conectar", methods=["POST"])
def conectar():
    """Conecta a Gmail y devuelve la lista de correos recientes."""
    data = request.json
    usuario = data.get("usuario", "").strip()
    password = data.get("password", "").strip()
    cantidad = int(data.get("cantidad", 10))

    try:
        servidor = obtener_servidor_imap(usuario)
        mail = imaplib.IMAP4_SSL(servidor)
        mail.login(usuario, password)
        mail.select("inbox")
        _, imap_data = mail.search(None, "ALL")
        ids = imap_data[0].split()

        if not ids:
            return jsonify({"error": "La bandeja de entrada está vacía."}), 400

        total = len(ids)
        cantidad = min(cantidad, total)
        ultimos_ids = ids[-cantidad:]

        correos = []
        for i, email_id in enumerate(ultimos_ids):
            _, data_header = mail.fetch(email_id, "(BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE)])")
            msg_header = email_lib.message_from_bytes(data_header[0][1])
            correos.append({
                "index": i,
                "id": email_id.decode(),
                "remitente": decodificar_texto(msg_header["From"])[:60],
                "asunto": decodificar_texto(msg_header["Subject"])[:80],
                "fecha": msg_header.get("Date", "")[:25],
            })

        mail.logout()
        return jsonify({"total": total, "correos": correos, "servidor": servidor})

    except imaplib.IMAP4.error as e:
        return jsonify({"error": f"Error de autenticación: {str(e)}"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/analizar", methods=["POST"])
def analizar():
    """Analiza un correo específico y devuelve el informe completo."""
    data = request.json
    usuario = data.get("usuario", "").strip()
    password = data.get("password", "").strip()
    email_id = data.get("email_id", "").encode()

    try:
        servidor = obtener_servidor_imap(usuario)
        mail = imaplib.IMAP4_SSL(servidor)
        mail.login(usuario, password)
        mail.select("inbox")

        _, raw_data = mail.fetch(email_id, "(RFC822)")
        msg = email_lib.message_from_bytes(raw_data[0][1])

        asunto = decodificar_texto(msg["Subject"])
        remitente = decodificar_texto(msg["From"])
        nombre_remitente, correo_remitente = parseaddr(remitente)
        dominio_puro = correo_remitente.split("@")[-1] if "@" in correo_remitente else correo_remitente

        cuerpo_texto, cuerpo_html = extraer_cuerpo(msg)
        cuerpo_combinado = cuerpo_texto + " " + cuerpo_html

        pais, ip = obtener_info_geografica(msg)
        spf, dkim = verificar_autenticacion(msg)
        empresas = extraer_nombre_aplicacion(cuerpo_combinado.lower())
        puntos, alertas = motor_reglas(asunto, cuerpo_combinado.lower(), nombre_remitente, dominio_puro, empresas)

        if spf != "pass" or dkim != "pass":
            puntos += 80
            alertas.append("El remitente no ha podido demostrar su identidad oficial (SPF/DKIM).")

        # --- MODELO IA  ---
        resultado_ia = None
        ia_usada = False

        if 40 <= puntos < 80 and MODELO_DISPONIBLE:
            ia_usada = True
            texto_para_ia = (asunto + " " + cuerpo_combinado)[:2000]
            texto_para_ia = traducir_al_ingles(texto_para_ia)
            
            try:
                predicciones, _ = modelo_ia.predict([texto_para_ia])
                resultado_ia = int(predicciones[0])
                if resultado_ia == 1:
                    alertas.append("IA: Ha clasificado el contenido como PHISHING.")
                else:
                    alertas.append("IA: Ha clasificado el contenido como SEGURO.")
            except Exception as e:
                alertas.append(f"IA: Error al clasificar ({e}).")

        # --- VEREDICTO FINAL ---
        if puntos >= 80:
            veredicto = "PHISHING"
            nivel = "danger"
        elif puntos >= 40:
            if ia_usada and resultado_ia == 1:
                veredicto = "SOSPECHOSO: PHISHING SEGÚN IA"
                nivel = "warning"
            elif ia_usada and resultado_ia == 0:
                veredicto = "SOSPECHOSO: SEGURO SEGÚN LA IA"
                nivel = "waning"
        else:
            veredicto = "SEGURO"
            nivel = "safe"

        mail.logout()
        return jsonify({
            "asunto": asunto,
            "remitente": remitente,
            "pais": pais,
            "ip": ip,
            "spf": spf,
            "dkim": dkim,
            "puntos": puntos,
            "veredicto": veredicto,
            "nivel": nivel,
            "alertas": alertas,
            "empresas_detectadas": empresas,
            "ia_usada": ia_usada,
            "modelo_disponible": MODELO_DISPONIBLE,
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("🛡️  Servidor de análisis de phishing iniciado en http://localhost:5000")
    app.run(debug=True, port=5000)
