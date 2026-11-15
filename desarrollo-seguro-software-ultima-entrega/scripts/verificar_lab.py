"""Pruebas limitadas del laboratorio propio. No reporta MitM real ni SQLi exhaustiva.
Uso (tras iniciar Docker): python scripts/verificar_lab.py
Salida: evidence/resultados_locales.json
"""
import base64
import hashlib
import hmac
import http.cookiejar
import json
import ssl
import struct
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = "https://localhost:8443"
CA = ROOT/"certs"/"ca.crt"
OUTPUT = ROOT/"evidence"/"resultados_locales.json"


def env_file():
    result={}
    for line in (ROOT/".env").read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k,v=line.split("=",1)
            result[k.strip()]=v.strip()
    return result


def client():
    cookie=http.cookiejar.CookieJar()
    context=ssl.create_default_context(cafile=str(CA))
    opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=context),
                                      urllib.request.HTTPCookieProcessor(cookie))
    return opener,cookie


def request(opener,path,method="GET",payload=None,headers=None):
    headers={**(headers or {})}
    data=None
    if payload is not None:
        data=json.dumps(payload).encode("utf-8")
        headers["Content-Type"]="application/json"
    req=urllib.request.Request(BASE+path,data=data,headers=headers,method=method)
    try:
        response=opener.open(req,timeout=8)
        body=response.read(250_000)
        return response.status,json.loads(body) if body else {},dict(response.headers)
    except urllib.error.HTTPError as error:
        content=error.read(5000)
        try: detail=json.loads(content)
        except Exception: detail={}
        return error.code, detail, dict(error.headers)


def totp(secret):
    secret=secret.upper(); pad="="*((8-len(secret)%8)%8)
    key=base64.b32decode(secret+pad)
    msg=struct.pack(">Q",int(time.time()//30))
    h=hmac.new(key,msg,hashlib.sha1).digest()
    off=h[-1]&15
    return f"{(struct.unpack('>I',h[off:off+4])[0]&0x7fffffff)%1_000_000:06d}"


def login(role,passwd,secret):
    op, jar=client()
    s,data,_=request(op,"/api/v1/auth/login","POST",{"correo":role,"password":passwd})
    if data.get("mfa_required") and s==200:
        s,data,_=request(op,"/api/v1/auth/mfa","POST",{"challenge":data["challenge"],
                                                           "codigo":totp(secret)})
    if s!=200 or data.get("authenticated") is not True:
        raise RuntimeError("No fue posible autenticar el rol "+role)
    return op,jar,data["csrf_token"]


def main():
    env=env_file()
    results=[]
    def record(id,observed,ok,details):
        results.append({"id":id,"estado":"APROBADO" if ok else "FALLIDO",
                        "observado":observed,"detalle":details})
        print(id,results[-1]["estado"],observed)
    def pending(id,reason):
        results.append({"id":id,"estado":"NO_EJECUTADO","detalle":reason})
    op,_=client()
    status,data,headers=request(op,"/health")
    record("E-01",f"HTTP {status}",status==200 and data=={"status":"ok"},"Salud de API sobre HTTPS")
    record("M-02-TLS",f"HTTPS HTTP {status}",status==200,"Cliente valida CA explícita del laboratorio")
    record("M-04-HSTS",headers.get("Strict-Transport-Security","ausente"),
           "max-age" in headers.get("Strict-Transport-Security",""),"Cabecera del proxy HTTPS")
    # Esta prueba no sustituye un MitM activo.
    try:
        rawop=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        rawop.open(BASE+"/health",timeout=5)
        record("CERT-NO-CONFIABLE","Certificado aceptado por sistema",False,
               "Probablemente la CA de laboratorio ya está confiada por el SO")
    except (ssl.SSLError,urllib.error.URLError) as exc:
        if isinstance(exc,urllib.error.URLError) and isinstance(exc.reason,ssl.SSLError):
            record("CERT-NO-CONFIABLE","Rechazo por certificado no confiable",True,"Cliente sin CA explícita")
        else:
            record("CERT-NO-CONFIABLE",type(exc).__name__,False,"Revisar si hubo otro error de red")
    student,jar,_=login("estudiante@lab.local",env["DEMO_PASSWORD"],env["DEMO_TOTP_SECRET"])
    s,grades,_=request(student,"/api/v1/me/calificaciones")
    record("RF-03",f"HTTP {s}, {len(grades) if isinstance(grades,list) else 0} curso(s)",
           s==200 and isinstance(grades,list),"Consulta autenticada")
    st_me,me,_=request(student,"/api/v1/me")
    for id,email in [("S-01","x' OR '1'='1' --"),("S-02","'")]:
        guest,cookies=client()
        s,_,_=request(guest,"/api/v1/auth/login","POST",{"correo":email,"password":"incorrecta"})
        session_cookie=any(c.name=="sid" for c in cookies)
        record(id,f"HTTP {s}, cookie sid={session_cookie}",s in (401,422) and not session_cookie,
               "Sondeo simple; no equivale a prueba SQLi exhaustiva")
    course_id=grades[0]["curso_id"] if grades else None
    if course_id and st_me==200:
        s,_,_=request(student,f"/api/v1/cursos/{course_id}/calificaciones/{me['id']}","PUT",
                      {"corte":1,"nota":4.0,"observacion":"no autorizado"})
        record("A-01",f"HTTP {s}",s==403,"Usuario estudiante no puede modificar notas")
    teacher,_,csrf=login("docente@lab.local",env["DEMO_PASSWORD"],env["DEMO_TOTP_SECRET"])
    s,courses,_=request(teacher,"/api/v1/cursos")
    cid=str(courses[0]["id"]) if s==200 and courses else None
    if cid:
        s,_,_=request(teacher,"/api/v1/cursos/uuid-invalido/calificaciones")
        record("S-03",f"HTTP {s}",s==422,"Parámetro UUID inválido")
        if st_me==200:
            route=f"/api/v1/cursos/{cid}/calificaciones/{me['id']}"
            s,_,_=request(teacher,route,"PUT",{"corte":1,"nota":"0 OR 1=1","observacion":"lab"},
                           {"X-CSRF-Token":csrf})
            record("S-04",f"HTTP {s}",s==422,"Campo nota rechaza texto no numérico")
            s,_,_=request(teacher,route,"PUT",{"corte":1,"nota":4.0,"observacion":"lab"})
            record("A-04",f"HTTP {s}",s==403,"Protección CSRF sin token")
    auditor,_,_=login("auditor@lab.local",env["DEMO_PASSWORD"],env["DEMO_TOTP_SECRET"])
    s,report,_=request(auditor,"/api/v1/auditoria")
    record("A-05",f"HTTP {s}, integridad={report.get('integridad')}",
           s==200 and report.get("integridad") is True,"Auditoría encadenada")
    s,db,_=request(auditor,"/api/v1/auditoria/estado-db")
    record("M-05-TLS-DB",f"HTTP {s}, ssl={db.get('ssl')}, version={db.get('version')}",
           s==200 and db.get("ssl") is True and db.get("version")=="TLSv1.3",
           "Cifrado en esta conexión; verificar certificados en configuración")
    pending("M-01","HTTP base no activo en versión reforzada; requiere entorno inicial")
    pending("M-03-MitM","El rechazo de CA no sustituye una interceptación MitM real")
    pending("S-05-sqlmap","Herramienta externa no ejecutada por este script")
    pending("A-06-DB-TAMPER","Alteración controlada de fila cifrada requiere laboratorio y backup")
    OUTPUT.parent.mkdir(parents=True,exist_ok=True)
    OUTPUT.write_text(json.dumps({"fecha_utc":datetime.now(timezone.utc).isoformat(),
        "objetivo":BASE,"resultados":results},indent=2,ensure_ascii=False),encoding="utf-8")
    print("Reporte guardado:",OUTPUT)

if __name__=="__main__":
    try: main()
    except Exception as exc:
        raise SystemExit("No se completó la prueba local: "+str(exc))
