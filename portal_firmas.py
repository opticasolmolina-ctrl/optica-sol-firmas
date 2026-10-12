"""Portal independiente para desplegar DETRÁS DE HTTPS. No publicar sin auditoría de seguridad."""
import os, sqlite3, secrets, datetime, json, re
from pathlib import Path
from flask import Flask, request, jsonify, abort, render_template_string
ROOT=Path(__file__).resolve().parent
DB=Path(os.environ.get('FIRMA_DB',str(ROOT/'firmas.sqlite3')))
KEY=os.environ.get('OPTICA_FIRMA_CLAVE','')
BASE=os.environ.get('OPTICA_FIRMA_URL','').rstrip('/')
app=Flask(__name__)
app.config['MAX_CONTENT_LENGTH']=350000
with sqlite3.connect(DB) as c:
 c.execute('CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, token TEXT UNIQUE NOT NULL, store TEXT NOT NULL, customer TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, signed_at TEXT, choices TEXT, signature TEXT, legal_version TEXT)')
def conn():
 c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;return c
def secure_api():
 if not KEY or not secrets.compare_digest(request.headers.get('X-Optica-Key',''),KEY):abort(403)
def get_row(id):
 with conn() as c:return c.execute('SELECT * FROM requests WHERE id=?',(id,)).fetchone()
@app.post('/api/requests')
def create():
 secure_api()
 if not BASE.startswith('https://'):return jsonify(error='Falta URL HTTPS'),400
 d=request.get_json(silent=True) or {}; id=secrets.token_urlsafe(16);token=secrets.token_urlsafe(32)
 now=datetime.datetime.now(datetime.timezone.utc); exp=now+datetime.timedelta(days=7)
 with conn() as c:c.execute('INSERT INTO requests(id,token,store,customer,created_at,expires_at) VALUES(?,?,?,?,?,?)',(id,token,str(d.get('store','Óptica'))[:100],str(d.get('customer','Cliente'))[:150],now.isoformat(),exp.isoformat()))
 return jsonify(id=id,url=BASE+'/firmar/'+token)
@app.get('/api/requests/<id>')
def state(id):
 secure_api();r=get_row(id)
 if not r:abort(404)
 return jsonify(id=r['id'],status='firmado' if r['signed_at'] else 'pendiente',signed_at=r['signed_at'],choices=json.loads(r['choices'] or '{}'),signature=r['signature'] or '',legal_version=r['legal_version'] or '',created_at=r['created_at'],store=r['store'],customer=r['customer'])
LEGAL='''Responsable: la óptica indicada en esta solicitud. Finalidades: gestión de clientes, prestación de servicios ópticos y comunicaciones que elijas. Los datos de graduación son datos de salud y requieren una base jurídica específica y medidas reforzadas. Derechos: acceso, rectificación, supresión y otros derechos ante el responsable. La óptica debe sustituir esta plantilla por su política de privacidad completa, con identidad, contacto, bases jurídicas, destinatarios y plazos de conservación, antes de su uso real.'''
PAGE='''<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Firma de privacidad</title><style>body{font:16px system-ui;max-width:640px;margin:20px auto;padding:14px;color:#172b3a}label{display:block;margin:16px 0}canvas{width:100%;height:150px;border:2px solid #abc;border-radius:8px;touch-action:none}button{padding:13px;border:0;border-radius:8px;background:#146cc2;color:white;margin:8px 0}article{padding:14px;background:#f2f5f9;white-space:pre-wrap}</style><h1>{{store}}</h1><h2>Información de privacidad y preferencias</h2><p>Hola, {{customer}}.</p><article>{{legal}}</article><form id="f"><label><input type="checkbox" id="read" required> He leído la información de privacidad</label><p>Selecciona solo las comunicaciones que quieras recibir:</p><label><input type="checkbox" name="revision"> Recordatorios de revisión</label><label><input type="checkbox" name="lenses"> Reposición de lentillas</label><label><input type="checkbox" name="birthday"> Cumpleaños y santo</label><label><input type="checkbox" name="offers"> Ofertas y promociones</label><p>Firma con el dedo:</p><canvas id="sig" width="600" height="150"></canvas><button type="button" id="clear">Borrar firma</button><p><button type="submit">Confirmar y firmar</button></p></form><p id="msg" role="status"></p><script>const c=document.querySelector('canvas'),x=c.getContext('2d');let down=false,drawn=false;function point(e){let r=c.getBoundingClientRect();return [(e.clientX-r.left)*c.width/r.width,(e.clientY-r.top)*c.height/r.height]}c.onpointerdown=e=>{down=true;c.setPointerCapture(e.pointerId);let p=point(e);x.beginPath();x.moveTo(...p)};c.onpointermove=e=>{if(!down)return;let p=point(e);x.lineWidth=2;x.lineCap='round';x.lineTo(...p);x.stroke();drawn=true};c.onpointerup=()=>down=false;document.getElementById('clear').onclick=()=>{x.clearRect(0,0,c.width,c.height);drawn=false};document.getElementById('f').onsubmit=async e=>{e.preventDefault();if(!drawn){alert('Falta la firma');return}let choices={};for(let k of ['revision','lenses','birthday','offers'])choices[k]=!!document.querySelector('[name='+k+']').checked;let r=await fetch(location.pathname,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({read:true,choices,signature:c.toDataURL('image/png')})});let d=await r.json();document.getElementById('msg').textContent=d.ok?'Firma registrada. Puedes cerrar esta página.':(d.error||'Error');if(d.ok)document.getElementById('f').remove()};</script></html>'''
@app.route('/firmar/<token>',methods=['GET','POST'])
def sign(token):
 with conn() as c:r=c.execute('SELECT * FROM requests WHERE token=?',(token,)).fetchone()
 if not r:abort(404)
 if r['signed_at']:
  if request.method=='POST':return jsonify(error='Enlace ya utilizado'),409
  return 'Firma ya registrada',200
 if datetime.datetime.now(datetime.timezone.utc)>datetime.datetime.fromisoformat(r['expires_at']):return jsonify(error='Enlace caducado'),410
 if request.method=='GET':return render_template_string(PAGE,store=r['store'],customer=r['customer'],legal=LEGAL)
 d=request.get_json(silent=True) or {};choices=d.get('choices',{});signature=d.get('signature','')
 if d.get('read') is not True or not isinstance(choices,dict) or set(choices)!={'revision','lenses','birthday','offers'} or not all(type(v) is bool for v in choices.values()) or not re.fullmatch(r'data:image/png;base64,[A-Za-z0-9+/=]{100,200000}',signature):return jsonify(error='Datos incompletos'),400
 with conn() as c:c.execute('UPDATE requests SET signed_at=?,choices=?,signature=?,legal_version=? WHERE id=? AND signed_at IS NULL',(datetime.datetime.now(datetime.timezone.utc).isoformat(),json.dumps(choices),signature,'PLANTILLA-DEMO-1',r['id']))
 return jsonify(ok=True)
if __name__=='__main__':app.run(host='127.0.0.1',port=8766)
