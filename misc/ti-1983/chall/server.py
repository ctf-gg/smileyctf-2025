from flask import Flask, request, send_file
import subprocess
import tempfile
import os
app = Flask(__name__, static_folder=None)
from werkzeug.middleware.proxy_fix import ProxyFix

app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
)

code_tmpl = open("code_tmpl.py").read()
@app.route('/')
def index():
    return open("static/index.html", "rb").read().decode()

@app.route('/static')
def fileserve():
    url = request.url
    fpath = url.split(f"static?")[-1]
    files = os.listdir("static")
    if fpath not in files or not fpath.endswith(".tmpl"):
        fpath = "🐈.tmpl"
    return send_file(f"static/{fpath}")

def render_error(msg):
    return open("static/error.html", "rb").read().decode().replace("{{msg}}", msg)

@app.route('/ti-84')
def execute_code():
    code = request.values.get('code')
    output_tmpl = request.values.get('tmpl')
    if len(code) > 3:
        return render_error("This is a ~~Wendys~~ TI-84.")
    tmpl = code_tmpl
    tmplcode = tmpl.replace("{{code}}", code)
    tmpfile = tempfile.NamedTemporaryFile(suffix=".py", delete=False)
    tmpfile.write(tmplcode.encode())
    tmpfile.flush()
    url = f"http://localhost:80/static?{output_tmpl}.tmpl"
    if sum(1 for c in url if ord(c) > 127) > 1:
        return render_error("too many emojis... chill with the brainrot")
    out_tmpl = os.popen(f"curl.exe -s {url}").read()
    if "{{out}}" not in out_tmpl:
        return render_error("Template must have {{out}}")
    tmpfile.close()
    result = subprocess.run(['python.exe', tmpfile.name], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout
    if os.path.exists(tmpfile.name):
        os.remove(tmpfile.name)
    return out_tmpl.replace("{{out}}", result)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80, debug=False)
