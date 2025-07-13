
"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

parsed = urlparse("https://google.com")
query_params = parse_qs(parsed.query)
query_params["code"] = "123"
new_query = urlencode(query_params, doseq=True)
new_url = urlunparse(parsed._replace(query=new_query))

"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from flask import Flask, request, make_response, redirect
import base64, sys

from selenium import webdriver
from selenium.webdriver.chrome.options import Options

flag = open('flag.txt').read().strip()
app = Flask(__name__)

PORT = 8802


@app.route('/')
def index():
    return make_response(open('index.html').read())

@app.route('/bot', methods=['GET'])
def bot():
    data = request.args.get('code', '🍃').encode('utf-8')
    data = base64.b64decode(data).decode('utf-8')
    parsed = urlparse(f"{request.host_url}")
    query_params = parse_qs(parsed.query)
    query_params["code"] = base64.b64encode(data.encode('utf-8')).decode('utf-8')
    new_query = urlencode(query_params, doseq=True)
    new_url = urlunparse(parsed._replace(query=new_query))
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    driver = webdriver.Chrome(options=options)
    driver.get(f'{request.host_url}void')
    driver.add_cookie({
        'name': 'flag',
        'value': flag.replace(".;,;.{", "").replace("}", ""),
        'path': '/',
    })
    print('[+] Visiting ' + new_url, file=sys.stderr)
    driver.get(new_url)
    driver.implicitly_wait(5)
    driver.quit()
    print('[-] Done visiting URL', new_url, file=sys.stderr)
    return make_response('Bot executed successfully', 200)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=False)