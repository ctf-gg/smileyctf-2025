from flask import Flask, request, make_response, render_template_string, redirect
import os, base64, sys

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time
app = Flask(__name__)

PORT = 8800

# flag start with d0nt, charset is string.ascii_letters +  string.digits + '{}_.-'
flag = open('flag.txt').read().strip()
print(flag.replace(".;,;.{", "").replace("}", ""))

template = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Pure Leaf</title>
    <style nonce="{{ nonce }}">
        body {
            background-color: #21d375;
            font-size: 100px;
            color: #fff;

            height: 100vh;
            margin: 0;

            text-align: center;
            justify-content: center;
            align-items: center;            
        }
    </style>
</head>
<body>
    <div class="head"></div>
    {% if flag %}
        <div class="leaf">{{ flag }}</div>
    {% endif %}
    {% if leaves %}
        <div class="leaf">{{ leaves | safe}}</div>
    {% else %}
        <div class="leaf">I love leaves</div>
    {% endif %}

    <script nonce="{{ nonce }}">
        Array.from(document.getElementsByClassName('leaf')).forEach(function(element) {
            let text = element.innerText;
            element.innerHTML = '';
            // our newest technology prevents you from copying the text
            // so we have to create a new element for each character
            // and append it to the element
            // this is a very bad idea, but it works
            // and we are not using innerHTML, so we are safe from XSS
            for (let i = 0; i < text.length; i++) {
                let charElem = document.createElement('span');
                charElem.innerText = text[i];
                element.appendChild(charElem);
            }
        });
    </script>
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    nonce = base64.b64encode(os.urandom(32)).decode('utf-8')

    flag_cookie = request.cookies.get('flag', None)

    leaves = request.args.get('leaf', 'Leaf')
    
    rendered = render_template_string(
        template,
        nonce=nonce,
        flag=flag_cookie,
        leaves=leaves,
    )
    
    response = make_response(rendered)

    response.headers['Content-Security-Policy'] = (
        f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
        "base-uri 'none'; frame-ancestors 'none';"
    )
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    return response


@app.route('/bot', methods=['GET'])
def bot():
    data = request.args.get('leaf', '🍃').encode('utf-8')
    data = base64.b64decode(data).decode('utf-8')
    url = f"http://127.0.0.1:8800/?leaf={data}"
    
    print('[+] Visiting ' + url, file=sys.stderr)
    
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    driver = webdriver.Chrome(options=options)
    driver.get(f'http://127.0.0.1:8800/void')
    driver.add_cookie({
        'name': 'flag',
        'value': flag.replace(".;,;.{", "").replace("}", ""),
        'path': '/',
    })
    
    print('[-] Visiting URL', url, file=sys.stderr)

    driver.get(url)
    driver.implicitly_wait(5)
    driver.quit()
    print('[-] Done visiting URL', url, file=sys.stderr)

    return redirect(f'http://127.0.0.1:8800/?leaf=Yayayayay I checked ur leaf its great', code=302)


if __name__ == '__main__':
    app.run(port=PORT, debug=False, host='0.0.0.0')
