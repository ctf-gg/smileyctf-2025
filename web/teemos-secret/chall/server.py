from flask import Flask, request, make_response, redirect
import base64, sys, secrets
from urllib.parse import urlparse
from PIL import Image

from selenium import webdriver
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.action_chains import ActionChains

from threading import Lock
bot_lock = Lock()


app = Flask(__name__)

PORT = 7382

flag = open('flag.txt').read().strip()
flags = [secrets.token_hex(16) for _ in range(1000)]
flag_access = secrets.choice(flags)

gamble_chance = 3

@app.after_request
def add_header(response):
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response

@app.route('/')
def list_flags():
    response = ''
    for i in flags:
        response += f'<a href="/{i}">{i}</a><br>'
    return make_response(response, 200)

@app.route('/gamble', methods=['GET'])
def gamble():
    global gamble_chance
    if gamble_chance <= 0:
        return 'No more chances left', 403
    access = request.args.get('flag')
    if access:
        gamble_chance -= 1
        if request.args.get('flag') == flag_access:
            gamble_chance = 3
            return f'You won! Your flag is: {flag}.', 200
    return 'You lost! Try again.', 403

@app.route('/<path:data>', methods=['GET'])
def index(data):
    response = secrets.token_hex(16)
    return make_response(response, 200)


@app.route('/bot', methods=['GET'])
def bot():
    if not bot_lock.acquire(blocking=False):
        return 'please wait admin bot to finish running', 429
    try:
        data = request.args.get('address', 'http://example.com/').encode('utf-8')
        data = base64.b64decode(data).decode('utf-8')
    
        url = urlparse(data)
        
        if url.scheme not in ['http', 'https']:
            return 'Invalid URL scheme', 400
    
        url = data.strip()
        print('[+] Visiting ' + url, file=sys.stderr)
    
        firefox_options = Options()
        firefox_options.add_argument("--headless")
        firefox_options.add_argument("--no-sandbox")
    
        driver = webdriver.Firefox(options=firefox_options)
        
        driver.get('http://127.0.0.1:7382/')
        driver.implicitly_wait(3)
        driver.get('http://127.0.0.1:7382/'+flag_access)
        driver.implicitly_wait(3)
    
        driver.switch_to.new_window('tab')
        driver.switch_to.window(driver.window_handles[0])
    
        print('[-] Visiting URL', url, file=sys.stderr)
        driver.get(url)
    
        wait = WebDriverWait(driver, 10)
        try:
            wait.until(lambda d: 'loaded' in d.title.lower())
        except Exception as e:
            print('[-] Error waiting for page to load:', e, file=sys.stderr)
    
        driver.get(url)
        driver.save_screenshot('screenshot.png')
        driver.quit()
        print('[-] Done visiting URL', url, file=sys.stderr)
    
        image = Image.open('screenshot.png')
        # opps I fucked it up
        screenshot_data = image.crop((0, 0, 1, 1)).tobytes()
        response = make_response(screenshot_data, 200)
        response.headers['Content-Type'] = 'image/png'
        return response
    finally:
        bot_lock.release()


if __name__ == '__main__':
    app.run(port=PORT, debug=False, host='0.0.0.0')
