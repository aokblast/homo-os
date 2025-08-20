import requests
with requests.post("http://10.211.55.87:1919/sankai", headers={
    "HOMO-KEY": "48763"
}, data=open("build/fe_gz/flag.enc", "rb").read()) as resp:
    print(resp.status_code)
    print(resp.text)