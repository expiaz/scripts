import http.server, ssl

# generate self signed cert
# openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:4096 -out serv.crt -keyout serv.key
# PUT YOUR DOMAIN IN Common Name (e.g. server FQDN or YOUR name) []:test.com
# then add in /etc/hosts 127.0.0.1	test.com
# python3 ./server.py

server_address = ('localhost', 443)
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket,
                               server_side=True,
                               keyfile="poc.key",
                               certfile='poc.crt',
                               ssl_version=ssl.PROTOCOL_TLS)
httpd.serve_forever()