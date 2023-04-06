import socket, ssl

CONNECTION_TIMEOUT = 5
CHUNK_SIZE = 1024
HTTP_VERSION = 1.1
CRLF = "\r\n\r\n"
GREEN = "\033[;32m"
RED = "\033[;31m"
NC = "\033[0m"

def receive_all(sock, chunk_size=CHUNK_SIZE):
    '''
    Gather all the data from a request.
    '''
    chunks = b""
    while True:
        chunk = sock.recv(int(chunk_size))
        if chunk:
            chunks += chunk
        else:
            break

    return chunks

def http(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(CONNECTION_TIMEOUT)
    # TODO resolv domain ?
    sock.connect((host, port))

def https(host, port):
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(CONNECTION_TIMEOUT)
    ss = context.wrap_socket(s, server_hostname=host)
    ss.connect((host, port))



def get(host, path, port=80):
    if port == 443:
        s = http(host,port)
    else:
        s = https(host,port)

    msg = b"GET " + path.encode('utf-8') + b" HTTP/" + HTTP_VERSION +  b"\r\n"
    msg += b"Host: " + host.encode('utf-8') + b"\r\n"
    msg += b"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) snap Chromium/83.0.4103.106 Chrome/83.0.4103.106 Safari/537.36\r\n"
    msg += b"Connection: close\r\n\r\n"

    s.sendall(msg)
    data = receive_all(sock, chunk_size=CHUNK_SIZE)
    s.shutdown(socket.SHUT_RDWR)
    s.close()

    return data