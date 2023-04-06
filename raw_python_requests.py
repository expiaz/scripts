import requests

# to be able to create raw requests
# we need to use under the hood API
# or python requests
# otherwise it will format the requests URL, parameters, path etc
s = requests.session()
p = requests.PreparedRequest()

# def prepare(
#     self,
#     method=None,
#     url=None,
#     headers=None,
#     files=None,
#     data=None,
#     params=None,
#     auth=None,
#     cookies=None,
#     hooks=None,
#     json=None,
# ):
#     """Prepares the entire request with the given parameters."""

#     self.prepare_method(method)
#     self.prepare_url(url, params)
#     self.prepare_headers(headers)
#     self.prepare_cookies(cookies)
#     self.prepare_body(data, files, json)
#     self.prepare_auth(auth, url)
p.method = "GET"
p.url = 'http://google.com'
p.headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) snap Chromium/83.0.4103.106 Chrome/83.0.4103.106 Safari/537.36"
}
p._cookies = requests.cookies.cookiejar_from_dict(None)

kwargs = {
    "timeout": None,
    "allow_redirects": False,
}
# if you want to add proxies
# import urllib3
# urllib3.disable_warnings()
# # or 
# requests.packages.urllib3.disable_warnings()
# kwargs['proxies'] = {
#     'http':'http://127.0.0.1:8080',
#     'https':'http://127.0.0.1:8080'
# }
# kwargs['verify'] = False

# if you have files or data (post) or json payload
# pass it to prepare body as if it was a parameter
# in requests.get/post/put...
# p.prepare_body(data, files, json)

response = s.send(p, **kwargs)

print(response)
