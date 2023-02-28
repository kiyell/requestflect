# Overview

During web application penetration testing, often the reflection of a user controlled value can lead to vulnerabilities such as [Cross-Site Scripting](https://portswigger.net/web-security/cross-site-scripting), [SQL Injection](https://portswigger.net/web-security/sql-injection), and [Cache Poisoning](https://portswigger.net/web-security/web-cache-poisoning). Although there are many tools that can scan and identify the reflection of URL parameters (x8 XSStrike), few are able to do the same for HTTP headers.

requestFlect works by testing a variety of HTTP headers such as the "X-Forwarded-Host" , "X-Original-Url", and "Origin" headers for reflection in the HTTP response body and headers. It is also able to to probe a server for cookie setting requests and then test values of those cookies for reflection. CORS misconfigurations will also be detected and reported.

# Examples

Scan a website for the value "testforreflection" reflected in the cookies or in the response to the 20 included header set tests:

`# ./requestFlect.py -a -k "testforreflection" https://www.example.com`

Scan a website using a specific header set test (see code)

`# ./requestFlect.py -m 10 -k "testforreflection" https://www.example.com`

# Usage
```
                                     | |   / _|| |            | |
 _ __   ___   __ _  _   _   ___  ___ | |_ | |_ | |  ___   ___ | |_
| '__| / _ \ / _` || | | | / _ \/ __|| __||  _|| | / _ \ / __|| __|
| |   |  __/| (_| || |_| ||  __/\__ \| |_ | |  | ||  __/| (__ | |_
|_|    \___| \__, | \__,_| \___||___/ \__||_|  |_| \___| \___| \__|
                | |
                |_|
Version 1.0
kiyell (https://github.com/kiyell)

       [-h] [-m method] [-c] [-a] [-k keyword] [-n] input_url

requestFlect probes webservers for reflections of user input in request
headers and cookies. It also detect problems with CORS configurations.

positional arguments:
  input_url

optional arguments:
  -h, --help            show this help message and exit
  -m method, --method method
                        HTTP header reflection specific method test
  -c, --cookie          Cookies reflection test
  -a, --all             Run both cookies and all method reflection tests
  -k keyword, --keyword keyword
                        Keyword to inject and test for reflection
  -n, --no-color        Output without color

Example: python ./requestFlect.py -k teststring -m 6 https://google.com
```
# Demo

TODO

# Credits:

- https://youst.in/posts/cache-poisoning-at-scale/
- https://kathan19.gitbook.io/howtohunt/host-header-attack/host-header
- https://portswigger.net/web-security/host-header/exploiting
