#!/usr/bin/env python3

import requests
import sys
import validators
import os
import urllib3
import h11
import httpx
import time
from h11._util import validate
from bs4 import BeautifulSoup
import random
urllib3.disable_warnings()
import argparse 
#removing MarkupResemblesLocatorWarning example: using input ./requestFlect -a https://snapchat.com
import warnings
warnings.filterwarnings('ignore')



usage = "Usage : \n\nrequestFlect.py.py <options> <arguements>\n \nOptions : \n -u \t:\t URL of the Website \n -i \t:\t Input file of the URLS\n"
keyword = 'testkeyword'
ua = "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/81.0"
hostinjection_result_list = list()
acao_result_list = list()
header3 = {"Origin": keyword, "User-Agent": ua}
hic_header_1 = {"Host": keyword, "User-Agent": ua}
hic_header_1 = {"Host": keyword, "User-Agent": ua, "host" : keyword}
hic_header_2 = {"X-Forwarded-Host": keyword, "User-Agent": ua}
add_host_special = True
special_char = b""
current_target = "unset current_target"
current_method = "none"
prepend_special_header = False
debug = 0
title = "notitle"
o_stcode = "0"
o_size = 0
G = '\033[92m'  # green
Y = '\033[93m'  # yellow
B = '\033[94m'  # blue
R = '\033[91m'  # red
W = '\033[0m'   # white
bannerdisplay =G+"                               _     __  _              _   \n                                     | |   / _|| |            | |  \n _ __   ___   __ _  _   _   ___  ___ | |_ | |_ | |  ___   ___ | |_ \n| '__| / _ \ / _` || | | | / _ \/ __|| __||  _|| | / _ \ / __|| __|\n| |   |  __/| (_| || |_| ||  __/\__ \| |_ | |  | ||  __/| (__ | |_ \n|_|    \___| \__, | \__,_| \___||___/ \__||_|  |_| \___| \___| \__|\n                | |                                                \n                |_|                                                \n"+B+"Version 1.0"+Y+"\nkiyell (https://github.com/kiyell) \n"+W


def banner(write):
	if write:
		print("""%s                                      _     __  _              _   \n                                     | |   / _|| |            | |  \n _ __   ___   __ _  _   _   ___  ___ | |_ | |_ | |  ___   ___ | |_ \n| '__| / _ \ / _` || | | | / _ \/ __|| __||  _|| | / _ \ / __|| __|\n| |   |  __/| (_| || |_| ||  __/\__ \| |_ | |  | ||  __/| (__ | |_ \n|_|    \___| \__, | \__,_| \___||___/ \__||_|  |_| \___| \___| \__|\n                | |                                                \n                |_|%s                                                \nVersion 1.0\n%skiyell (https://github.com/kiyell) \n""" % (G, W, Y))
	return bannerdisplay

def no_color():
	global G, Y, B, R, W
	G = Y = B = R = W = ''

def is_redirect(status_code) :
	if status_code == 301 :
		return True
	elif status_code == 302 :
		return True
	elif status_code == 303 :
		return True
	elif status_code == 307 :
		return True
	elif status_code == 308 :
		return True
	else :
		return False


def process_req_file(url_file) :
	print(1)
	return

def process_file(url_file) :
	f = open(url_file,"r")
	for line in f :
		line = line.strip()
		print("\n"+"Scanning : "+line)
		hostinjection_check(line)
		acao_check(line)
	f.close()
	if len(hostinjection_result_list) == 0 :
		print("\nNo Vulnerable URL(s)")
	else :
		print("\n*** Potential Host Header Injection at :\n")
		for url in hostinjection_result_list :
			print(url)
	
	if len(acao_result_list)== 0:
		print("\nNo CORS Misconfig(s)")
	else :
		print("\n*** Possible CORS Misconfig at :\n")
		for url in acao_result_list :
			print(url)
	return


# this monkey patch is only needed, when you want to remove
# the 'Host' header
def _validate(self):
	"""remove validation for missing Host header"""
	validate(h11._events.request_target_re, self.target, "Illegal target characters")
	#validate(h11._headers._field_name_re, self.target, 1)


h11._events.Request._validate = _validate

# this monkey patch is only needed, when the 'Host' header
# should not be the first header
def write_headers(headers, write):
	"""put the Host header at the specified place, not at the top"""
	raw_items = headers._full_items
	for raw_name, name, value in raw_items:
		if name == b"host" and not prepend_special_header:
				write(b"%s%s: %s\r\n" % (raw_name, special_char, value))
		elif name == b"host" and prepend_special_header:
				write(b"%s%s: %s\r\n" % (special_char, raw_name, value))
		else:
				write(b"%s: %s\r\n" % (raw_name, value))
	write(b"\r\n")


h11._writers.write_headers = write_headers
	
def hostinjection_basic_check(target_url) :
	target_url=target_url+"/"
	la=0
	if validators.url(target_url) :
		try :
			response1=requests.get(target_url, headers=hic_header_1, allow_redirects=False, verify=False)
			response2=requests.get(target_url, headers=hic_header_2, allow_redirects=False, verify=False)
			response1_location=""
			response2_location=""
			
			
			if is_redirect(response1.status_code) :
				if len(response1.headers["Location"]) != 0 :	
					response1_location=response1.headers["Location"]
					
			response1_body=response1.text
			

			if is_redirect(response2.status_code) :
				if len(response2.headers["Location"]) != 0 :	
					response2_location=response2.headers["Location"]
					
			response2_body=response2.text
			
			if(response1_body.find(keyword) > -1  or
						   response1_location.find(keyword) > -1 or
						   response1.status_code==200 or
						   response2_body.find(keyword) > -1 or
						   response2_location.find(keyword) > -1) :
				hostinjection_result_list.append(target_url)
				print("[!!] Potential Host Header Injection at "+target_url)
			else :
								print("-- hostinjection_check pass: "+target_url)
				
		except Exception as e:
			print(e)
						#print("-- hostinjection_check pass with exception: "+target_url)
	else :
		print("\r"+"Malformed URL : "+target_url+"\r")
	#	exit(1)
	return

def acao_check(target_url):
	target_url=target_url+"/"
	try:
		response3=requests.get(target_url, headers=header3, allow_redirects=False, verify=False)
		response3_acao=""

		if len(response3.headers["access-control-allow-origin"]) !=0 :
			response3_acao=response3.headers["access-control-allow-origin"]
		if len(response3.headers["Access-Control-Allow-Origin"]) !=0 :
			response3_acao=response3.headers["Access-Control-Allow-Origin"]

		if(response3_acao.find(keyword) > -1) :
			acao_result_list.append(target_url)
			print("[!!] \n*** Overly Permissive CORS Policy :"+target_url)
			

	except:
		print("-- acao_check pass: "+target_url)

def printdebug(string, end="\n"):
	if debug:
		print(string, end)
		
def show_cache_headers(response):
	for h in response.headers:
		if h.find("Cache") > -1 or h.find("cache") > -1:
			print(h+":"+response.headers.get(h), end= " ")
	print("\n")

def check_response(response):

		### debug info
		
		printdebug("DEBUG -- METHOD "+str(current_method)+":"+current_target, end =":")
		if (is_redirect(response.status_code)):
				printdebug(response.status_code, end =":")
				printdebug("-->"+response.headers["Location"])
		else :
				printdebug(response.status_code)

		### code vuln checks here
		#ACAO Check
				
		acao_var=""
		if response.headers.get('access-control-allow-origin') is not None :
				acao_var=response.headers.get('access-control-allow-origin')
				if acao_var.find(keyword) > -1 :
						print("\n[!!] *** Overly Permissive CORS Policy : "+current_target+" :METHOD:"+str(current_method))
						show_cache_headers(response)
				if acao_var.find("null") > -1 or acao_var.find("NULL") > -1:
						print("\n[!!] *** Trusted null origin CORS Policy : "+current_target+" :METHOD:"+str(current_method))
		if acao_var.find(keyword) == -1 :
		## if ACAO passes then general response head check only if not redirect
				resp_heads = str(response.headers)
				#print(resp_heads)
				if (resp_heads.find(keyword) > -1 or resp_heads.find(keyword.lower()) > -1):
						head_index = int(resp_heads.find(keyword))
						h_location_with_context = str(resp_heads[head_index-10:head_index+len(keyword)+10])
						print("\n[!!] *** Header Reflection Found :"+current_target+":METHOD:"+str(current_method))
						print("	Header Injection Context sample: | "+h_location_with_context+" |", end="")
						show_cache_headers(response)

		## response body check

		response.read()
		if response.text.find(keyword) > -1 :
				resp_body = str(response.text)
				body_index = int(response.text.find(keyword))
				b_location_with_context = str(response.text[body_index-10:body_index+len(keyword)+10])
				print("\n[!!] *** Body Reflection Found :"+current_target+":METHOD:"+str(current_method))
				print("	Body Injection Context sample: | "+b_location_with_context+" |", end="")
				show_cache_headers(response)
		if response.text.find(":11337") > -1 :
				resp_body = str(response.text)
				body_index = int(response.text.find(":11337"))
				b_location_with_context = str(response.text[body_index-10:body_index+len(":11337")+10])
				print("\n[!!] *** Body Port Reflection Found :"+current_target+":METHOD:"+str(current_method))
				print("	Body Port Injection Context sample: | "+b_location_with_context+" |", end="")
				show_cache_headers(response)
		#print (response.cookies)
		

def cookies_check(target_url):
	global current_target
	global current_method
	global title
	global o_stcode
	global o_size
	current_target = target_url
	current_method = "c"
	target_no_uri = target_url.split('/')[1]+target_url.split('/')[2]
	method_headers_1 = [("Host", target_no_uri),("Cache-Control", "no-store"),("User-Agent", ua)]
	cookies1 = httpx.Cookies()
	check_title = 1
	timeout_exit =0
	
	print("\nBaseline & Cookie Injection check Target : "+target_url+"\n")
	
	with httpx.Client(verify=False,timeout=10,event_hooks={'response': [check_response]}) as client:
				headers = httpx.Headers(method_headers_1)
				request = client.build_request("GET", target_url)
				request.headers = headers
				try:
					r = client.send(request,allow_redirects=False)
					cookies1 = r.cookies
					soup = BeautifulSoup(r.content, 'html.parser')
					o_stcode = "0"
					o_stcode = r.status_code
					if soup.title is not None:
						title = soup.title.string
					if is_redirect(r.status_code):
						check_title = 0
					o_size = len(r.content)
					print("  {"+current_method+"}("+str(r.status_code)+")["+str(title).strip()+"] o:"+str(o_size), end ="=>")
				except Exception as e:
					print(e)
					timeout_exit+=1
					
	if 1:
		cookies2 = httpx.Cookies()
		for c in cookies1:
			#print("Setting: "+c)
			cookies2.set(c,keyword)
			
		
		with httpx.Client(verify=False,timeout=10,event_hooks={'response': [check_response]},cookies=cookies2,headers=method_headers_1) as client:
				request = client.build_request("GET", target_url)
				try:
					r = client.send(request,allow_redirects=True)
					soup = BeautifulSoup(r.content, 'html.parser')
					newtitle = "nochange"
					if check_title and soup.title is not None:
						if soup.title.text != title:
							print("changed!", end = "")
							newtitle = soup.title.text
					print("("+str(r.status_code)+")["+str(newtitle).strip()+"] d:"+str(o_size - len(r.content)))
				except Exception as e:
					print(e)
					timeout_exit+=1
					if timeout_exit == 2:
						## Skipping other potentional tests because host likely down
						quit()
def injection_advanced_check(target_url, header_method, special_method, prependspecial):

		
		# using a client instance is the recommended way to use httpx
		global current_target
		global current_method
		global add_host_space
		global special_char
		global prepend_special_header
		current_target = target_url
		current_method = str(header_method)
		#+"|"+str(special_method)+"|"+str(prependspecial)
		prepend_special_header = prependspecial
		#target_no_uri = target_url.replace("https://", "")
		target_no_uri = target_url.split('/')[1]+target_url.split('/')[2]
		rand = str(random.randint(00,99))
		# Header combos:

		method_headers = [
				#0 method host is keyword
				[("Host", keyword),("Cache-Control", "no-transform"),("User-Agent", ua)],
				#1 method host is subdomain of keyword
				[("Host", target_no_uri+"."+keyword),("Cache-Control", "no-transform"),("User-Agent", ua)],
				#2 method keyword is subdomain of host
				[("Host", keyword+"."+target_no_uri),("Cache-Control", "no-transform"),("User-Agent", ua)],
				#3 method origin is keyword
				[("Host", target_no_uri),("Origin", keyword),("Cache-Control", "no-transform"),("User-Agent", ua)],
				#4 method null origin
				[("Host", target_no_uri),("Origin", "null"),("Cache-Control", "no-transform"),("User-Agent", ua)],
				#5 method origin is subdomain of keyword
				[("Host", target_no_uri),("Origin", target_no_uri+"."+keyword),("Cache-Control", "no-transform"),("User-Agent", ua)],
				#6 method origin keyword is prepended
				[("Host", target_no_uri),("Origin", keyword+"."+target_no_uri),("Cache-Control", "no-transform"),("User-Agent", ua)],
				#7 method add two hosts, the second is keyword
				[("Host",  target_no_uri),("Host", keyword),("Cache-Control", "no-transform"),("User-Agent", ua)],
				#8 method add two hosts, first is keyword
				[("Host",  keyword),("Host", target_no_uri),("Cache-Control", "no-transform"),("User-Agent", ua)],
				#9 method referer is keyword
				[("Host", target_no_uri),("Referer", keyword),("Cache-Control", "no-transform"),("User-Agent", ua)],
				#10 method referer is host with keyword appended
				[("Host", target_no_uri),("Referer", target_no_uri+"/"+keyword),("Cache-Control", "no-transform"),("User-Agent", ua)],
				#11 method add X-headers, x port number
				[("Host",  target_no_uri),("X-Forwarded-Host", keyword),("X-Host", keyword),("X-Forwarded-Server", keyword)
				,("X-HTTP-Host-Override", keyword),("X-Forwarded-For", keyword),("X-Forwarded-Port", "11337"),("Cache-Control", "no-transform"),("User-Agent", ua)],
				#12 method add X-headers,origin,referer wo host
				[("Origin",  keyword),("Referer", keyword),("X-Forwarded-Host", keyword),("X-Host", keyword),("X-Forwarded-Server", keyword)
				,("X-HTTP-Host-Override", keyword),("X-Forwarded-For", keyword),("Cache-Control", "no-transform"),("User-Agent", ua)],
				#13 method fastly-host normal but change host
				[("Fastly-host", target_no_uri),("Host", keyword),("Cache-Control", "no-transform"),("User-Agent", ua)],
				#14 method x-amz-website
				[("x-amz-website-redirect-location", "https://"+keyword),("Host", target_no_uri),("Cache-Control", "no-transform"),("User-Agent", ua)],
				#15 method x-original-host, x-original-url, X-Rewrite-URL
				[("x-original-host", keyword),("x-original-url", "/"+keyword),("x-rewrite-url", "/"+keyword),("Host", target_no_uri),("Cache-Control", "no-transform"),("User-Agent", ua)],
				#16 method localhost x-forwarded-for 127.0.0.1
				[("X-Forwarded-For", "127.0.0.1"),("Host", target_no_uri),("Cache-Control", "no-transform"),("User-Agent", ua)],
				#17 method host:port
				[("Host", target_no_uri+":11337"),("Cache-Control", "no-transform"),("User-Agent", ua)],
				#18 method GET keyword
				[("Host", target_no_uri),("Cache-Control", "no-transform"),("User-Agent", ua)],
				#19 method GET @keyword
				[("Host", target_no_uri),("Cache-Control", "no-transform"),("User-Agent", ua)],
				
				
				
				[("B", "1"),("A", "3"),("a", "4"),("Origin", keyword),("Host", target_no_uri),("Cache-Control", "no-store"),("User-Agent", ua)],
				[("bbggg", "1"),("A", "3"),("a", "4"),("R", "5"),("Host", target_no_uri),("Cache-Control", "no-store"),("User-Agent", ua)],
				]
				
		special_chars = [b"",b"\n\r",b"\r\n",b"\r",b"\n",b" ",b"\t"]
		special_char = special_chars[special_method]
		
		addpath = ""
		if header_method == 18:
			addpath = " "+keyword
		if header_method == 19:
			addpath = " @"+keyword
			

		
		with httpx.Client(verify=False,timeout=10,event_hooks={'response': [check_response]}) as client:
			headers = httpx.Headers(method_headers[header_method])
			request = client.build_request("GET"+addpath, target_url+"?"+rand+"="+"h1")
			request.headers = headers

			try:
				r = client.send(request)
				soup = BeautifulSoup(r.content, 'html.parser')
				newtitle = "nochange"
				note = ""
				if soup.title is not None and title != "notitle":
					if soup.title.text != title:
						newtitle = soup.title.text.strip()
						note = "changed!"
				print("  {"+current_method+"}("+str(o_stcode)+")["+title.strip()+"]=>"+note+"("+str(r.status_code)+")["+newtitle+"] d:"+str(o_size - len(r.content)))
			except Exception as e:
				print(e)
						
def parser_error(errmsg):
    banner(1)
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    print(R + "Error: " + errmsg + W)
    sys.exit()	

parser = argparse.ArgumentParser(prog=banner(0),description="requestFlect probes webservers for reflections of user input in request headers and cookies. It also detect problems with CORS configurations.",epilog='\tExample: \r\npython ' + sys.argv[0] + " -k teststring -m 6 https://google.com")
parser.error = parser_error
parser.add_argument("input_url")
parser.add_argument("-m", "--method", help = "HTTP header reflection specific method test", metavar="method")
parser.add_argument("-c","--cookie", help = "Cookies reflection test",action="store_true")
parser.add_argument("-a","--all", help = "Run both cookies and all method reflection tests",action="store_true")
parser.add_argument("-k", "--keyword", help = "Keyword to inject and test for reflection", metavar="keyword")
parser.add_argument('-n', '--no-color', help='Output without color', default=False, action='store_true')

args = parser.parse_args()
if args.keyword:
	keyword = args.keyword
if args.method:
	print(args.method)
	injection_advanced_check(args.input_url,int(args.method),0,False)
if args.no_color:
	no_color()
if args.cookie:
	cookies_check(args.input_url)
if args.all:
	cookies_check(args.input_url)
	print("\nInjection advanced check Target : "+args.input_url+"\n")
	for x in range(20):
		injection_advanced_check(args.input_url,x,0,False)
		time.sleep(3)

