from socket import gethostbyname
from random import randint
from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from lib.utils import URL
from lib.ui import GUI
import datetime
import sys





OP_INJECTION_PARAMS = [
	URL.PARAM_URL,
	URL.PARAM_BODY
]

OP_DEBUG_MODE = 0
OP_DEBUG_SERVER = "127.0.0.1"
OP_DEBUG_PORT = 80
OP_DEBUG_USE_HTTPS = 0
OP_SHOW_OUT_OF_SCOPE = 0


class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def getTabCaption(self):
    	# Setting extenstion tab name
        return "Bit Blinder"

    def getUiComponent(self):
    	# Returning instance of the panel as in burp's docs
        return self.ui.panel

    def registerExtenderCallbacks(self, callbacks):

        gui = GUI() # Local instance of the GUI class
        self.ui = gui.gui()

        # Registering callbacks from burp api
        self.callbacks = callbacks
        self.callbacks.setExtensionName("BIT/Blinder")
        self.callbacks.registerHttpListener(self)

        # Redirect the stdout to burp stdout
        sys.stdout = self.callbacks.getStdout()
        
        # Saving IExtensionHelpers to use later
        self.helpers = self.callbacks.getHelpers()

        # Settings up the main gui
        self.callbacks.customizeUiComponent(self.ui.panel)
        self.callbacks.addSuiteTab(self)

        print("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*")
        print("-  Developer: Ahmed Ezzat (BitTheByte)      -")
        print("-  Github:    https://github.com/BitTheByte -")
        print("-  Version:   0.04b                         -")
        print("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*")
        print("[WARNING] MAKE SURE TO EDIT THE SETTINGS BEFORE USE")
        print("[WARNING] THIS TOOL WILL WORK FOR IN-SCOPE ITEMS ONLY")
        print("[WARNING] THIS TOOL WILL CONSUME TOO MUCH BANDWIDTH")

        # Invoke burp's api
        return

    def processHttpMessage(self, flags, isRequest, rawData):

    	# Check if tool is enabled from the gui panel
        if not self.ui.enable.isSelected(): return
        # Check if it's not a request from burp
        if not isRequest: return

        # Getting request data
        request = rawData.getRequest()
        requestInfo = self.helpers.analyzeRequest(rawData)
        url = requestInfo.getUrl()

        # Check if the url in the scope
        if not self.callbacks.isInScope(url):
            if OP_SHOW_OUT_OF_SCOPE:
                print("[-] %s is out of scope" % url)
            return


        https = 1 if 'https' in requestInfo.url.getProtocol() else 0
        payloads = self.ui.get_payloads()
        body = request[requestInfo.getBodyOffset():]
        path = requestInfo.url.getPath()
        host = requestInfo.url.getHost()
        port = requestInfo.url.port
        method = requestInfo.getMethod()
        headers = requestInfo.getHeaders()
        paramters = requestInfo.getParameters()
        vparams = [p for p in paramters if p.getType() in OP_INJECTION_PARAMS]

        req_time = datetime.datetime.today().strftime('%m/%d|%H:%M:%S')

        print("====================================================")
        print("[{}] HOST: %s".format(req_time) % host)
        print("[{}] PATH: %s".format(req_time) % path)
        print("[{}] PORT: %i".format(req_time) % port)
        print("[{}] METH: %s".format(req_time) % method)
        print("[{}] HTTP: %i".format(req_time) % (not https))
        print("[{}] INJC: %s".format(req_time) % len(vparams))
        print("====================================================")

        new_request = request
        new_paramters_value = []

        for paramter in vparams:
            name = paramter.getName()
            value = paramter.getValue()
            ptype = paramter.getType()

            # Check if the randomize option is selected
            if self.ui.randomize.isSelected():
                payload = payloads[randint(0, len(payloads) - 1)]
            else:
                payload = payloads[0]

            # Adding the new paramters to array to use it for later
            new_paramters_value.append(
                	self.helpers.buildParameter(name, payload, ptype)
                )


        for new_paramter in new_paramters_value:
            name = new_paramter.getName()
            value = new_paramter.getValue()
            ptype = new_paramter.getType()

            updated = self.helpers.updateParameter(new_request, new_paramter)

            # Check if debug mode is enabled
            if OP_DEBUG_MODE:
                self.callbacks.makeHttpRequest(
                    	gethostbyname(OP_DEBUG_SERVER), OP_DEBUG_PORT,
                    	OP_DEBUG_USE_HTTPS, updated
                    )
            else:
                self.callbacks.makeHttpRequest(
                    	gethostbyname(host), port, https, updated
                    )
        # Invoke burp api
        return
