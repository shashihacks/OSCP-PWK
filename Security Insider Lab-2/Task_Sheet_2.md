Web Application Vulnerabilities -2

### Exercise 1: Cross Site Request Forgery (CSRF/XSRF)

### Task 1
__Q__ 1. Briefly explain what CSRF/XSRF is in your own words (outline the roles and steps involved in XSRF attack).

__Solution__

- Cross-site-request-forgery (CSRF)- is an attack where the malicious website exploits trust between the web browser and the authenticated user's website which is vulnerable
- Unauthorized requests or commands are run on behalf of victim on the vulnerable website
-  Assume a vulnerable website that allows to run commands(like funds transfer), containing a url for that funds transfer. So when the user hits `transfer funds` with appropriate parameters, request gets executed succussfully

- Steps invloved:
    - Setup a malcious website
    - Create a script or source(like, `img` tags, `iframe`) that executes the request to transfer funds.
    - Allow the  authenticated victim to access the malicous website
    - Send the fund transfer request . (Since the victim is authenticated and the URL/script is crafted to transfer funds, cookies stored on victim's broswer also be sent)
    - Request gets sent on behalf of malicous users so the  request procesess successfully.


### Task 2

__Q: What is the difference between XSS and CSRF/XSRF from their execution perspective?__  
__Solution:__ If a website is vulnerable to stored XSS, execution of commands on behalf of victim is easy and does'nt require to setup a malicous website. In case of Cross-site request forgery,, the excution requires, the authentication victim from vulnerable website to visit the malicouis website setup by the attacker in order to execute the commands/requests.

__Briefly explain why your bank is theoretically vulnerable to CSRF/XSRF attack!__  
__Solution:__ After examining the web request, on `Transfer Funds` page , the website doesn't seem to send  any unique identifier or tokens , that identify the request as being originated from the same domain, or performed by the actual user.

![funds_transfer](images/task2/funds_transfer.PNG)


