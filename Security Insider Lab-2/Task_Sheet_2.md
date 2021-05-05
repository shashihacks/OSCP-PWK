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
    - Request procesess succfully.


