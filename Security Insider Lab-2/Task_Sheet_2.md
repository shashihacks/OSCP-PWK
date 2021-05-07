Web Application Vulnerabilities -2

### Exercise 1: Cross Site Request Forgery (CSRF/XSRF)

#### Task 1
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


#### Task 2

__Q: What is the difference between XSS and CSRF/XSRF from their execution perspective?__  
__Solution:__ If a website is vulnerable to stored XSS, execution of commands on behalf of victim is easy and does'nt require to setup a malicous website. In case of Cross-site request forgery,, the excution requires, the authentication victim from vulnerable website to visit the malicouis website setup by the attacker in order to execute the commands/requests.


#### Task 3

__Q: Briefly explain why your bank is theoretically vulnerable to CSRF/XSRF attack!__  
__Solution:__ After examining the web request, on `Transfer Funds` page , the website doesn't seem to send  any unique identifier or tokens , that identify the request as being originated from the same domain, or performed by the actual user.

![funds_transfer](images/task2/funds_transfer.PNG)


#### Task 4

__Assume that you are a valid customer of your bank. Show how you can use XSRF
to transfer money from another account to your account.__




#### Task 5.



### Exercise 2: Server-Side Request Forgery(SSRF)

__1. Briefly explain in your own words what is SSRF vulnerability and common SSRF attacks and what are the common SSRF defences circumventing__

__Solution__ SSRF(Server side request forgery) is a web server vulnerability where an attacker tricks the sever to execute a request. with a specially crafted request, one can control the server to request a URL, usually crafted with a publicly accessible URL, thus giving the partial or full control on server requests.

__2. What is the difference between SSRF and CSRF/XSRF from their execution
perspective?__

__Solution:__ CSRF targets the user, to trick or executes malicious links/requests,and send it to server on behalf of them, where as SSRF invloves specifically targeting the server, that is vulnerable in handling user requests. Although in both cases, its the server that is vulnerable, the victim is different in CSRF and SSRF attacks.  


### Exercise 3: Local File Inclusion (LFI)

__1. Briefly explain what is a Local File Inclusion (LFI) vulnerability? By using a simple
example, describe how do LFIs work and how to avoid this vulnerability? Show
a vulnerable code and apply your patch to it.__
__Solution:__  Local File Inclusion (LFI) ia web vulnerability, where an attacker tricks the web application to dynamically load files from from the web server that are available locally.

*Example:* When an application receives an unsantitized user input,  and processed, which exposes local files because of the input that directly constructs the file path, which is included in response

sample vulnerable code

```php

    echo "File included: ".$_REQUEST["page"]."<br>";
    echo "<br><br>";
    $local_file = $_REQUEST["page"];
    echo "Local file to be used: ". $local_file;
    echo "<br><br>"
    include $local_file;

```

How it works:
- Look for page includes or file names as parameters like'
    ```php
         http://www.vbank.com/file.php?file=transfer.php 
    ```
- change file by changing the file inlcude or file path URL
- Traverse through directory to look for local files and observe the  response from the application
 
- example..
    ```php
        http://www.vbank.com/file.php?file=../../../etc/shadow
    ```

- If the file path is true and the application does;nt filter and file is availbale in local to the server, contents can be displayed on the browser as a response
- The lack of input validation and filtering for files allow to read aribitary file contents

**Avoiding the Vulnerability**
    - Common and effective solution is to avoid allowing user submitted input to the application API.
    - An application can also have allowed list of files to include (whitelisting fioles and directories that can be included), any other input or file names can be rejected.




- **Fix: Whitelisting file**
    ```php
     $allowed_files = array('index','transfer', 'accounts'); //list of files that are allowed to be included 
     $local_file = $_REQUEST["page"];
     if(in_array($_GET['file'], $allowed_files)) { //check if the requested file is in allowed array list
        include ($_GET['file']. '.php')
    }
    ```



__2. How do you identify and exploit LFI? Describe it with a simple example.__

<br></br><br></br><br></br><br></br><br></br>