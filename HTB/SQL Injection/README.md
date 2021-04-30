###Introduction

Most modern web applications utilize a database structure on the backend. Such databases are used to store and retrieve data related to the web application, from actual web content to user information and content, and so on.

To make the web applications dynamic, the web application has to interact with the database in real-time. As HTTP(S) requests arrive from the user, the web application's backend will issue queries to the database to build the response. These queries can include information from the HTTP(S) request or other relevant information.

![DB Interaction](https://academy.hackthebox.eu/storage/modules/33/db_request_3.png)

When user-supplied information is used to construct the query to the database, malicious users can try to trick the query into being used for something other than what the original programmer intended, providing the user access to query the database using an attack known as SQL injection (SQLi).

SQL injection refers to attacks against relational databases such as
 MySQL   (whereas injections against non-relational databases, such as MongoDB, are referred to as NoSQL injection).

This module will focus on <span style="color:green"> MySQL </span> to introduce SQL Injection concepts.

####SQL Injection (SQLi)
There are many types of injection vulnerabilities possible within web applications, such as HTTP injection, code injection, and command injection. The most common example, however, is SQL injection. A SQL injection occurs when a malicious user attempts to pass input that changes the final SQL query sent by the web application to the database, enabling the user to perform other unintended SQL queries directly against the database.

There are many ways to accomplish this. To get a SQL injection to work, the attacker must first inject SQL code and then subvert the web application logic by changing the original query or executing a completely new one. First of all, the attacker has to inject code outside the expected user input limits, so it does not get executed as simple user input. In the most basic case, this is done by injecting a single quote (') or a double quote (") to escape the limits of user input and inject data directly into the SQL query.

Once an attacker can inject, they have to look for a way to execute a different SQL query. This can be done using SQL code to make up a working query that executes both the intended and the new SQL queries. There are many ways to achieve this, like using stacked queries or using Union queries.

Finally, to retrieve our new query's output, we have to interpret it or capture it on the front end of the web application.

####Use Cases and Impact

A SQL injection can have a tremendous impact, especially if privileges on the backend server and database are very lax.

First of all, we may retrieve secret/sensitive information that should not be visible to us, like user logins and passwords or credit card information, which can then be used for other malicious purposes. SQL injections cause many password and data breaches against web sites, which are then re-used to steal user accounts, access other services, or perform other nefarious actions.

Another use case of SQL injection is to subvert the intended web application logic. The most common example of this is bypassing login without passing a valid pair of username and password credentials. Another example is accessing features that are locked to certain users, like admin panels.

Attackers may also be able to read and write files directly on the backend server, which may, in turn, lead to placing back doors on the backend server, and gaining direct control over it, and eventually taking control over the entire web site.

####Prevention
SQL injections are usually caused by poorly coded web applications or poorly secured privileges on the backend server and databases. Later on, we will discuss ways to reduce the chances of being vulnerable to SQL injections through secure coding methods like user input sanitization and validation and proper backend user privileges and control.


###Intro to Databases

####Databases
Before we learn about SQL injections, we need to learn more about databases and Structured Query Language (SQL), which databases will use to perform the necessary queries. Web applications utilize back-end databases to store various content and information related to the web application. This can be core web application assets like images and files, web application content like posts and updates, or user data like usernames and passwords.

There are many different types of databases, each of which fits a particular type of use. Traditionally, an application used file-based databases, which was very slow with the increase in size. This lead to the adoption of <span style="color:green"> Database Management Systems (DBMS).<span>

####Database Management Systems

A Database Management System (DBMS) is software that helps create, define, host, and manage databases. Various kinds of DBMS were designed over time, such as file-based, Relational DBMS (RDBMS), NoSQL, Graph based, and Key/Value stores.

There are multiple ways to interact with a DBMS, such as command-line tools, graphical interfaces, or even APIs (Application Programming Interfaces). DBMS are used in various banking, finance, and education sectors to record large amounts of data. Some of the essential features of a DBMS include:


| Feature     | Description          |
| -------- | -------------- |
| <span style="color:green">Concurrency </span>| A real-world application might have multiple users interacting with it simultaneously. A DBMS makes sure that these concurrent interactions succeed without corrupting or losing any data. |
| <span style="color:green">Consistency </span>| With so many concurrent interactions, the DBMS needs to ensure that the data remains consistent and valid throughout the database. |
| <span style="color:green">Security </span>| DBMS provide fine-grained security controls through user authentication and permissions. This will prevent unauthorized viewing or editing of sensitive data.|
| <span style="color:green">Reliability </span>|It's easy to backup databases and roll them back to a previous state in case of data loss or a breach.|
| <span style="color:green">Structured Query Language </span>|SQL simplifies user interaction with the database with an intuitive syntax supporting various operations.|


####Architecture
The diagram below details a two-tiered architecture.

![2 tier Architecture](https://academy.hackthebox.eu/storage/modules/33/db_2.png)


<span style="color:green">Tier I </span> usually consists of client-side applications such as websites or GUI programs. These applications consist of high-level interactions such as user login or commenting. The data from these interactions is passed to <span style="color:green">Tier II </span> through API calls or other requests.

The second tier is the middleware, which interprets these events and puts them in a form required by the DBMS. The application layer uses specific libraries and drivers based on the type of DBMS to interact with them. The DBMS receives queries from the second tier and performs the requested operations. These operations could include insertion, retrieval, deletion, or updating of data. After processing, the DBMS returns any requested data or error codes in the event of invalid queries.

It is possible to host the application server as well as the DBMS on the same host. However, databases with large amounts of data supporting many users are typically hosted separately to improve performance and scalability.


###Types of Databases
Databases, in general, are categorized into <span style="color:green">Relational</span> Databases and <span style="color:green">Non-Relational Databases</span>. Only Relational Databases utilize SQL, while Non-Relational databases utilize a variety of methods for communications.

In relational databases, data is stored in tables, rows, and columns. Each table can have unique keys, which can link tables together and create relationships between tables. For example, we can have a ___users___ table in a relational database containing columns like _id_, _username_, _first_name_, _last_name_, and others.

