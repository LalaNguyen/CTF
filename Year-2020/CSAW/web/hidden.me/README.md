**Knowledge**:
- Node JS (for prototype testing)

**Task**: Find the flag, given a website with a submission form. 

**Investigation**:

When we investigated the source file, we saw the hint "<!-- zwsp is fun!-->". ZWSP is a short form of Zero-width space. ZWSP characters are not printable, so we cannot see them.
Hence, it is best to download the webpage and examines its hex or binary form, instead of the text form. The quickest way is to tell the server to
encode the returning page as binary directly in the script, and then print out all the page content.

It is visible that the ZWSP chars are padded to the end of this html file.
```bash
</html>âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
```

How do we decode this? Actually, we did not need to understand how ZWSP decoding works. Instead, we used the existing zwsp-steg to decode the content. Let's change back the encoding to "utf8".
What we had was the following:

```bash
</html>
b'YWxtMHN0XzJfM3o='
```

A simple base64 conversion gives us `YWxtMHN0XzJfM3o= --> alm0st_2_3z`, which unfortunately was not the flag. What should we do next, then? Well, we did not use the form.
Let's put the text into the form and submit it. Once done, we were presented with the following string:

```bash
/ahsdiufghawuflkaekdhjfaldshjfvbalerhjwfvblasdnjfbldf/<pwd>
```

It looked like a url path, but what is the <pwd> ? Possibly the `alm0st_2_3z`. We visited the path `http://web.chal.csaw.io:5018/ahsdiufghawuflkaekdhjfaldshjfvbalerhjwfvblasdnjfbldf/alm0st_2_3z`
and found a new webpage, which seems to use ZWSP to hide the information as well. It also confirms that the pwd is `alm0st_2_3z` It also confirms that `alm0st_2_3z` is the pwd. Repeating the same steps above, we obtain the next hex number `755f756e6831645f6d33` which can be translated to `u_unh1d_m3`.
Similarly, we put the `u_unh1d_m3`, which is perhap the second pwd. Indeed, we were presented with the following string once we submitted the second pwd:

```bash
/19s2uirdjsxbh1iwudgxnjxcbwaiquew3gdi/<pwd1>/<pwd2>
```

We filled in the pwd1 and pwd2 accordingly, and obtained the flag `flag{gu3ss_u_f0und_m3}`.




