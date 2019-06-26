
# Artisinal Hand-Crafted HTTP 3

This is a 300-point PicoCTF 2018 Web problem. It's basically a lesson in writing HTTP3 GET and POST requests by hand.

### Problem description

We found a hidden flag server hiding behind a proxy, but the proxy has some... _interesting_ ideas of what qualifies someone to make HTTP requests. Looks like you'll have to do this one by hand. Try connecting via `nc 2018shell.picoctf.com 17643`, and use the proxy to send HTTP requests to `flag.local`. We've also recovered a username and a password for you to use on the login page: `realbusinessuser`/`potoooooooo`.


### Solution

I kept notes of my progress and am completing the write-up after the competition, when the server hosting this problem is down. But as I recall, netcatting to that host and port provides the user with a prompt to then enter HTTP GET and POST requests by hand.

For awhile I tried sending requests such as `GET /flag.local HTTP/1.1`, which all failed. Then I realized that the _host_, not the page, is supposed to be `flag.local`.

Next, I sent:

```
GET / HTTP/1.1
Host: flag.local
Referer: flag.local/
```

and received in response:

```
HTTP/1.1 200 OK
x-powered-by: Express
content-type: text/html; charset=utf-8
content-length: 321
etag: W/"141-LuTf9ny9p1l454tuA3Un+gDFLWo"
date: Thu, 04 Oct 2018 12:15:29 GMT
connection: close


		<html>
			<head>
				<link rel="stylesheet" type="text/css" href="main.css" />
			</head>
			<body>
				<header>
					<h1>Real Business Internal Flag Server</h1>
					<a href="/login">Login</a>
				</header>
				<main>
					<p>You need to log in before you can see today's flag.</p>
				</main>
			</body>
		</html>
```

Great! That was pretty much the hardest part of the problem for me. Now, let's go to the login page.

```
GET /login HTTP/1.1
Host: flag.local
Referer: flag.local/


HTTP/1.1 200 OK
x-powered-by: Express
content-type: text/html; charset=utf-8
content-length: 498
etag: W/"1f2-UE5AGAqbLVQn1qrfKFRIqanxl9I"
date: Thu, 04 Oct 2018 12:17:10 GMT
connection: close


		<html>
			<head>
				<link rel="stylesheet" type="text/css" href="main.css" />
			</head>
			<body>
				<header>
					<h1>Real Business Internal Flag Server</h1>
					<a href="/login">Login</a>
				</header>
				<main>
					<h2>Log In</h2>

					<form method="POST" action="login">
						<input type="text" name="user" placeholder="Username" />
						<input type="password" name="pass" placeholder="Password" />
						<input type="submit" />
					</form>
				</main>
			</body>
		</html>
```

Okay, I need to make a POST request. Remember that for these, the `content-length` must be equal to the length of the posted information.

```
POST /login HTTP/1.1
Host: flag.local
Referer: flag.local/login
Content-Length: 52
Content-Type: application/x-www-form-urlencoded

user=realbusinessuser&pass=potoooooooo&submit=submit
```

gives me:

```
HTTP/1.1 302 Found
x-powered-by: Express
set-cookie: real_business_token=PHNjcmlwdD5hbGVydCgid2F0Iik8L3NjcmlwdD4%3D; Path=/
location: /
vary: Accept
content-type: text/plain; charset=utf-8
content-length: 23
date: Thu, 04 Oct 2018 12:37:58 GMT
connection: close
```

Great, now I have a login cookie. Let's go back to the main page with that cookie set and setting the `Referer` field to the login page:

```
GET / HTTP/1.1
Host: flag.local
Referer: flag.local/login
Cookie: real_business_token=PHNjcmlwdD5hbGVydCgid2F0Iik8L3NjcmlwdD4%3D; Path=/
```

gives me the flag:

```
HTTP/1.1 200 OK
x-powered-by: Express
content-type: text/html; charset=utf-8
content-length: 438
etag: W/"1b6-im2R+pSFSyMdILdzGNXpRLS7woM"
date: Thu, 04 Oct 2018 12:39:13 GMT
connection: close


		<html>
			<head>
				<link rel="stylesheet" type="text/css" href="main.css" />
			</head>
			<body>
				<header>
					<h1>Real Business Internal Flag Server</h1>
					<div class="user">Real Business Employee</div>
					<a href="/logout">Logout</a>
				</header>
				<main>
					<p>Hello <b>Real Business Employee</b>!  Today's flag is: <code>picoCTF{0nLY_Us3_n0N_GmO_xF3r_pR0tOcol5_6f21}</code>.</p>
				</main>
			</body>
		</html>
```

And that is that.

### Comparison to other approaches

Some other write-ups such as [this one](https://github.com/Dvd848/CTFs/blob/master/2018_picoCTF/Artisinal%20Handcrafted%20HTTP%203.md) did not include `submi=submit` in the POST request, and they still got the login cookie back:

```
POST /login HTTP/1.1
Host: flag.local
Referer: flag.local/login
Content-Length: 52
Content-Type: application/x-www-form-urlencoded

user=realbusinessuser&pass=potoooooooo&submit=submit
```

Other than that, the approaches are all the same, as there really isn't much room for artistic license despite the artisinal nature of this problem.
