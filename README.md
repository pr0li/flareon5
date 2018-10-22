# FlareOn5 writeup: level 4, binstall.exe

It all starts with binstall.exe. I go ahead and execute the installer, catching events with ProcMon and ProcExp. I can see that both Firefox and Chrome had their caches emptied (though this doesn't seem to have any effect on further analysis).

Most importantly, a dll is dumped and AppInit_DLLs registry key is added to point to that dll (written to ```%APPDATA%\Microsoft\Internet Explorer\browserassist.dll```). This is familiar to me, as I've written about this injection technique in the past. To sum it up, every user mode process on the system that makes use of User32.dll will have AppInit_DLLs loaded into its address space. I open cmd and attach to it with Olly. Not surprisingly, I find browserassist.dll loaded in there.

![injected DLL](https://github.com/pr0li/flareon5/blob/master/img/01.png)

Now I'm quite sure I need to open Firefox and have that dll injected into it, as this browser is mentioned in the instructions for the challenge. In order to catch execution of that dll before it even gets to Firefox's entry point, I set up Olly like this:

```
Options>Options...>Debugging>Start>System breakpoint
Options>Options...>Debugging>Events>Pause on new module (DLL)
```

Then I drop firefox.exe into Olly and keep pressing F9 to continue execution until I reach the entry point of browserassist.dll. I uncheck "Pause on new module" because it can get pretty annoying later on. I check with IDA and there doesn't seem to be anything interesting until a thread is created for subroutine labeled as StartAddress. A few instructions before that there's a call to GetModuleFilenameA. The result is hashed and compared to some constant. I know it's gotta be firefox :)

I continue debugging and confirm my hypothesis but then I find some calls to check Firefox's version. I notice that I can just patch one single jump and keep going. A new thread is created and my breakpoint on StartAddress is hit. Note: for some reason, if I keep going, debugging this new thread, Olly freezes at some point. So I kill the main thread before I continue debugging and everything seems to go well :)

There seem to be some decryption and Internet routines ahead. I also see GetModuleFilename again in there, so it might be used as the decryption key or something. I don't really check, I just keep going until I have to stop. So, a URL is decrypted (http://pastebin.com/raw/hvaru8NU) and some encrypted text is pulled from there. That text is decrypted and we get something really pretty :)

![decrypted text](https://github.com/pr0li/flareon5/blob/master/img/02.png)

It is TinyNuke's configuration for webinjects (https://github.com/rossja/TinyNuke/blob/master/panel/private/injects.json). That decrypted configuration is big and I get lost in between js code at first (see file config.json). So I decide to just go see those injections in action. I use a json beautifier and see that the most important fields at this point are those that tell us which sites and files will be injected:

```
"path": "/js/controller.js",
"host": "*flare-on.com"

"path": "/js/model.js",
"host": "*flare-on.com"

"path": "/js/view.js",
"host": "*flare-on.com"
```

If I continue debugging, there's not much to mention, except that nss3.dll, nspr4.dll, PR_Read and PR_Write strings are decrypted. Yes, those are used to read which site is being visited and inject js code accordingly.

So I hit F9 and find out that killing that main thread was not going to be flawless. Anyway, I don't need Olly anymore, so I permanently patch the dll. To be able to modify the file, I set the registry key LoadAppInit_DLLs to zero. Then I close everything I had open. I proceed to change "cmp eax, 1" to "cmp eax, 0". In other words, change 83 F8 01 to 83 F8 00.

![firefox version check](https://github.com/pr0li/flareon5/blob/master/img/03.png)

![patching comparison](https://github.com/pr0li/flareon5/blob/master/img/04.png)

After changing that registry key back to 1, I visit flare-on.com and use Firefox's debugger to see that the code has actually been injected in model, view and controller. Now there is a new command "su" that asks for a password. The function cp() has been added to controller.js to check for a valid password. After some necessary beautifying, here's the portion of cp() that checks for a valid password:

```javascript
function cp(p) {
    if (model.passwordEntered = !1, 10 === p.length && 123 == (16 ^ p.charCodeAt(0)) && p.charCodeAt(1) << 2 == 228 && p.charCodeAt(2) + 44 === 142 && p.charCodeAt(3) >> 3 == 14 && p.charCodeAt(4) === parseInt(function() {
            var h = Array.prototype.slice.call(arguments),
                k = h.shift();
            return h.reverse().map(function(m, W) {
                return String.fromCharCode(m - k - 24 - W)
            }).join("")
        }(50, 124) + 4..toString(36).toLowerCase(), 31) && p.charCodeAt(5) - 109 == -22 && 64 == (p.charCodeAt(3) << 4 & 255) && 5 * p.charCodeAt(6) === parseInt(function() {
            var n = Array.prototype.slice.call(arguments),
                M = n.shift();
            return n.reverse().map(function(r, U) {
                return String.fromCharCode(r - M - 16 - U)
            }).join("")
        }(22, 107) + 9..toString(36).toLowerCase(), 19) && p.charCodeAt(7) + 14 === "xyz".charCodeAt(1) && 3 * (6 * (p.charCodeAt(8) - 50) + 14) == 17 + parseInt(function() {
            var l = Array.prototype.slice.call(arguments),
                f = l.shift();
            return l.reverse().map(function(O, o) {
                return String.fromCharCode(O - f - 30 - o)
            }).join("")
        }(14, 93) + 6..toString(36).toLowerCase(), 8) - 1 + 12 && 3 + (p.charCodeAt(9) + 88 - 1) / 2 === p.charCodeAt(0)) model.root = 1, model.password = p;
    
    view.addCmd()
}
```

We see that a valid password must be 10 characters long and it is possible to go char by char, finding each char by solving equations.

Some of the characters can be found by solving a single expression. For example:
123 == (16 ^ p.charCodeAt(0))

Then, ```p.charCodeAt(0) = 107 = 'k'```

Other characters have been shifted to the left or right, and so there may be more than one possible solution:

p.charCodeAt(1) << 2 == 228

Then, p.charCodeAt(1) = xx11 1001 = 39h, 79h, B9h, F9h
Only 39h and 79h make sense as user input.
So, ```p.charCodeAt(1) = '9' or 'y'```

For p[3] we have two expressions with shifts, but they produce a single result:

p.charCodeAt(3) >> 3 == 14

64 == (p.charCodeAt(3) << 4 & 255)

So, (p.charCodeAt(3) == 70h to 77h) && (p.charCodeAt(3) == 04h, 14h, ... , F4h)
The only value that satisfies this is 74h = 't'

Finally, p[4], p[6] and p[8] have a function definition that can be solved by assigning the return value to a variable. I used W3Schools Online Code Editor (https://www.w3schools.com/html/tryit.asp?filename=tryhtml_script) to get to try the code fast.

The password is 'k9btBW7k2y'. With that password, now we are root. Note: for some reason I initially got confused and thought that p[4], p[6] and p[8] could not be solved and needed to be brute forced. So I made a script to brute force those 3 characters. It is unnecesary but I'll leave the code in ```passBruteForce.html``` in case anyone finds it amusing.

Command cd has also been injected and if we cd to the secret dir, we'll get our flag. The part of the code that checks this is here:

```javascript
if (dir === (function() {
        var Q = Array.prototype.slice.call(arguments),
            f = Q.shift();
        return Q.reverse().map(function(M, m) {
            return String.fromCharCode(M - f - 50 - m)
        }).join('')
    })(57, 214) + (14).toString(36).toLowerCase() + (function() {
        var B = Array.prototype.slice.call(arguments),
            N = B.shift();
        return B.reverse().map(function(q, J) {
            return String.fromCharCode(q - N - 36 - J)
        }).join('')
    })(59, 216) && model.root === 1)
```

Just make that comparison an assignment and you got yourself the secret directory, which happens to be 'key'. I'll leave that code in ```GetDir.html```.

Finally I execute 'cd key' to get the flag:

![challenge solved](https://github.com/pr0li/flareon5/blob/master/img/05.png)

Cool challenge!
