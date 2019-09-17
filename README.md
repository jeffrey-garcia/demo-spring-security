# A demo project of securing Angular Web App

A demo project for CORS negotiation and CSRF protection using Spring Boot Security.

<b>Table of Contents:</b>
- [Common misconceptions](#Common-Misconceptions)
- [Solution](#Solution)
- [Build, Run, Test](#Build-Run-Test)
- [Debug-Locally](#Debug-Locally)
- [References](#references)

<br/>

### <a name="Common-Misconceptions"></a> Common misconceptions

#### Why do we need CSRF when we have SOP?
##### Same Origin Policy
For security reasons, browsers restrict cross-origin HTTP requests initiated 
from scripts. For example, XMLHttpRequest follow the `same-origin policy`. 
This means that a web application making AJAX call can only request resources 
from the same origin the application was loaded from, unless the response from 
other origins includes the right CORS headers.

However, following 2 categories of cross-origins requests are allowed:
- cross-origins writes request in the forms of: links, redirects, and http form submissions
- cross-origins embedding resources, such as:
    - JavaScript with `<script src="…"></script>`
    - CSS applied with `<link rel="stylesheet" href="…">`
    - Images displayed by `<img>` 
    - Media played by `<video>` and `<audio>`
    - Plugins embedded with `<object>`, `<embed>`, and `<applet>`
    - Fonts applied with `@font-face`. Some browsers allow cross-origin fonts, others require same-origin.
    - Anything embedded by `<frame>` and `<iframe>`. Sites can use the X-Frame-Options header to prevent cross-origin framing.

<br/>

##### CSRF
Cross-Site Request Forgery (CSRF), on the other hand is a type of attack that 
occurs when a malicious web site, email, blog, instant message, or program causes 
a user's web browser to perform an unwanted action on a trusted site when the user 
is authenticated. A CSRF attack works because browser requests automatically include 
any credentials associated with the site, such as the user's session cookie, IP 
address, etc. Therefore, if the user is authenticated to the site, the site cannot 
distinguish between the forged or legitimate request sent by the victim. We would 
need a token/identifier that is not accessible to attacker and would not be sent 
along (like cookies) with forged requests that attacker initiates. 

To prevent `cross-origin writes`, check an unguessable token in the request: 
known as a Cross-Site Request Forgery (CSRF) token, and you must prevent cross-origin 
reads of pages that require this token.

CSRF attacks are possible against web apps that use cookie-based authentication 
because:
- Browsers store cookies issued by a web app.
- Stored cookies include session cookies for authenticated users.
- Browsers send all of the cookies associated with a domain to the web app 
every request regardless of how the request to app was generated within the 
browser.


Read [HERE](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy) 
and [HERE](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
and [HERE](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#warning-no-cross-site-scripting-xss-vulnerabilities)

<br/>

#### What if all the backend API is secured by requiring an OAuth token instead of session cookie?

##### Cookie-based authentication
When a user authenticates using their username and password, they're 
issued a token, containing an authentication ticket that can be used 
for authentication and authorization. The token is stored as a cookie 
that accompanies every request the client makes. 

If your backend service API is using cookie-based authentication and is  
going to be accessed by a custom web app through browser, you need CSRF 
protection definitely. And in order to use the Spring Security CSRF protection, 
we must make sure we use proper HTTP methods for anything that modifies 
state (PATCH, POST, PUT, and DELETE – not GET).

Common ways to steal cookies include Social Engineering or exploiting an XSS 
vulnerability in the application. Although `HttpOnly` cookie attribute can help to 
mitigate this attack by preventing access to cookie value through JavaScript 
(together with `Secure` attribute that enforces the cookie is only sent via HTTPS),
the real problem is that browser by-design automatically send all previous stored 
cookies with every request it made to the server in same origin, and that's why usage 
of cookies in web app is vulnerable to CSRF attack.

Read [HERE](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)
and [HERE](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

<br/>

##### Token-based authentication
When it comes to token-based authentication, the token `must be` stored 
somewhere in the client device. When a user attempts to access a resource 
requiring authentication, the token is sent to the server with an additional 
authorization header in form of Bearer token. This makes the app stateless. 
To send the token on subsequent requests, store the token in the browser's 
local storage. 

Don't be concerned about CSRF vulnerability if the token is stored in the 
browser's local storage. CSRF is a concern when the token is stored in a 
cookie.

However, this boils down to the next question.

<br/> 

#### Are Web Browser Storage safe place to store the authentication token
Any data stored there is accessible through JavaScript on the same domain. 
This means that any JavaScript running on your site will have access to web 
storage, and because of this can be vulnerable to cross-site scripting (XSS) 
attacks. 

##### Secutiry Threat
- any authentication your app requires can be bypassed by a user with local 
privileges to the machine on which the data is stored. Therefore, it's 
recommended not to store any sensitive information in local storage.

- Use the object sessionStorage instead of localStorage if persistent storage 
is not needed. sessionStorage object is available only to that window/tab 
until the window is closed.

- A single Cross Site Scripting can be used to steal all the data in these 
objects, so again it's recommended not to store sensitive information in 
local storage.

- A single Cross Site Scripting can be used to load malicious data into 
these objects too, so don't consider objects in these to be trusted.

- Do not store session identifiers in local storage as the data is always 
accesible by JavaScript. 

##### Types of attack
Such attack can be materialized in following ways:
- Modern web apps include 3rd party massive numbers of JavaScript libraries, 
package managers like `npm` imports other peoples’ code into web apps. The 
malicious script can easily read the tokens from there and send them to a 
remote server. There on-wards the remote server or attacker would have no 
problem in impersonating the victim user.

- Resources embedding (script tags/CSS/image tags hosted on different domains) 
into web app, such as 3rd party JavaScript libraries for A/B testing, market 
analytics, ads.

- Usage of JavaScript hosted on CDNs or outside infrastructure poses another potential 
threat 

Web browser storage (local or session storage) is not really a secure place to store 
sensitive information.
 
Read [HERE](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.md#token-sidejacking)
and [HERE](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/HTML5_Security_Cheat_Sheet.md#local-storage)

<br/>

#### Aren't anti-CSRF token itself vulnerable to XSS attack?
CSRF token itself is delivered from the server to browser via cookies to trusted domain. 
In order for the web app to attach it into every subsequent request it sent to the server, 
the `HttpOnly` cookie attribute can't be set to true such that the javascript of the web 
app can access it.

Having said that, the CSRF token itself is vulnerable to XSS attack again, the CSRF token 
itself can be exploit so the attacker can still initiate a CSRF attack if the web app 
itself is not completely sealed away from XSS vulnerabilities.

This is a chicken-and-egg problem here. A way to mitigate this problem is to set the CSRF 
token to a `digest` of your backend authentication cookie with a salt for added security.

Read [HERE](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#warning-no-cross-site-scripting-xss-vulnerabilities)
and [HERE](https://v5.angular.io/guide/http#security-xsrf-protection)

<br/>

#### Can we handle request error due to CORS failure programmatically?
CORS failures result in errors, but for security reasons, specifics about the 
error are not available to JavaScript. All the code knows is that an error 
occurred. The only way to determine what specifically went wrong is to look at 
the browser's console for details.

<br/> 

### <a name="Solution"></a> Solution
- Rely on SOP to provide the default cross-origin access policy in browser
- Enable CORS to enforce cross-origins read/write/form-post only for allowed domain
- Enable CSRF token for root/sub-domains 
- Enable login session using spring-session and Redis to facilitate horizontal scaling
  (by default the CSRF token is stored inside the HTTP session, and the
  HTTP session is replicated over all the backend instances)

<br/>

#### Exepcted Behavior
The following tables illustrate the comparison matrix for various combination of protection technique.

##### HTTP GET
| Scenario | SOP [x]<br/>CORS [ ]<br/>Session [ ]<br/>CSRF [ ] | SOP [x]<br/>CORS [x]<br/>Session [ ]<br/>CSRF [ ] | SOP [x]<br/>CORS [x]<br/>Session [x]<br/>CSRF [ ] | SOP [x]<br/>CORS [x]<br/>Session [x]<br/>CSRF [x] |
| :--- | :--- | :--- | :--- | :--- | 
| same origin request | Success | Success |  |  |
| cross-origins request | Fail* | Fail* |  |  |
| cross-origins request <br/> (allowed in CORS policy) |  | Success |  |  |
| cross-origins request with authentication |  |  | Fail* |  |
| cross-origins request with authentication <br/> (allowed in CORS policy) |  |  | Success |  |
| cross-origins request with authentication and CSRF token |  |  |  | Fail* |
| cross-origins request with authentication and CSRF token <br/> (allowed in CORS policy)  |  |  |  | Success |

`*` Declined by CORS policy

##### HTTP POST
| Scenario | SOP | SOP<br/>CORS Policy | SOP<br/>CORS Policy<br/>Session | SOP<br/>CORS Policy<br/>Session<br/>CSRF |
| :--- | :--- | :--- | :--- | :--- | 
| same origin request | Success | Success |  |  |
| cross-origins request | Fail* | Fail* |  |  |
| cross-origins request <br/> (allowed in CORS policy) |  | Success |  |  |
| cross-origins request with authentication |  |  | Fail* |  |
| cross-origins request with authentication <br/> (allowed in CORS policy) |  |  | Success |  |
| cross-origins request with authentication and CSRF token |  |  |  | Fail* |
| cross-origins request with authentication and CSRF token <br/> (allowed in CORS policy)  |  |  |  | Success |

`*` Declined by CORS policy

##### HTTP FROM POST
| Scenario | SOP | SOP<br/>CORS Policy | SOP<br/>CORS Policy<br/>Session | SOP<br/>CORS Policy<br/>Session<br/>CSRF |
| :--- | :--- | :--- | :--- | :--- | 
| same origin request | Success | Success |  |  |
| cross-origins request | <font color='red'>Success</font> | Fail* |  |  |
| cross-origins request <br/> (allowed in CORS policy) |  | Success |  |  |
| cross-origins request with authentication |  |  | Fail* |  |
| cross-origins request with authentication <br/> (allowed in CORS policy) |  |  | Success |  |
| cross-origins request with authentication and CSRF token |  |  |  | Fail* |
| cross-origins request with authentication and CSRF token <br/> (allowed in CORS policy)  |  |  |  | Success |

`*` Declined by CORS policy

This proves that hardening of CORS policy to tighten the acceptance of cross-origins requests from 
legitimate domain/host is the first-line of defense to effectively block CSRF attack, regardless if 
CSRF token exist.

<br/>

### <a name="Build-Run-Test"></a> Build, Run & Test
#### Running app standalone locally
- Maven Wrapper
    ```sh
    ./mvnw clean spring-boot:run
    ```
<br/>

### <a name="Debug-Locally"></a> Debugging Spring-Session Locally
#### Install Redis
To develop/debug locally, install Redis.

On a Mac with homebrew:
```sh        
brew install redis
```
Once completed, launch it with default settings.
```sh
redis-server
``` 

<br/>

#### Remove all sessions by using redis-cli
On a Mac computer
```sh
redis-cli keys '*' | xargs redis-cli del
```

<br/>

### <a name="references"></a> References
- [Cross-Site Scripting Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [Cross-Site Request Forgery](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)
- [Prevent Cross-Site Request Forgery (XSRF/CSRF)](https://docs.microsoft.com/en-us/aspnet/core/security/anti-request-forgery?view=aspnetcore-2.2)
- [Spring Security's Cross Site Request Forgery](https://docs.spring.io/spring-security/site/docs/5.0.x/reference/html/csrf.html)
- [CORS support in Spring Framework](https://spring.io/blog/2015/06/08/cors-support-in-spring-framework)
- [Spring Security and Angular](https://spring.io/guides/tutorials/spring-security-and-angular-js/)
- [Spring Session](https://docs.spring.io/spring-session/docs/current/reference/html5/guides/boot-redis.html)
