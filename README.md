# A demo project of securing Angular Web App

A demo project for CORS negotiation and CSRF protection using Spring Boot Security.

<b>Table of Contents:</b>
- [Common misconceptions](#Common-Misconceptions)
- [Build, Run, Test](#Build-Run-Test)
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

However, following 2 categories of cross-origins request are allowed:
- cross-origins writes request in the forms of: links, redirects, and form submissions
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

<br/>

##### Conclusion
If your backend service API is going to be accessed by a custom web app through 
browser, you need CSRF protection definitely.

Read [HERE](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy) 
and [HERE](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
and [HERE](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#warning-no-cross-site-scripting-xss-vulnerabilities)

<br/>

#### What if all the backend API is secured by requiring an OAuth token?
This doesn't change the fact that cross-origin write and read still reach 
the server, it only differs in that way that now the server will validate 
the OAuth token before touching any data.

When it comes to authentication using OAuth 2.0 for a typical single-page-app 
(such as Angular which leverage on client-side technology), the OAuth access 
token/refresh token `must be` stored somewhere in the client device inevitably, 
so that once the user authenticates himself by providing login credentials, 
he doesn't need to provide his credentials again to navigate through the 
website. Either in browser local storage, session storage or cookies.

So this boils down to the next question.

<br/> 

#### Are there any safe places to store the OAuth token
##### Web Browser Storage
Any data stored there is accessible through JavaScript on the same domain. 
This means that any JavaScript running on your site will have access to web 
storage, and because of this can be vulnerable to cross-site scripting (XSS) 
attacks. 

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

##### Cookies
Whereas cookies are often used in web application to identify a user and their 
authenticated session, so stealing a cookie can lead to hijacking the authenticated 
user's session. 

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

### <a name="Build-Run-Test"></a> Build, Run & Test
#### Running app standalone locally
- Maven Wrapper
    ```sh
    ./mvnw clean spring-boot:run
    ```
<br/>

### <a name="references"></a> References
- [Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [Cross-Site Request Forgery](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)
- [Prevent Cross-Site Request Forgery (XSRF/CSRF)](https://docs.microsoft.com/en-us/aspnet/core/security/anti-request-forgery?view=aspnetcore-2.2)
- [Spring Security's Cross Site Request Forgery](https://docs.spring.io/spring-security/site/docs/5.0.x/reference/html/csrf.html)
- [CORS support in Spring Framework](https://spring.io/blog/2015/06/08/cors-support-in-spring-framework)
- [Spring Security and Angular](https://spring.io/guides/tutorials/spring-security-and-angular-js/)
- [Spring Session](https://docs.spring.io/spring-session/docs/current/reference/html5/guides/boot-redis.html)
