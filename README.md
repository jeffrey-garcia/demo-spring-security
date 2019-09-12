# A demo project of securing Angular Web App

A demo project for CORS negotiation and CSRF protection using Spring Boot Security.

<b>Table of Contents:</b>
- [Common misconceptions](#Common-Misconceptions)
- [Build, Run, Test](#Build-Run-Test)
- [References](#references)

<br/>

### <a name="Common-Misconceptions"></a> Common misconceptions

#### Why do we need CSRF when we have already disabled CORS?
Same Origin Policy (SOP) is a browser-level security control 
which prevents scripts running under one origin to read data 
from another origin.
```
While READ from another origin is not permitted, cross-domain WRITE requests are still permitted, 
```

Cross-domain write requests are typically allowed, examples are:
- XMLHttpRequest (POST)
- Form Submissions
- Links
- Redirects

In short, performing a CSRF attack on a vulnerable site which 
results in server-side state change (e.g. user creation, document 
deletion etc), the attack will be successful but the attacker would 
not be able to read the response.

Read [HERE](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy) 
and [HERE](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
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

#### Aren't anti-CSRF token itself vulnerable to XSS attack?
CSRF token itself is delivered from the server to browser via cookies to trusted domain. 
In order for the web app to attach it into every subsequent request it sent to the server, 
the `HttpOnly` cookie attribute can't be set to true such that the javascript of the web app 
can access it. 

Having said that, the CSRF token is vulnerable to XSS attack again, so it's a 
chicken-and-egg problem here. A way to mitigate this problem is to set the CSRF 
token to a digest of your site's authentication cookie with a salt for added security.

Read [HERE](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#warning-no-cross-site-scripting-xss-vulnerabilities)
and [HERE](https://v5.angular.io/guide/http#security-xsrf-protection)

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
