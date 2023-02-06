const express = require('express');
const app = express();

//Configure Helmet Using the ‘parent’ helmet() Middleware
let helmet = require('helmet')
//Hackers can exploit known vulnerabilities in Express/Node if they see that your site is powered by Express. X-Powered-By: Express is sent in every request coming from Express by default. Use the helmet.hidePoweredBy() middleware to remove the X-Powered-By header
app.use(helmet.hidePoweredBy());
//Mitigate the risk of Clickjacking, Clickjacking is a technique of tricking a user into interacting with a page different from what the user thinks it is. This can be obtained executing your page in a malicious context, by mean of iframing. In that context a hacker can put a hidden layer over your page. Hidden buttons can be used to run bad scripts. This middleware sets the X-Frame-Options header. It restricts who can put your site in a frame. It has three modes: DENY, SAMEORIGIN, and ALLOW-FROM.
app.use(helmet.frameguard({action: 'deny'}));
//The basic rule to lower the risk of an XSS attack is simple: “Never trust user’s input”. As a developer you should always sanitize all the input coming from the outside. This includes data coming from forms, GET query urls, and even from POST bodies. Sanitizing means that you should find and encode the characters that may be dangerous e.g. <, >.
//helmet.xssFilter() to sanitize input sent to your server
app.use(helmet.xssFilter());
//Avoid Inferring the Response MIME Type with helmet.noSniff()
//Browsers can use content or MIME sniffing to override response Content-Type headers to guess and process the data using an implicit content type. While this can be convenient in some scenarios, it can also lead to some dangerous attacks. This middleware sets the X-Content-Type-Options header to nosniff, instructing the browser to not bypass the provided Content-Type. Use the helmet.nosniff() method on your server
app.use(helmet.noSniff());
//Prevent IE from Opening Untrusted HTML with helmet.ieNoOpen()
//An untrusted HTML page could start doing bad things in the context of your pages. This middleware sets the X-Download-Options header to noopen. This will prevent IE users from executing downloads in the trusted site’s context.
app.use(helmet.ieNoOpen());

//Configure helmet.hsts() to use HTTPS for the next 90 days.
var ninetyDaysInSeconds = 90*24*60*60;
app.use(helmet.hsts({maxAge: ninetyDaysInSeconds, force: true}));

//Disable DNS Prefetching with helmet.dnsPrefetchControl()
//To improve performance, most browsers prefetch DNS records for the links in a page. In that way the destination ip is already known when the user clicks on a link. This may lead to over-use of the DNS service (if you own a big website, visited by millions people…), privacy issues (one eavesdropper could infer that you are on a certain page), or page statistics alteration (some links may appear visited even if they are not). If you have high security needs you can disable DNS prefetching, at the cost of a performance penalty.
app.use(helmet.dnsPrefetchControl());

//Disable Client-Side Caching with helmet.noCache()
//If you are releasing an update for your website, and you want the users to always download the newer version, you can (try to) disable caching on client’s browser. It can be useful in development too. Caching has performance benefits, which you will lose, so only use this option when there is a real need.
app.use(helmet.noCache());

//Set a Content Security Policy with helmet.contentSecurityPolicy()
app.use(helmet.contentSecurityPolicy({directives: {defaultSrc: ["'self'"], scriptSrc:["'self'", "trusted-cdn.com"]}}));




module.exports = app;
const api = require('./server.js');
app.use(express.static('public'));
app.disable('strict-transport-security');
app.use('/_api', api);
app.get("/", function (request, response) {
  response.sendFile(__dirname + '/views/index.html');
});
let port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Your app is listening on port ${port}`);
});
