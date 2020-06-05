# bitfire
Enterprise class security for Everyone. Web Application Firewall with highly efficient filtering, granular reporting, javascript based bot filtering.

Stop worms, web defacements, malware and other malicious activity on your website.

highly efficient filtering runs in <3ms on most servers.
Block rate for AWS T2 servers >120 HTTP blocks per second.
Filtering for ALL bot traffic.  Bot IP address filtering and human javascript verification ensures that all malicious bots are blocked.
add multi factor (SMS based) authentication for up to 10 site admins
whitelisted MFA users means admins won't have restricted access
filter all HTML tags and javascipt onX events as well as DOM injection for popular frameworks like angular, vuejs, etc
intelligent parsers understand your request (we use <10 regular expressions for filtering)
customizable profanity filter
customizable spam list filter
over 2,000 unique SQL injections and over 10,000 unique XSS injections run in our internal filter tests
learning WAF slowly locks your site down to just your valid traffic from verified human users
new contant can be added to locked sites by just visiting the page from a trusted account
transparent CSRF protection and filtering
fast country based IP filtering
daily updated IP block lists

functional programming design with moslty pure functions and full code coverage gives you peace of mind that your code is solid.


## OWASP top 10 features (honest info)

#1: injection *2:
out of the box we block all html tags and javascript attributes for XSS protection with whitelisting single url and parameter combinations for any valid pages or trusted users.  We have robust SQL detection that actually parses input for SQL and fails the request.  We also filter any local file paths such as /bin/foobar, /etc/foobar, /sbin/foobar, C:\boot.ini, cmd.exe, etc.  BitFIRE not currently offer LDAP filtering. Drop a feature request in #issues if this is something you would like to see.

#2: broken authentication *3:
We don't provide additional authentication services for your end users.  We do however provide MFA authentication for access to your site administration area (wp-admin for eaxmple) and provide filtering for only MFA authenitcated users to access these areas.  This prevents credential stuffing and account takeover for your site administrators.

#3: sensative data exposure *1:
We do offer data loss prevention for Credit Card numbers and Social Security numbers.  This feature is not enabled by default and has a noticable performance impact as all rendered web pages must be inspected for credit card numbers or other data before serving them.  We also over custom filtering but do not recomend this for the majority of BitFIRE users.

#4: XML entities *2:
Like our Free Forever*3 bot filtering, we do offer xml entity protection on all requests

#5: Broken Access Control *2:
Access control services are beyond the scope of even the most advanced firewall.  That's just not what they do.  Anyone who tells you their Firewall provides "fixed" access control for your website, is being less then fully open.

#6: Security Misconfiguration *2:
We do provide some security configuration guidance.  For instance we add HTTP security headers to all requests locking them down to best pracctices as well as audit your PHP configuration and provide ini settings suggestions.  We do not alter or fix your operating system configuration, SSL configuration or any security configuration outside of HTTP headers and PHP settings.  Anyone who tells you their firewall solved all security misconfigurations is not telling you the entire truth.

#7: Cross Site Scripting *1:
We have a robust testing suite with over 10,000 unique XSS attacks each relase must pass and add to it every month.  Cross site scripting protection is part of our Free Foreever *3 filtering.

#8: Insecure deserialization *1:
This is an insidious security issue that can be difficult to fully protect from and has plagued the Java and PHP communities for years.  We include deserialization filtering in our Free Forever filtering and prevent all known deserialization bugs across raw, urlencoded and uploaded files.  Because deserialization is such a complex attack vector we recommend your application not support php deserialization and provide code auditing functionality to restrict it in your code base.

#9: Using components with known vulnerabilities *2:
We are currently developing this feature to add to our core product offering.  Expect first release to support WordPress and Joomla sites as well as npm modules via package.json files.  We plan to cross reference known out of date software with the CVE project to deliver actionalbe information.  Long terms plans begining in 2021 are to add auto update functionality for wordpress and joomla sites.

#10: Insufficient Logging and Monitoring *3:
Fortunately you can buy this.  We log all blocked traffic in elastic search and you can see each blocked request and inspect exactly why it was blocked.

*1: Free Forever - Our free forever services are full unmetered filtering available to all of your servers free of charge
*2: Premium Filtering - Premium filtering features are available free of change for 500 unique visitors each month. 
*3: MFA / Logging - Multifactor and Logging features require server resources and unformtunately we are unable  to provide these features to the community for free.
