# bitfire
## Enterprise class security for Everyone. 

**True learning Web Application Firewall learns your website and filters input to only allow valid behaviors.**
**Stop worms, web defacements, bots, spam, malware and other malicious activity on your website.**

* highly efficient filtering runs in <2ms on most servers.
* Block rate for AWS T2 micro servers >120 full HTTP blocks per second.
* Blocks ALL bots, only allows from trusted networks (google, bing, facebook, etc)
* Javascript challenge protection to verify real webbrowsers from scanners
* filter all HTML tags, javascipt "on" events as well as DOM injection for popular frameworks like angular, vuejs, etc.
* intelligent parsers understand web requests (we use <10 regular expressions for filtering)
* customizable profanity filter
* customizable spam list filter
* over 2,000 unique SQL injections and over 10,000 unique XSS injections run in our internal filter tests
* transparent CSRF protection and filtering

functional programming design with >90% pure functions ensures stable firewall operation


## OWASP top 10 breakdown
 
### 1: injection *2:
out of the box BitFIRE can block all html tags and javascript attributes for XSS protection with whitelisting single url and parameter combinations for any valid pages or trusted users.
Robust SQL detection parses input as actual SQL.  BitFIRE also filters local file paths such as /bin/foobar, /etc/foobar, /sbin/foobar, C:\boot.ini, cmd.exe, etc.  BitFIRE does NOT currently offer LDAP filtering since this is such a rare configuration.

### 2: broken authentication *3:
We don't provide additional authentication services for your end users.  We do however provide MFA authentication for access to your site administration area (wp-admin for example) and provide filtering for only MFA authenticated users to access these areas.  This prevents credential stuffing and account takeover for your site administrators and other sensitive accounts.

### 3: sensitive data exposure *1:
We do offer data loss prevention for Credit Card numbers and Social Security numbers.  This feature is not enabled by default and has a noticeable performance impact as all rendered web pages must be inspected for credit card numbers or other data before serving them.  We also offer custom output filtering but do not recommend this for the majority of BitFIRE users.

### 4: XML entities *2:
Like our Free Forever bot filtering, BitFIRE has xml entity protection on all requests

### 5: Broken Access Control *2:
Access control services are beyond the scope of even the most advanced firewall.  That's just not what they do.  Anyone who tells you their Firewall provides "fixed" access control for your website, is being less then fully transparent.

### 6: Security Misconfiguration *2:
BitFIRE provides security configuration guidance. For instance we add HTTP security headers to all requests locking them down to best practices as well as audit your PHP configuration and provide setting suggestions.
We do not alter or fix operating system configurations, SSL configuration or any security configuration outside of HTTP headers and PHP settings.  Anyone advertising a PHP firewall to fix all security misconfigurations is exaggerating.


### 7: Cross Site Scripting *1:
BitFIRE has a robust testing suite with over 10,000 unique XSS attacks each release must pass and additional tests are added every month.  Cross site scripting protection is part of our Free Foreever *3 filtering.

### 8: Insecure deserialization *1:
This is an serious security issue that can be difficult to fully protect from and has plagued the Java and PHP communities for years.  We include deserialization filtering in our Free Forever filtering and prevent all known deserialization bugs across raw, urlencoded and uploaded files.  Because deserialization is such a complex attack vector we recommend your application not support php deserialization and provide code auditing functionality to restrict it in your code base.

### 9: Using components with known vulnerabilities *2:
We are currently developing this feature to add to our core product offering.  Expect first release to support WordPress and Joomla sites as well as npm modules via package.json files.  We plan to cross reference known out of date software with the CVE project to deliver actionable information.  Long terms plans for 2021 are to add auto update functionality for wordpress and Joomla sites.

### 10: Insufficient Logging and Monitoring *3:
Fortunately you can buy this.  We log all blocked traffic in elastic search and you can see each blocked request and inspect exactly why it was blocked.

_*1: Free Forever_ - Our free forever services are full un-metered filtering available to all of your servers free of charge

_*2: Premium Filtering_ - Premium filtering features are available free of change for 500 unique visitors each month. 

_*3: MFA / Logging_ - Multifactor and Logging features require server resources and unfortunately we are unable  to provide these features to the community for free.
