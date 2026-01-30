# Nginx WAF

In this lab, you will configure WAF functionality in NGINXaaS and run some common attacks and see how the WAF blocks them.

## Pre-Requisites

- You must have your Nginx for Azure instance running
- Your Nginx for Azure instance must be running with the "plan:standardv3" SKU
- You must have selected "Enable F5 WAF for NGINX" when creating the Nginx for Azure instance
- You must have your AKS1 Cluster running
- See `Lab0` for instructions on setting up your system for this Workshop
- Familiarity with basic Linux commands and commandline tools
- Familiarity with basic HTTP protocol
- JuiceShop deployed in AKS cluster and exposed with Nginx Ingress Controller

The following steps will guide you through adding a Web Application Firewall (WAF) Policy.
These steps will apply a preconfigured WAF policy to the load balancer created previously.
[include image from https://github.com/nginxinc/nginx-azure-workshops/blob/main/labs/lab9/media/lab9_diagram.png, but with minor changes to make it show WAF]

# Protecting Applications with NGINX WAF
[include image from https://github.com/nginxinc/nginx-azure-workshops/raw/main/labs/lab9/media/nginx-cache-icon.png]

## Test Application Vulnerabilities

Prior to configuring the WAF policy, run some common L7 HTTP vulnerability attacks and observe their effect.
   
  1. Open another tab in your browser (Chrome shown), navigate to the newly configured Load Balancer
     configuration: **http://juiceshop.example.com**, to confirm it is functional.
  
  2. Using some of the sample attacks below, add the URI path & variables to your application to generate
     security event data.
```
     * /?cmd=cat%20/etc/passwd
     * /product?id=4%20OR%201=1
     * /cart?search=aaa'><script>prompt('Please+enter+your+password');</script>
```

Observe the results (NEED DESCRIPTION OF WHAT STUDENT SHOULD EXPECT TO SEE)

## Understanding NGINX WAF Configuration

F5 WAF for NGINX ships with two reference policies, both with a default enforcement mode set to Blocking:

- The **default** policy which is identical to the base template and provides OWASP Top 10 and Bot security protection out of the box.
- The **strict** policy contains more restrictive criteria for blocking traffic than the default policy. It is meant to be used for protecting sensitive applications that require more security but with higher risk of false positives.

For this lab, we will only implement the _default_ policy as this will be sufficient to show how the NGINX WAF can protect your application from the most common attacks.
If your environment requires more restrictive filters, the _strict_ policy may be a good solution.
However, in real-world production environments, these are merely starting points. Additional customizations can be performed according to the needs of the applications F5 WAF NGINX protects.
See the following tables for a list of additional options that can be use to further customize your NGINX WAF policies:

### Supported security policy features

(Tables taken from https://docs.nginx.com/waf/policies/configuration/#supported-security-policy-features)

| Feature        | Description |
| -------------- | ----------- |
| Allowed methods	| Checks allowed HTTP methods. By default, all the standard HTTP methods are allowed. |
| Attack signatures	| The default policy covers the OWASP top 10 attack patterns. Specific signature sets can be added or disabled. |
| Bot signatures | Bot signatures and headers can be inspected to authenticate the identity of a client making a request. |
| Brute force attack preventions | Configure parameters to secure areas of a web application from brute force attacks. |
| Cookie enforcement | By default all cookies are allowed and not enforced for integrity. The user can add specific cookies, wildcards or explicit, that will be enforced for integrity. It is also possible to set the cookie attributes: HttpOnly, Secure and SameSite for cookies found in the response. |
| Data guard | Detects and masks Credit Card Number (CCN) and/or U.S. Social Security Number (SSN) and/or custom patterns in HTTP responses. Disabled by default. |
| Deny and Allow IP lists | Deprecated. See IP address lists |
| Do-nothing | Do-nothing allows you to avoid inspecting or parsing a URL. |
| Disallowed file type extensions | Support any file type, and includes a predefined list of file types by default |
| Evasion techniques | All evasion techniques are enabled by default, and can be disabled individually. These include directory traversal, bad escaped characters and more. |
| Filetypes | The filetype feature allows you to selectively allow filetypes. |
| Geolocation | The geolocation feature allows you to configure enforcement based on the location of an object using the two-letter ISO code representing a country. |
| GraphQL protection | GraphQL protection allows you to configure enforcement for GraphQL, an API query language. |
| gRPC protection | gRPC protection detects malformed content, parses well-formed content, and extracts the text fields for detecting attack signatures and disallowed meta-characters. In addition, it enforces size restrictions and prohibition of unknown fields. The Interface Definition Language (IDL) files for the gRPC API must be attached to the profile. gRPC protection is available for unary or bidirectional traffic. |
| HTTP compliance | All HTTP protocol compliance checks are enabled by default except for GET with body and POST without body. It is possible to enable any of these two. Some of the checks enabled by default can be disabled, but others, such as bad HTTP version and null in request are performed by the NGINX parser and NGINX App Protect WAF only reports them. These checks cannot be disabled. |
| IP address lists | Organize lists of allowed and forbidden IP addresses across several lists with common attributes. |
| IP intelligence | Configure the IP Intelligence feature to customize enforcement based on the source IP of the request, limiting access from IP addresses with questionable reputation. |
| JWT protection | JWT protection allows you to configure policies based on properties of JSON web tokens, such as their header and signature properties. |
| Override rules | Override rules allow you to override default policy settings under specific conditions. |
| Response signatures | Response signatures allow you to inspect HTTP responses, selectively allowing specific response codes or lengths. |
| Server technology signatures | Support adding signatures per added server technology. |
| Time-based signature staging | Time-based signature staging allows you to stage signatures for a specific period of time. During the staging period, violations of staged signatures are logged but not enforced. After the staging period ends, violations of staged signatures are enforced according to the policy’s enforcement mode. |
| Threat campaigns | These are patterns that detect all the known attack campaigns. They are very accurate and have almost no false positives, but are very specific and do not detect malicious traffic that is not part of those campaigns. The default policy enables threat campaigns but it is possible to disable it through the respective violation. |
| User-defined browser control | Allow or deny specific browsers, and define custom browsers |
| User-defined HTTP headers | Handling headers as a special part of requests |
| User-defined URLs and parameters | Use user-defined properties when configuring violations. |
| User-defined signatures | Create and configure user-defined signatures for enforcement |
| XFF trusted headers | Disabled by default, and can accept an optional list of custom XFF headers. |
| XML and JSON content | XML content and JSON content profiles detect malformed content and signatures in the element values. Default policy checks maximum structure depth. It is possible to enable more size restrictions: maximum total length of XML/JSON data, maximum number of elements and more. |

### Additional policy features

| Feature        | Description |
| -------------- | ----------- |
| Blocking pages | The user can customize all blocking pages. By default the AJAX response pages are disabled, but the user can enable them. |
| Enforcement by violation rating | By default block requests that are declared as threats, which are rated 4 or 5. It is possible to change this behavior: either disable enforcement by Violation Rating or block also request with Violation Rating 3 - needs examination. |
| Large request blocking | To increase the protection of resources at both the NGINX Plus and upstream application tiers, all requests that are larger than 10 MB in size are blocked.  When these requests are blocked, a `VIOL_REQUEST_MAX_LENGTH` violation will be logged.|
| Malformed cookie | Requests with cookies that are not RFC compliant are blocked by default. This can be disabled. |
| Parameter parsing | Support only auto-detect parameter value type and acts according to the result: plain alphanumeric string, XML or JSON. |
| Request size checks | Upper limit of request size as dictated by the maximum buffer size of 10 MB;  Size checks for: URL, header, Query String, whole request (when smaller than the maximum buffer), cookie, POST data. By default all the checks are enabled with the exception of POST data and whole request. The user can enable or disable every check and customize the size limits. |
| Status code restriction | Illegal status code in the range of 4xx and 5xx. By default only these are allowed: 400, 401, 404, 407, 417, 503. The user can modify this list or disable the check altogether. |
| Sensitive parameters | The default policy masks the “password” parameter in the security log, and can be customized for more |

(For more information see https://docs.nginx.com/waf/policies/configuration/)

## Adding an NGINX WAF Policy

Create the Nginx for Azure configuration needed for the new WAF-protected version of juiceshop.example.com.

Using the Nginx for Azure Console, enable WAF by adding the following lines to /etc/nginx/conf.d/juiceshop.example.com.conf:
- "load_module modules/ngx_http_app_protect_module.so;" in the main context.
- "app_protect_enforcer_address 127.0.0.1:50000;" in the http context. (THIS CONTEXT WILL NEED TO BE ADDED FOR THIS LAB SECTION.)
- The following lines in the location context:
   - app_protect_enable on;
   - app_protect_policy_file "/etc/app_protect/conf/NginxDefaultPolicy.json";
   - app_protect_security_log_enable on;
   - app_protect_security_log "/etc/app_protect/conf/log_all.json" syslog:server=127.0.0.1:5140;


The juiceshop.example.com.conf file should now look like this:

    # Nginx 4 Azure - Juiceshop Nginx HTTP
    # WAF for Juiceshop

    # ADD THIS LINE TO LOAD WAF MODULE
    load_module modules/ngx_http_app_protect_module.so;

    server {
        
        listen 80;      # Listening on port 80 on all IP addresses on this machine

        server_name juiceshop.example.com;   # Set hostname to match in request
        status_zone juiceshop;

        # access_log  /var/log/nginx/juiceshop.log main;
        access_log  /var/log/nginx/juiceshop.example.com.log main_ext;
        error_log   /var/log/nginx/juiceshop.example.com_error.log info;

        # ADD THE ENFORCER ADDRESS BEFORE THE LOCATION BLOCK
        # (NEED TO CREATE AN HTTP CONTEXT AND MOVE THIS THERE)
        app_protect_enforcer_address 127.0.0.1:50000;

        location / {
            
            # return 200 "You have reached juiceshop server block, location /\n";

            # Set Rate Limit, uncomment below
            # limit_req zone=limit100;  #burst=110;       # Set  Limit and burst here
            # limit_req_status 429;           # Set HTTP Return Code, better than 503s
            # limit_req_dry_run on;           # Test the Rate limit, logged, but not enforced
            # add_header X-Ratelimit-Status $limit_req_status;   # Add a custom status header

            ## NGINX WAF CONFIGURATION
            app_protect_enable on;
            app_protect_policy_file "/etc/app_protect/conf/NginxDefaultPolicy.json";
            app_protect_security_log_enable on;
            # app_protect_security_log log_all stderr;
            app_protect_security_log "/etc/app_protect/conf/log_all.json" syslog:server=127.0.0.1:5140;
            ## NGINX WAF CONFIGURATION

            proxy_pass http://aks1_ingress;       # Proxy to AKS1 Nginx Ingress Controllers
            add_header X-Proxy-Pass aks1_ingress_juiceshop;  # Custom Header

        }

        # Cache Proxy example for static images / page components
        # Match common files with Regex
        location ~* \.(?:ico|jpg|png)$ {
            
            ### Uncomment for new status_zone in dashboard
            status_zone images;

            proxy_cache image_cache;
            proxy_cache_valid 200 60s;
            proxy_cache_key $scheme$proxy_host$request_uri;

            # Override cache control headers
            proxy_ignore_headers X-Accel-Expires Expires Cache-Control Set-Cookie;
            expires 365d;
            add_header Cache-Control "public";

            # Add a Cache status header - MISS, HIT, EXPIRED
            
            add_header X-Cache-Status $upstream_cache_status;
            
            proxy_pass http://aks1_ingress;    # Proxy AND load balance to AKS1 NIC
            add_header X-Proxy-Pass nginxazure_imagecache;  # Custom Header

        }  

    }

The default policy enforces violations by Violation Rating, the F5 WAF for NGINX computed assessment of the risk of the request based on the triggered violations.

- 0: No violation
- 1-2: False positive
- 3: Needs examination
- 4-5: Threat

The default policy enables most of the violations and signature sets with Alarm turned ON, but not Block.

These violations and signatures, when detected in a request, affect the violation rating. By default, if the violation rating is calculated to be malicious (4-5) the request will be blocked by the VIOL_RATING_THREAT violation.

This is true even if the other violations and signatures detected in that request have the Block flag turned OFF. It is the VIOL_RATING_THREAT violation having the Block flag turned ON that caused the blocking, but indirectly the combination of all the other violations and signatures in Alarm caused the request to be blocked.

By default, other requests which have a lower violation rating are not blocked, except for some specific violations described below. This is to minimize false positives. However, you can change the default behavior.

For more information on configuring WAF capability in NGINX, see https://docs.nginx.com/waf/policies/configuration/
    
**Submit your Nginx Configuration.**

## Testing the Newly-added NGINX WAF Policy

Now, test out the newly-deployed default WAF policy.

  1. Open another tab in your browser (Chrome shown), navigate to the newly configured Load Balancer
     configuration: **http://juiceshop.example.com**, to confirm it is functional.
  
  2. Using some of the sample attacks below, add the URI path & variables to your application to generate
     security event data.
```
     * /?cmd=cat%20/etc/passwd
     * /product?id=4%20OR%201=1
     * /cart?search=aaa'><script>prompt('Please+enter+your+password');</script>
```

> note::
>   *The web application firewall is blocking these requests to protect the application. The block page can*
>   *be customized to provide additional information.*

   ## Expected Results

  (Need to describe what students should expect to see and provide a screenshot.)
