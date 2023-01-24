# irulesowasptop10
Example Irules OWASP Top 10



Here are some examples of iRule configurations that address specific OWASP Top 10 vulnerabilities:

*   A1: Injection:

```ruby
when HTTP_REQUEST {
    if { [HTTP::uri] contains ";"} {
        HTTP::respond 403 "Access Denied - Possible injection attempt"
    }
    if { [HTTP::uri] contains "%27"} {
        HTTP::respond 403 "Access Denied - Possible injection attempt"
    }
    if { [HTTP::uri] contains "union"} {
        HTTP::respond 403 "Access Denied - Possible injection attempt"
    }
}
```

This iRule checks the URI of incoming HTTP requests for certain strings associated with SQL injection attacks, such as ";", "%27" and "union" and blocks them if they are present.

*   A2: Broken Authentication and Session Management:

```ruby
when HTTP_REQUEST {
    if { [HTTP::header Cookie] contains "sessionid" } {
        set sessionid [HTTP::header Cookie]
        if { [IP::client_addr] != [Session::get $sessionid client_addr] } {
            HTTP::respond 403 "Access Denied - Invalid session"
        }
    }
}
```

This iRule checks the "Cookie" header of incoming HTTP requests for a "sessionid" value, and then compares the client IP address of the request to the IP address associated with the session ID. If they do not match, the request is blocked.

*   A3: Cross-Site Scripting (XSS):

```ruby
when HTTP_REQUEST {
    if { [HTTP::uri] contains "<script>"} {
        HTTP::respond 403 "Access Denied - XSS attempt"
    }
    if { [HTTP::uri] contains "onload="} {
        HTTP::respond 403 "Access Denied - XSS attempt"
    }
}
```

This iRule checks the URI of incoming HTTP requests for certain strings associated with XSS attacks, such as "<script>" and "onload=", and blocks them if they are present.

*   A4: Insecure Direct Object References:

```ruby
when HTTP_REQUEST {
    if { [HTTP::uri] contains "../"} {
        HTTP::respond 403 "Access Denied - Insecure object reference"
    }
    if { [HTTP::uri] contains "..\\"} {
        HTTP::respond 403 "Access Denied - Insecure object reference"
    }
}
```

This iRule checks the URI of incoming HTTP requests for certain strings associated with insecure direct object references, such as "../" and "..", and blocks them if they are present.

It's important to note that iRule is a powerful tool but it is not a silver bullet, it should be used in conjunction with other security measures such as proper coding practices, security testing and regular security assessments.

show more

Sure, here are some more examples of iRule configurations that address specific OWASP Top 10 vulnerabilities:

*   A5: Security Misconfiguration:

```ruby
when HTTP_REQUEST {
    if { [HTTP::uri] contains "setup.php" } {
        HTTP::respond 403 "Access Denied - Setup file detected"
    }
    if { [HTTP::uri] contains "admin" } {
        if { [IP::client_addr] != "192.168.1.100" } {
            HTTP::respond 403 "Access Denied - Admin access not allowed"
        }
    }
}
```

This iRule checks the URI of incoming HTTP requests for certain strings associated with security misconfiguration, such as "setup.php" and "admin", and blocks them if they are present. Additionally, it checks if the client IP address is not from a specific IP address, it will block it.

*   A6: Sensitive Data Exposure:

```ruby
when HTTP_REQUEST {
    if { [HTTP::uri] contains ".pem" } {
        HTTP::respond 403 "Access Denied - Private key detected"
    }
    if { [HTTP::uri] contains ".key" } {
        HTTP::respond 403 "Access Denied - Private key detected"
    }
    if { [HTTP::uri] contains ".crt" } {
        HTTP::respond 403 "Access Denied - Certificate detected"
    }
}
```

This iRule checks the URI of incoming HTTP requests for certain strings associated with sensitive data exposure, such as ".pem", ".key" and ".crt", and blocks them if they are present.

*   A7: Missing Function Level Access Control

2 / 2

lanjutkan

Sure, here's an example of an iRule configuration that addresses the OWASP Top 10 vulnerability A7: Missing Function Level Access Control:

```php
when HTTP_REQUEST {
    set user [HTTP::header "X-User"]
    set role [HTTP::header "X-Role"]

    if {$role == "admin"} {
        if { [HTTP::uri] contains "admin" } {
            # Allow access to admin resources
        } else {
            HTTP::respond 403 "Access Denied - Admin access not allowed"
        }
    } elseif {$role == "user"} {
        if { [HTTP::uri] starts_with "/users" } {
            if {$user == [HTTP::uri]} {
                # Allow access to user resources
            } else {
                HTTP::respond 403 "Access Denied - Invalid user"
            }
        } else {
            HTTP::respond 403 "Access Denied - User access not allowed"
        }
    } else {
        HTTP::respond 403 "Access Denied - Invalid role"
    }
}
```

This iRule checks the "X-User" and "X-Role" headers of incoming HTTP requests and compares the values to a list of allowed roles and users. It then checks the URI of the request to determine if it is accessing a resource that the user is authorized to access. If the user is not authorized, the request is blocked with a "Access Denied" message. This iRule can be used to implement basic access control based on user role and user name.

It's worth noting that this is just an example, and you should tailor your iRule configuration to your specific needs and environment. It's also important to note that this iRule is not a complete solution for access control, it's only a layer of protection. Furthermore, it's crucial to implement proper access control on the application level as well.

show more

Sure, here are some more examples of iRule configurations that address specific OWASP Top 10 vulnerabilities:

*   A8: Cross-Site Request Forgery (CSRF)

```ruby
when HTTP_REQUEST {
    set csrf_token [HTTP::header "X-CSRF-Token"]
    set csrf_session [session::get [IP::client_addr] csrf_token]
    if {$csrf_token != $csrf_session} {
        HTTP::respond 403 "Access Denied - Invalid CSRF token"
    }
}
```

This iRule checks the "X-CSRF-Token" header of incoming HTTP requests and compares it to the CSRF token associated with the client's IP address in the session. If the token does not match, the request is blocked.

*   A9: Using Components with Known Vulnerabilities

```ruby
when HTTP_REQUEST {
    set user_agent [HTTP::header "User-Agent"]
    if {[class match [string tolower $user_agent] contains "outdatedbrowser"]} {
        HTTP::respond 403 "Access Denied - Outdated browser detected"
    }
}
```

This iRule checks the "User-Agent" header of incoming HTTP requests and compares it to a list of known outdated browsers. If a match is found, the request is blocked.

*   A10: Unvalidated Redirects and Forwards

```ruby
when HTTP_REQUEST {
    set redirect_url [HTTP::header "X-Redirect-Url"]
    if {![class match [string tolower $redirect_url] contains "mydomain.com"]} {
        HTTP::respond 403 "Access Denied - Invalid redirect URL"
    }
}
```

This iRule checks the "X-Redirect-Url" header of incoming HTTP requests and compares it to a list of allowed domain names. If the redirect URL is not on the list, the request is blocked.

Again, it's important to note that these iRule examples are only a layer of protection, they can't replace a comprehensive security strategy. It's important to use iRule in conjunction with other security measures, such as proper coding practices, security testing and regular security assessments.
