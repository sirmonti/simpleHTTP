# simpleHTTP - Simple HTTP client library
Wrapper around file_get_contents function to simplify HTTP and HTTPS connections

## Description
Wrapper class around file_get_contents function. This class is not intended
to compete with full featured network frameworks, as Guzzle or Swoole, but to
provide a simple and convenient solution to use web services or access web resources

## Installation
Via composer
```console
composer require sirmonti/simplehttp
```
This class does not have any external dependency, which means you don't need to
do a full installation, you can simply download and drop
[simpleHTTP.php](https://github.com/sirmonti/simpleHTTP/blob/main/src/simpleHTTP.php)
file in your project folder.

## Features
- Lightweigth
- Very simple interface
- You can disable certificate verification, to allow sites with self-signed or expired certificates
- In HTTPS connections, the certificate chain for the remote is retrieved
- Certificate authentication supported. You can provide your
  certificate to authenticate agains remote site
- Configurable exception level. You can disable exceptions, fire exceptions only
  on network errors, or fire exceptions on HTTP errors too
- Responses in PSR7 format. This feature requires an external package installed

## Basic usage

This is only a brief explanation, the file [simpleHTTP.md](simpleHTTP.md) provide
a more extensive method reference.

Complete documentation can be found [Here](https://sirmonti.github.io/simpleHTTP/).

You create an object of the simpleHTTP class. The constructor has two parameters,
the exception level and the remote certificate validation.

Here we create an object with an exception level 2 and certificate validation disabled:
```php
  $http=new simpleHTTP(2,false);
```
The certificate validation is a boolean flag that enable or disable the validation
of the remote certificate on https connections. If the validation is enabled, if the
remote site has a bogus certificate (expired, autosigned or for another domain)
the connection will be aborted and an error will be fired. In disabled, the
error will be ignored and the connection will be executed normally.

About the exception levels, there are three levels:

- 0: Exceptions are disabled. Errors only set status code responses.
- 1: Exception only on network errors. HTTP errors will be reported as status codes.
- 2: Exception will be fired on any error.

Default values is exception level 1 and certificate validation enabled.

Supported methods are: **GET**, **POST**, **PUT**, **HEAD**, **DELETE**
and **OPTIONS**. The request call return the request body and the other
data, like response headers, are stored internally and can be retrieved.

Here, a basic example
```php
  $http=new simpleHTTP;
  $resp=$http->get('https://www.example.com/');
  printf("Response data:\n%s\n",$resp);
```
This library can return responses in PSR7 format, but is neccesary to have a
third party library installed. Currently, [HttpSoft](https://github.com/httpsoft/http-message),
[Nyholm](https://github.com/nyholm/psr7), [Guzzle](https://github.com/guzzle/psr7/),
[Laminas-diactoros](https://github.com/laminas/laminas-diactoros) and
[Slim](https://github.com/slimphp/Slim-Psr7) are supported. simpleHTTP detects
which one is installed and will fire an error if none is installed.

PSR7 responses are useful because the main PHP frameworks use this format.

Example getting a PSR7 response
```php
  $http=new simpleHTTP;
  $http->get('https://www.example.com/');
  $resp=$http->PSRResponse();
```
## Examples
There are more examples in [examples](examples) folder.

This is the most simple usage:
```php
  $http=new simpleHTTP;
  $resp1=$http->get('https://www.example.com/data1.txt');
  $resp2=$http->get('https://www.example.com/data2.json');
```
As you see, the object execute direct requests providing the URL.

Here, and example configuring exceptions and certificate acceptance
```php
  // Exception level 2 (exception on network or HTTP errors)
  // Certificate validation disabled (Will accept any certificate)
  $http=new simpleHTTP(2,false);
  $data=[
    'field1'=>'Data to send in field1',
    'field2'=>'Data to send in field2'
  ];
  // Execute a POST request sending the content of the $data variable
  $resp=$http->post('https://www.example.com/sendpoint',$data);
```

Here, a POST with a JSON encoded body
```php
  // Default exception level is 1, which means exceptions will be fired
  // only on network errors
  $http=new simpleHTTP;
  $data=[
    'field1'=>'Data to send in field1',
    'field2'=>'Data to send in field2'
  ];
  $resp=$http->postJSON('https://www.example.com/jsonentrypoint',$data);
```

And here, a POST with an image as data body
```php
  $http=new simpleHTTP;
  $data=file_get_contents('exampleimage.jpg');
  $http->postRAW('https://www.example.com/imagenentrypoint','image/jpeg',$data);
```
But, What if you need to add an authentication header?
```php
  $http=new simpleHTTP;
  // Create the authentication header
  $headers=[
    'Authorization: Bearer AuthenticationToken'
  ];
  // Configure the default headers to send
  $http->setExtraHeaders($headers);
  $data=[
    'field1'=>'Data to send in field1',
    'field2'=>'Data to send in field2'
  ];
  $resp=$http->post('https://www.example.com/sendpoint',$data);
```
But, If we need an extra header only in a specific request?
```php
  $http=new simpleHTTP;
  $headers=[
    'Authorization: Bearer AuthenticationToken'
  ];
  $http->setExtraHeaders($headers);
  $data=[
    'field1'=>'Data to send in field1',
    'field2'=>'Data to send in field2'
  ];
  // Add an extra header to this request
  $resp=$http->post('https://www.example.com/sendpoint',$data,['X-Extra-Header: Data']);
```
The requests from this class use "simpleHTTP/7.0" as user agent. You can set
your own one
```php
  $http=new simpleHTTP;
  // Add an User-Agent header
  $headers=[
    'Authorization: Bearer AuthenticationToken',
    'User-Agent: MyOwnUserAgent/1.0'
  ];
  $http->setExtraHeaders($headers);
  $data=[
    'field1'=>'Data to send in field1',
    'field2'=>'Data to send in field2'
  ];
  $resp=$http->post('https://www.example.com/sendpoint',$data);
```
Here, a *PUT* request example
```php
  $http=new simpleHTTP;
  $headers=[
    'Authorization: Bearer AuthenticationToken',
    'User-Agent: MyOwnUserAgent/1.0'
  ];
  $http->setExtraHeaders($headers);
  $data=[
    'field1'=>'Data to send in field1',
    'field2'=>'Data to send in field2'
  ];
  // Example PUT with body in JSON format
  $resp=$http->putJSON('https://www.example.com/sendpoint',$data);
```
But, How I can get the response headers and result status?
```php
  $http=new simpleHTTP;
  $resp=$http->get('https://www.example.com/');
  printf("HTTP/%s %d %s\n",$http->protocolVersion(),$http->respCode(),$http->respStatus());
  printf("Response mime type: %s\n",$http->respMIME());
```
This code will produce this output
```
HTTP/1.1 200 OK
Response mime type: text/html; charset=UTF-8
```

## LICENSE

This library is licensed under [MIT LICENSE](LICENSE)
