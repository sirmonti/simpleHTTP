***

# simpleHTTP

Wrapper class around file_get_contents function. This class is not intended
to compete with full featured network frameworks, as Guzzle or Swoole, but
to provide a simple and convenient solution to use web services or access
web resources



* Full name: `\simpleHTTP`

**See Also:**

* https://github.com/sirmonti/simplehttp/ - simpleHTTP github project



## Properties


### verifCERT

Enable/Disable certificate verification on https connections.

```php
public bool $verifCERT
```

When connecting to a https site, the program verify if the
certificate is valid and fires an error if not. Disabling certificate validation
you can prevent this error and connect to sites with bogus certificate.
You can edit this value to change default value.




***

### exceptlevel

Exception level. You can edit this value to change default value

```php
private int $exceptlevel
```

Expected values:

- 0: No exceptions
- 1: Exception only on network errors or invalid arguments
- 2: Exception on HTTP errors (4XX and 5XX errors) too




***

## Methods


### __construct

Constructor

```php
public __construct(int $elevel = 1, bool $verifCert = true): mixed
```

There are two optional parameters, the interrupt level and the certificate
verification flag. When connecting to a https site, the program verify if the
certificate is valid and fires an error if not. Disabling certificate validation
you can prevent this error and connect to sites with bogus certificate.

There are three interruption levels:
- 0: No exceptions fired. Operations results are returned in httpcode and httpstatus
- 1: Exceptions only on network errors or bad formed URLs. HTTP errors don't fire exceptions
- 2: All errors fire an exception.






**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$elevel` | **int** | (optiona) Set interruption level |
| `$verifCert` | **bool** | (optional) Enable or disable certificate verification |





***

### setExceptionLevel

Set exception level

```php
public setExceptionLevel(int $level): void
```

This method configures the use of exceptions on an error. There are three exception levels

- 0: No exceptions fired. Operations results are returned in httpcode and httpstatus
- 1: Exceptions only on network errors or bad formed URLs. HTTP errors don't fire exceptions
- 2: All errors fire an exception.






**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$level` | **int** | Exception level |





***

### getExceptionLevel

Get the configured exception level

```php
public getExceptionLevel(): int
```









**Return Value:**

Configured exception level




***

### setExtraHeaders

Define a set of extra headers to be attached to following requests

```php
public setExtraHeaders(array&lt;int,string&gt; $headers = []): mixed
```








**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$headers` | **array<int,string>** | Extra headers to set |





***

### getExtraHeaders

Get the extra headers, if any

```php
public getExtraHeaders(): array&lt;int,string&gt;
```









**Return Value:**

Configured extra headers




***

### getSendHeaders

Get the headers that has been sent on last request

```php
public getSendHeaders(): array
```

If you call this method before any request, it will
return default headers.







**Return Value:**

Header sent on last request




***

### getPeerCert

Get the peer certificate from the visited site

```php
public getPeerCert(): \OpenSSLCertificate|null
```

When connecting to a https site, the certificate chain for the remote
site is retrieved, allowing extra validations. This method returns the
certificate of the visited site. The certificate can be proccesed with
the openssl_x509_* set of functions.







**Return Value:**

Peer site certificate




***

### getCertchain

Get the certificate chain from the visited site

```php
public getCertchain(): array
```

When connecting to a https site, the certificate chain for the remote
site is retrieved, allowing extra validations. This method returns an
array with the complete certificate chain of the visited site.
The certificates can be proccesed with the openssl_x509_* set of functions.







**Return Value:**

Certificate chain




***

### setAuthCert

Set local certificate/key pair to authenticate connections

```php
public setAuthCert(string $certfile, string $keyfile = &#039;&#039;, string $passphrase = &#039;&#039;): mixed
```

The parameters are the paths to the files containing the certificates encoded in PEM format.
If the certificate and the private key are stored in different files, you must provide both.






**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$certfile` | **string** | File with the certificate in PEM format |
| `$keyfile` | **string** | (optional) File with the private key in PEM format |
| `$passphrase` | **string** | (optional) Passphrase if keys are encrypted |





***

### protocolVersion

Get the protocol version for the las HTTP request

```php
public protocolVersion(): string
```









**Return Value:**

Protocol version




***

### respCode

Get the status code for the last HTTP request

```php
public respCode(): int
```

Normally, the status code is the return code from the HTTP connection (200,404,500, ..),
but this class adds two extra codes:

- -1: Invalid schema. Only http:// and https:// is supported
- -2: Invalid argument. Data passed to the method call is not valid
- -3: Network error. Network connection failed







**Return Value:**

Status code




***

### respStatus

Get the status message for the last HTTP request

```php
public respStatus(): string
```









**Return Value:**

Status message




***

### respHeaders

Get the response headers for the last HTTP request

```php
public respHeaders(): array&lt;string,string&gt;
```









**Return Value:**

Headers




***

### respMIME

Get the mime type of the response for the last HTTP request

```php
public respMIME(): string
```









**Return Value:**

Response data mime type




***

### respBody

Get the data returned by the last HTTP request

```php
public respBody(): string
```









**Return Value:**

HTTP response




***

### get

Do a GET HTTP request

```php
public get(string $url, array&lt;string,string&gt; $headers = []): string
```








**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | URL to retrieve |
| `$headers` | **array<string,string>** | Extra HTTP headers |


**Return Value:**

Data retrieved



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### post

Do a POST HTTP request

```php
public post(string $url, array&lt;string,mixed&gt; $data, array&lt;string,string&gt; $headers = []): string
```








**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | POST destination URL |
| `$data` | **array<string,mixed>** | Associative array with POST parameters |
| `$headers` | **array<string,string>** | (optional) Extra HTTP headers |


**Return Value:**

Response data



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### postJSON

Do a POST HTTP request with the body data in JSON format

```php
public postJSON(string $url, mixed $data, array&lt;string,string&gt; $headers = []): string
```








**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | POST destination URL |
| `$data` | **mixed** | Data to include in the body |
| `$headers` | **array<string,string>** | (optional) Extra HTTP headers |


**Return Value:**

Response data



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### postRAW

Do a POST HTTP request with the body in a custom format

```php
public postRAW(string $url, string $mime, mixed $data, array&lt;string,string&gt; $headers = []): string
```








**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | POST destination URL |
| `$mime` | **string** | MIME type of the data |
| `$data` | **mixed** | Data to include in the body |
| `$headers` | **array<string,string>** | (optional) Extra HTTP headers |


**Return Value:**

Response data



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### put

Do a PUT HTTP request

```php
public put(string $url, array&lt;string,mixed&gt; $data, array&lt;string,string&gt; $headers = []): string
```








**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | POST destination URL |
| `$data` | **array<string,mixed>** | Associative array with POST parameters |
| `$headers` | **array<string,string>** | (optional) Extra HTTP headers |


**Return Value:**

Response data



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### putJSON

Do a PUT HTTP request with the body data in JSON format

```php
public putJSON(string $url, mixed $data, array&lt;string,string&gt; $headers = []): string
```








**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | POST destination URL |
| `$data` | **mixed** | Data to include in the body |
| `$headers` | **array<string,string>** | (optional) Extra HTTP headers |


**Return Value:**

Response data



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### putRAW

Do a PUT HTTP request with the body in a custom format

```php
public putRAW(string $url, string $mime, mixed $data, array&lt;string,string&gt; $headers = []): string
```








**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | POST destination URL |
| `$mime` | **string** | MIME type of the data |
| `$data` | **mixed** | Data to include in the body |
| `$headers` | **array<string,string>** | (optional) Extra HTTP headers |


**Return Value:**

Response data



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### patch

Do a PATCH HTTP request

```php
public patch(string $url, array $data, array&lt;string,string&gt; $headers = []): string
```








**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | POST destination URL |
| `$data` | **array** | Associative array with POST parameters |
| `$headers` | **array<string,string>** | (optional) Extra HTTP headers |


**Return Value:**

Response data



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### patchJSON

Do a PATCH HTTP request with the body data in JSON format

```php
public patchJSON(string $url, mixed $data, array&lt;string,string&gt; $headers = []): string
```








**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | POST destination URL |
| `$data` | **mixed** | Data to include in the body |
| `$headers` | **array<string,string>** | (optional) Extra HTTP headers |


**Return Value:**

Response data



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### patchRAW

Do a PATCH HTTP request with the body in a custom format

```php
public patchRAW(string $url, string $mime, mixed $data, array&lt;string,string&gt; $headers = []): string
```








**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | POST destination URL |
| `$mime` | **string** | MIME type of the data |
| `$data` | **mixed** | Data to include in the body |
| `$headers` | **array<string,string>** | (optional) Extra HTTP headers |


**Return Value:**

Response data



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### head

Do a HEAD HTTP request

```php
public head(string $url, array&lt;string,string&gt; $headers = []): string
```








**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | URL to retrieve |
| `$headers` | **array<string,string>** | Extra HTTP headers |


**Return Value:**

Data retrieved



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### delete

Do a DELETE HTTP request

```php
public delete(string $url, array&lt;string,string&gt; $headers = []): string
```








**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | URL to retrieve |
| `$headers` | **array<string,string>** | Extra HTTP headers |


**Return Value:**

Data retrieved



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### options

Do an OPTIONS HTTP request

```php
public options(string $url, array&lt;string,string&gt; $headers = []): string
```








**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$url` | **string** | URL to retrieve |
| `$headers` | **array<string,string>** | Extra HTTP headers |


**Return Value:**

Data retrieved



**Throws:**
<p>on invalid parameters</p>

- [`InvalidArgumentException`](./InvalidArgumentException.md)
<p>on network error</p>

- [`RuntimeException`](./RuntimeException.md)



***

### PSRResponse

Retrieve a PSR7 Response

```php
public PSRResponse(): \ResponseInterface
```

This method return the result for the last request in a PSR7 message.
To use this method you must have installed one of the following packages:
httpsoft/http-message, nyholm/psr7, guzzle/psr7, laminas/laminas-diactoros
or slim/psr7

This method fires an Error if there isn't any PSR7 package installed







**Return Value:**

Message in PSR7 format



**Throws:**
<p>If there isn't any PSR7 package installed</p>

- [`Error`](https://www.php.net/manual/en/class.error.php)



***


***
> Automatically generated on 2024-01-31
