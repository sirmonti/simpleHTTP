<?php

declare(strict_types=1);

/**
 * @package simpleHTTP
 */
use Composer\Script\Event;
use Symfony\Component\Console\Output\ConsoleOutput;
use Psr\Http\Message\ResponseInterface;
use Nyholm\Psr7\Response as NResponse;
use GuzzleHttp\Psr7\Response as GResponse;
use HttpSoft\Message\Response as HResponse;
use HttpSoft\Message\StreamFactory as HStream;
use Laminas\Diactoros\Response as LResponse;
use Laminas\Diactoros\StreamFactory as LStream;
use Slim\Psr7\Header as SHeader;
use Slim\Psr7\Headers as SHeaders;
use Slim\Psr7\Response as SResponse;
use Slim\Psr7\Stream as SSTream;

/**
 * Wrapper class around file_get_contents function. This class is not intended
 * to compete with full featured network frameworks, as Guzzle or Swoole, but
 * to provide a simple and convenient solution to use web services or access
 * web resources
 * 
 * @see https://github.com/sirmonti/simplehttp/ simpleHTTP github project
 * 
 * @author Francisco Monteagudo <francisco@monteagudo.net>
 * @version 7.0.0
 * @license https://opensource.org/licenses/MIT (MIT License)
 * @copyright (c) 2024, Francisco Monteagudo
  A ver */
class simpleHTTP {

    /**
     * Enable/Disable certificate verification on https connections.
     * 
     * When connecting to a https site, the program verify if the
     * certificate is valid and fires an error if not. Disabling certificate validation
     * you can prevent this error and connect to sites with faulty certificate.
     * You can edit this value to change default value.
     * 
     * @var bool
     */
    public bool $verifCERT = true;

    /**
     * If request returns a redirection, it must be followed.
     * 
     * @var bool
     */
    public bool $followRedirs = true;

    /**
     * On the request command, send the full URI instead the path.
     * 
     * For example, instead send "GET /test.html HTTP/1.1" command to the server,
     * script will send "GET http://www.example.com/test.html HTTP/1.1".
     * Include full URI breaks standard, but is neccesary if connect to a proxy.
     * 
     * @var bool
     */
    public bool $reqFullURI = false;

    /**
     * How many redirections must be followed before a "Many redirections"
     * error must be fired
     * 
     * @var int
     */
    public int $maxfollows = 20;

    /**
     * Connection timeout. Connection closes if exceds timeout without
     * response. Default value is ten seconds.
     * 
     * @var float
     */
    public float $timeout = 10.0;

    /**
     * Exception level. You can edit this value to change default value
     * 
     * Expected values:
     * 
     * - 0: No exceptions
     * - 1: Exception only on network errors or invalid arguments
     * - 2: Exception on HTTP errors (4XX and 5XX errors) too
     * 
     * @var int
     */
    private int $exceptlevel = 1;

    /** @ignore */
    private const USERAGENT = 'simpleHTTP/7.0';

    /** @ignore */
    private const DEFHEADER = ['User-Agent: ' . self::USERAGENT];

    /** @ignore */
    private const RESPPACKAGES=[
        'httpsoft/http-message'=>'HttpSoft\Message\Response',
        'nyholm/psr7'=>'Nyholm\Psr7\Response',
        'guzzlehttp/psr7'=>'GuzzleHttp\Psr7\Response',
        'laminas/laminas-diactoros'=>'Laminas\Diactoros\Response',
        'slim/psr7'=>'Slim\Psr7\Response'
    ];

    /** @ignore */
    private array $extraheaders = [];

    /** @ignore */
    private string $protversion = '';

    /** @ignore */
    private int $respcode = 0;

    /** @ignore */
    private string $respstatus = '';

    /** @ignore */
    private string $respmime = '';

    /** @ignore */
    private array $respheaders = [];

    /** @ignore */
    private string $respbody = '';

    /** @ignore */
    private string $url = '';

    /** @ignore */
    private string $method = '';

    /** @ignore */
    private string $hostheader = '';

    /** @ignore */
    private array $sendheaders = [];

    /** @ignore */
    private array $opts = [];

    /** @ignore */
    private string $body = '';

    /** @ignore */
    private array $certChain = [];

    /** @ignore */
    private string $localCert = '';

    /** @ignore */
    private string $localKey = '';

    /** @ignore */
    private string $passphrase = '';

    /** @ignore */
    private string $proxy = '';

    /**
     * Constructor
     * 
     * There are two optional parameters, the interrupt level and the certificate
     * verification flag. When connecting to a https site, the program verify if the
     * certificate is valid and fires an error if not. Disabling certificate validation
     * you can prevent this error and connect to sites with bogus certificate.
     * 
     * There are three interruption levels:
     * - 0: No exceptions fired. Operations results are returned in httpcode and httpstatus
     * - 1: Exceptions only on network errors or bad formed URLs. HTTP errors don't fire exceptions
     * - 2: All errors fire an exception.
     * 
     * @param int $elevel (optiona) Set interruption level
     * @param bool $verifCert (optional) Enable or disable certificate verification
     */
    function __construct(int $elevel = 1, bool $verifCert = true) {
        $this->verifCERT = $verifCert;
        $this->exceptlevel = $elevel;
    }

    /** @ignore */
    private function mergeHeaders(array $headers) {
        $this->sendheaders = [];
        $noms = ['content-length' => true];
        $this->hostheader = '';
        foreach([$headers,$this->extraheaders,self::DEFHEADER] as $hdrs) {
            foreach ($hdrs as $head) {
                $key = strtolower(strstr($head, ':', true));
                if (!isset($noms[$key])) {
                    $noms[$key] = true;
                    $this->sendheaders[] = $head;
                    if($key=='host') $this->hostheader = trim(substr(strstr($head,':'),1));
                }
            }
        }
    }

    /** @ignore */
    private function buildopts(): void {
        if (!filter_var($this->url, FILTER_VALIDATE_URL)) {
            $this->respcode = -2;
            $this->respstatus = _('Invalid URL');
            throw new Exception;
        }
        $info = parse_url($this->url);
        if (strtolower(substr($info['scheme'], 0, 4)) != 'http') {
            $this->respcode = -1;
            $this->respstatus = _('Invalid scheme. This class only supports http and https connections');
            throw new Exception;
        }
        if($this->hostheader=='') {
            $host = $info['host'];
            $this->sendheaders[] = 'Host: ' . $host;
        } else {
            $host = $this->hostheader;
        }
        $this->opts = [
            'http' => [
                'ignore_errors' => true,
                'request_fulluri' => $this->reqFullURI,
                'timeout' => $this->timeout,
                'follow_location' => $this->followRedirs ? 1:0,
                'max_redirects' => $this->maxfollows,
                'method' => $this->method
            ]
        ];
        if ($this->body != '') {
            $this->sendheaders[] = 'Content-Length: ' . strlen($this->body);
            $this->opts['http']['content'] = $this->body;
        }
        $this->opts['http']['header'] = $this->sendheaders;
        if($this->proxy!='') {
            $this->opts['http']['proxy']=$this->proxy;
        }
        if (strtolower($info['scheme']) == 'https') {
            if ($this->verifCERT) {
                $this->opts['ssl'] = [
                    'SNI_enabled' => true,
                    'peer_name' => $host,
                    'capture_peer_cert_chain' => true
                ];
            } else {
                $this->opts['ssl'] = [
                    'verify_peer' => false,
                    'verify_peer_name' => false,
                    'capture_peer_cert_chain' => true
                ];
            }
            if ($this->localCert != '') {
                $this->opts['ssl']['local_cert'] = $this->localCert;
            }
            if ($this->localKey != '') {
                $this->opts['ssl']['local_pk'] = $this->localKey;
            }
            if ($this->passphrase != '') {
                $this->opts['ssl']['passphrase'] = $this->passphrase;
            }
        }
    }

    /** @ignore */
    private function buildResponseHeaders(array $headers) {
        $this->respheaders = [];
        foreach ($headers as $head) {
            $pos = strpos($head, ':');
            if ($pos > 0) {
                [$cab, $val] = explode(':', $head, 2);
                $cab = strtolower(trim($cab));
                $val = trim($val);
                if (isset($this->respheaders[$cab])) {
                    if (is_array($this->respheaders[$cab]))
                        $this->respheaders[$cab][] = $val;
                    else
                        $this->respheaders[$cab] = [$this->respheaders[$cab], $val];
                } else {
                    $this->respheaders[$cab] = $val;
                }
                if (strtolower($cab) == 'content-type') {
                    $this->respmime = trim(substr($head, 14));
                }
            }
        }
    }

    /** @ignore */
    private function execHTTP() {
        $this->respcode = 0;
        $this->protversion = '';
        $this->respstatus = '';
        $this->respmime = '';
        $this->respheaders = [];
        $this->respbody = '';
        $this->certChain = [];
        try {
            if (count($this->sendheaders) == 0) {
                $this->sendheaders = self::DEFHEADER;
            }
            $this->buildopts();
            $ctx = stream_context_create($this->opts);
            $data = (string) @file_get_contents($this->url, false, $ctx);
            $this->respbody = $data;
            $opts = stream_context_get_options($ctx);
            if (isset($opts['ssl']['peer_certificate_chain'])) {
                $this->certChain = $opts['ssl']['peer_certificate_chain'];
            }
            if (count((array) @$http_response_header) == 0) {
                $this->respcode = -3;
                $this->respstatus = _('Network error');
                throw new Exception();
            }
            $status = array_shift($http_response_header);
            if (!preg_match('/^HTTP\/([0-9]+\.[0-9]+)\ ([0-9]{3})\ (.+)$/', $status, $resp)) {
                $this->respcode = -3;
                $this->respstatus = _('Network error');
                throw new Exception();
            }
            $this->buildResponseHeaders($http_response_header);
            $this->protversion = (string) $resp[1];
            $this->respcode = (int) $resp[2];
            $this->respstatus = (string) $resp[3];
            if (($this->respcode >= 400) && ($this->exceptlevel == 2))
                throw new Exception();
            return $data;
        } catch (Exception $e) {
            if (($this->exceptlevel == 2) && ($this->respcode >= 400)) {
                throw new RuntimeException($this->respstatus, $this->respcode);
            }
            if ($this->exceptlevel > 0) {
                if ($this->respcode == -3) {
                    throw new RuntimeException($this->respstatus, $this->respcode);
                } else {
                    throw new InvalidArgumentException($this->respstatus, $this->respcode);
                }
            }
        }
        return $this->respbody;
    }

    /**
     * Set exception level
     * 
     * This method configures the use of exceptions on an error. There are three exception levels
     * 
     * - 0: No exceptions fired. Operations results are returned in httpcode and httpstatus
     * - 1: Exceptions only on network errors or bad formed URLs. HTTP errors don't fire exceptions
     * - 2: All errors fire an exception.
     * 
     * @param int $level Exception level
     */
    function setExceptionLevel(int $level): void {
        if (($level >= 0) && ($level <= 2))
            $this->exceptlevel = $level;
    }

    /**
     * Get the configured exception level
     * 
     * @return int Configured exception level
     */
    function getExceptionLevel(): int {
        return $this->exceptlevel;
    }

    /**
     * Set the proxy server
     * 
     * You provide the host name or IP address and port
     * 
     * @param string $host Proxy host
     * @param int $port Proxy port
     * @return bool Proxy has been set OK
     */
    function setProxy(string $host='',int $port=8080): bool {
        if($host=='') {
            $this->proxy='';
            return true;
        }
        if($port==0) return false;
        if((filter_var($host,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4|FILTER_FLAG_IPV6))||
           (filter_vars($host,FILTER_VALIDATE_DOMAIN,FILTER_FLAG_HOSTNAME))) {
            $this->proxy='tcp://'.$host.':'.$port;
            return true;
        }
        return false;
    }

    /**
     * Get the proxy parameters
     * 
     * @param string $host Filled with proxy host name or IP
     * @param int $port Filled with proxy port
     */
    function getProxy(string &$host, int &$port) {
        $host='';
        $port=0;
        if($this->proxy=='') return;
        if(!preg_match('/^tcp\:\/\/(.+)\:([0-9]+)$/',$this->proxy,$resp)) return;
        $host=$resp[1];
        $port=(int)$resp[2];
    }

    /**
     * Define a set of extra headers to be attached to following requests
     * 
     * @param array<int,string> $headers Extra headers to set
     */
    function setExtraHeaders(array $headers = []) {
        $this->extraheaders = $headers;
        $this->mergeHeaders([]);
    }

    /**
     * Get the extra headers, if any
     * 
     * @return array<int,string> Configured extra headers
     */
    function getExtraHeaders(): array {
        return $this->extraheaders;
    }

    /**
     * Get the headers that has been sent on last request
     * 
     * If you call this method before any request, it will
     * return default headers.
     * 
     * @return array Header sent on last request
     */
    function getSendHeaders(): array {
        if (count($this->sendheaders) == 0)
            return self::DEFHEADER;
        return $this->sendheaders;
    }

    /**
     * Get the body that has been sent on last request
     * 
     * If you call this method before any request, it will
     * return an empty string.
     * 
     * @return string Body sent on last request
     */
    function getSendBody(): string {
        return $this->body;
    }

    /**
     * Get the peer certificate from the visited site
     * 
     * When connecting to a https site, the certificate chain for the remote
     * site is retrieved, allowing extra validations. This method returns the
     * certificate of the visited site. The certificate can be proccesed with
     * the openssl_x509_* set of functions.
     * 
     * @return OpenSSLCertificate|null Peer site certificate
     */
    function getPeerCert(): ?OpenSSLCertificate {
        if (count($this->certChain) == 0)
            return null;
        return $this->certChain[0];
    }

    /**
     * Get the certificate chain from the visited site
     * 
     * When connecting to a https site, the certificate chain for the remote
     * site is retrieved, allowing extra validations. This method returns an
     * array with the complete certificate chain of the visited site.
     * The certificates can be proccesed with the openssl_x509_* set of functions.
     * 
     * @return array Certificate chain
     */
    function getCertchain(): array {
        return $this->certChain;
    }

    /**
     * Set local certificate/key pair to authenticate connections
     * 
     * The parameters are the paths to the files containing the certificates encoded in PEM format.
     * If the certificate and the private key are stored in different files, you must provide both. 
     * 
     * @param string $certfile File with the certificate in PEM format
     * @param string $keyfile (optional) File with the private key in PEM format
     * @param string $passphrase (optional) Passphrase if keys are encrypted
     */
    function setAuthCert(string $certfile, string $keyfile = '', string $passphrase = '') {
        $this->localCert = $certfile;
        $this->localKey = $keyfile;
        $this->passphrase = $passphrase;
    }

    /**
     * Get the protocol version for the las HTTP request
     * 
     * @return string Protocol version
     */
    function protocolVersion(): string {
        return $this->protversion;
    }

    /**
     * Get the status code for the last HTTP request
     * 
     * Normally, the status code is the return code from the HTTP connection (200,404,500, ..),
     * but this class adds two extra codes:
     * 
     * - -1: Invalid schema. Only http:// and https:// is supported
     * - -2: Invalid argument. Data passed to the method call is not valid
     * - -3: Network error. Network connection failed
     *
     * @return int Status code
     */
    function respCode(): int {
        return $this->respcode;
    }

    /**
     * Get the status message for the last HTTP request
     *
     * @return string Status message
     */
    function respStatus(): string {
        return $this->respstatus;
    }

    /**
     * Get the response headers for the last HTTP request
     *
     * @return array<string,string> Headers
     */
    function respHeaders(): array {
        return $this->respheaders;
    }

    /**
     * Get the mime type of the response for the last HTTP request
     *
     * @return string Response data mime type
     */
    function respMIME(): string {
        return $this->respmime;
    }

    /**
     * Get the data returned by the last HTTP request
     * 
     * @return string HTTP response
     */
    function respBody(): string {
        return $this->respbody;
    }

    /**
     * Do a GET HTTP request
     *
     * @param string $url URL to retrieve
     * @param array<string,string> $headers Extra HTTP headers
     * @return string Data retrieved
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    function get(string $url, array $headers = []): string {
        $this->method = 'GET';
        $this->url = $url;
        $this->body = '';
        $this->mergeHeaders($headers);
        $this->execHTTP();
        return $this->respbody;
    }

    /**
     * Do a POST HTTP request
     *
     * @param string $url POST destination URL
     * @param array<string,mixed> $data Associative array with POST parameters
     * @param array<string,string> $headers (optional) Extra HTTP headers
     * @return string Response data
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    function post(string $url, array $data, array $headers = []): string {
        $this->method = 'POST';
        $this->url = $url;
        array_unshift($headers, 'Content-Type: application/x-www-form-urlencoded');
        $this->mergeHeaders($headers);
        $this->body = http_build_query($data);
        $this->execHTTP();
        return $this->respbody;
    }

    /**
     * Do a POST HTTP request with the body data in JSON format
     *
     * @param string $url POST destination URL
     * @param mixed $data Data to include in the body
     * @param array<string,string> $headers (optional) Extra HTTP headers
     * @return string Response data
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    function postJSON(string $url, $data, array $headers = []): string {
        $this->method = 'POST';
        $this->url = $url;
        array_unshift($headers, 'Content-Type: application/json');
        $this->mergeHeaders($headers);
        $this->body = json_encode($data);
        $this->execHTTP();
        return $this->respbody;
    }

    /**
     * Do a POST HTTP request with the body in a custom format
     *
     * @param string $url POST destination URL
     * @param string $mime MIME type of the data
     * @param mixed $data Data to include in the body
     * @param array<string,string> $headers (optional) Extra HTTP headers
     * @return string Response data
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    function postRAW(string $url, string $mime, $data, array $headers = []): string {
        $this->method = 'POST';
        $this->url = $url;
        array_unshift($headers, 'Content-Type: ' . $mime);
        $this->mergeHeaders($headers);
        $this->body = json_encode($data);
        $this->execHTTP();
        return $this->respbody;
    }

    /**
     * Do a PUT HTTP request
     *
     * @param string $url POST destination URL
     * @param array<string,mixed> $data Associative array with POST parameters
     * @param array<string,string> $headers (optional) Extra HTTP headers
     * @return string Response data
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    function put(string $url, array $data, array $headers = []): string {
        $this->method = 'PUT';
        $this->url = $url;
        array_unshift($headers, 'Content-Type: application/x-www-form-urlencoded');
        $this->mergeHeaders($headers);
        $this->body = http_build_query($data);
        $this->execHTTP();
        return $this->respbody;
    }

    /**
     * Do a PUT HTTP request with the body data in JSON format
     *
     * @param string $url POST destination URL
     * @param mixed $data Data to include in the body
     * @param array<string,string> $headers (optional) Extra HTTP headers
     * @return string Response data
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    function putJSON(string $url, $data, array $headers = []): string {
        $this->method = 'PUT';
        $this->url = $url;
        array_unshift($headers, 'Content-Type: application/json');
        $this->mergeHeaders($headers);
        $this->body = json_encode($data);
        $this->execHTTP();
        return $this->respbody;
    }

    /**
     * Do a PUT HTTP request with the body in a custom format
     *
     * @param string $url POST destination URL
     * @param string $mime MIME type of the data
     * @param mixed $data Data to include in the body
     * @param array<string,string> $headers (optional) Extra HTTP headers
     * @return string Response data
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    function putRAW(string $url, string $mime, $data, array $headers = []): string {
        $this->method = 'PUT';
        $this->url = $url;
        array_unshift($headers, 'Content-Type: ' . $mime);
        $this->mergeHeaders($headers);
        $this->body = json_encode($data);
        $this->execHTTP();
        return $this->respbody;
    }

    /**
     * Do a PATCH HTTP request
     *
     * @param string $url POST destination URL
     * @param array $data Associative array with POST parameters
     * @param array<string,string> $headers (optional) Extra HTTP headers
     * @return string Response data
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    function patch(string $url, array $data, array $headers = []): string {
        $this->method = 'PATCH';
        $this->url = $url;
        array_unshift($headers, 'Content-Type: application/x-www-form-urlencoded');
        $this->mergeHeaders($headers);
        $this->body = http_build_query($data);
        $this->execHTTP();
        return $this->respbody;
    }

    /**
     * Do a PATCH HTTP request with the body data in JSON format
     *
     * @param string $url POST destination URL
     * @param mixed $data Data to include in the body
     * @param array<string,string> $headers (optional) Extra HTTP headers
     * @return string Response data
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    function patchJSON(string $url, $data, array $headers = []): string {
        $this->method = 'PATCH';
        $this->url = $url;
        array_unshift($headers, 'Content-Type: application/json');
        $this->mergeHeaders($headers);
        $this->body = json_encode($data);
        $this->execHTTP();
        return $this->respbody;
    }

    /**
     * Do a PATCH HTTP request with the body in a custom format
     *
     * @param string $url POST destination URL
     * @param string $mime MIME type of the data
     * @param mixed $data Data to include in the body
     * @param array<string,string> $headers (optional) Extra HTTP headers
     * @return string Response data
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    function patchRAW(string $url, string $mime, $data, array $headers = []): string {
        $this->method = 'PATCH';
        $this->url = $url;
        array_unshift($headers, 'Content-Type: ' . $mime);
        $this->mergeHeaders($headers);
        $this->body = json_encode($data);
        $this->execHTTP();
        return $this->respbody;
    }

    /**
     * Do a HEAD HTTP request
     *
     * @param string $url URL to retrieve
     * @param array<string,string> $headers Extra HTTP headers
     * @return string Data retrieved
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    function head(string $url, array $headers = []): string {
        $this->method = 'HEAD';
        $this->url = $url;
        $this->body = '';
        $this->mergeHeaders($headers);
        $this->execHTTP();
        return $this->respbody;
    }

    /**
     * Do a DELETE HTTP request
     *
     * @param string $url URL to retrieve
     * @param array<string,string> $headers Extra HTTP headers
     * @return string Data retrieved
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    function delete(string $url, array $headers = []): string {
        $this->method = 'DELETE';
        $this->url = $url;
        $this->body = '';
        $this->mergeHeaders($headers);
        $this->execHTTP();
        return $this->respbody;
    }

    /**
     * Do an OPTIONS HTTP request
     *
     * @param string $url URL to retrieve
     * @param array<string,string> $headers Extra HTTP headers
     * @return string Data retrieved
     * @throws InvalidArgumentException on invalid parameters
     * @throws RuntimeException on network error
     */
    function options(string $url, array $headers = []): string {
        $this->method = 'OPTIONS';
        $this->url = $url;
        $this->body = '';
        $this->mergeHeaders($headers);
        $this->execHTTP();
        return $this->respbody;
    }

    /**
     * Retrieve a PSR7 Response
     * 
     * This method return the result for the last request in a PSR7 message.
     * To use this method you must have installed one of the following packages:
     * httpsoft/http-message, nyholm/psr7, guzzle/psr7, laminas/laminas-diactoros
     * or slim/psr7
     * 
     * This method fires an Error if there isn't any PSR7 package installed
     * 
     * @return ResponseInterface Message in PSR7 format
     * @throws Error If there isn't any PSR7 package installed
     */
    function PSRResponse(): ResponseInterface {
        if (class_exists('HttpSoft\Message\Response')) {
            $factory = new HStream;
            return new HResponse($this->respcode, $this->respheaders, $factory->createStream($this->respbody), $this->protversion, $this->respstatus);
        }
        if (class_exists('Nyholm\Psr7\Response')) {
            return new NResponse($this->respcode, $this->respheaders, $this->respbody, $this->protversion, $this->respstatus);
        }
        if (class_exists('GuzzleHttp\Psr7\Response')) {
            return new GResponse($this->respcode, $this->respheaders, $this->respbody, $this->protversion, $this->respstatus);
        }
        if (class_exists('Laminas\Diactoros\Response')) {
            $factory = new LStream;
            return new LResponse($factory->createStream($this->respbody), $this->respcode, $this->respheaders);
        }
        if (class_exists('Slim\Psr7\Response')) {
            $h = new SHeaders($this->respheaders);
            $o = fopen('php://memory', 'r+');
            fwrite($o, $this->respbody);
            fseek($o, 0);
            return new SResponse($this->respcode, $h, new SSTream($o));
        }
        throw new Error(_('To use this method you must have installed one of the following packages') . ': ' . implode(', ',array_keys(self::RESPPACKAGES)));
    }

    /** @ignore */
    static public function verifyPSR7() {
        $out=new ConsoleOutput;
        foreach(self::RESPPACKAGES as $name=>$class) {
            if(class_exists($class)) {
                $out->writeln(sprintf('PSR7 will be provided by %s',$name));
                return;
            }
        }
        $out->writeln('<fg=red>There isn\'t any PSR7 package installed, you will not be able to use PSR7Response() method</>');
        $out->writeln('<fg=green>If you want to use it, you must install one of this packages:</>');
        foreach(self::RESPPACKAGES as $name=>$class) {
            $out->writeln('  <fg=blue>'.$name.'</>');
        }
        $out->writeln('<fg=green>-----</>');
    }

}
