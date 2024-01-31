<?php

require_once '../src/simpleHTTP.php';

try {
    // Build object configured to fire exception on any error
    $http = new simpleHTTP(2);
    // Set the authorization and contect accept headers
    $http->setExtraheaders(['Authorization: Bearer TestToken', 'Accept: application/json']);
    // Call REST test service
    $resp = json_decode($http->get('https://reqbin.com/echo/get/json'));
    print_r($resp);
} catch (Exception $e) {
    // Print error, if any
    printf("Error: <%d:%s>\n", $e->getCode(), $e->getMessage());
}

