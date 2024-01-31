<?php

require_once '../src/simpleHTTP.php';

try {
    // Build object configured to fire exception on any error
    $http = new simpleHTTP(2, true);

    // Set the authorization header
    $http->setExtraheaders(['Authorization: Bearer TestToken']);
    // Set data
    $data = [
        'name' => 'John',
        'surname' => 'Smith',
        'email' => 'john.smith@example.com'
    ];
    // Call REST test service
    $resp = json_decode($http->postJSON('https://reqbin.com/echo/post/json', $data));
    print_r($resp);
} catch (Exception $e) {
    // Print error, if any
    printf("Error: <%d:%s>\n", $e->getCode(), $e->getMessage());
}

