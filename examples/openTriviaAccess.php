<?php

require_once '../src/simpleHTTP.php';

// Build object with disabled exceptions and certificate validation
$http = new simpleHTTP(0, false);
// Call Open Trivia Database. We add an extra header to change default User-Agent header
$resp = json_decode($http->get('https://opentdb.com/api.php?amount=2&category=30', ['User-Agent: Test/1.0']));
// Print response
print_r($resp);
// Print status codes
printf("Respnse: <%d:%s>\n", $http->respCode(), $http->respStatus());
