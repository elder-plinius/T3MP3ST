<?php
// Request B — plain page; the pre-RINIT diagnostic (if any) consumes stale state here.
echo 'consumer page: PHP ' . PHP_VERSION . "\n";
$e = error_get_last();
if ($e) { echo 'last: ' . print_r($e, true) . "\n"; }
