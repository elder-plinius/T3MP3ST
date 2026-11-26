<?php
$body = file_get_contents('php://input');
echo 'body_bytes=' . strlen($body) . "\n";
echo 'post_count=' . count($_POST) . "\n";
echo 'files_count=' . count($_FILES) . "\n";
echo 'memory_peak=' . memory_get_peak_usage(true) . "\n";
echo 'memory_limit=' . ini_get('memory_limit') . "\n";
