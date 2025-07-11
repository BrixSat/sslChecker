<?php
// file_download.php - File Download Handler
if (isset($_GET['file']) && isset($_GET['content'])) {
    $filename = $_GET['file'];
    $content = base64_decode($_GET['content']);

    // Set appropriate headers
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Content-Length: ' . strlen($content));

    // Output the file content
    echo $content;
    exit;
}

http_response_code(400);
echo "Invalid download request";
