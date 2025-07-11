
<?php
// ssl_converter.php - SSL Certificate Converter Backend
header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type");

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    echo json_encode(["success" => false, "error" => "Method not allowed"]);
    exit;
}

// Handle file upload
if (!isset($_FILES['certificate']) || $_FILES['certificate']['error'] !== UPLOAD_ERR_OK) {
    echo json_encode(["success" => false, "error" => "No file uploaded or upload error"]);
    exit;
}

$fromFormat = $_POST["fromFormat"] ?? "";
$toFormat = $_POST["toFormat"] ?? "";
$pfxPassword = $_POST["pfxPassword"] ?? "";

if (empty($fromFormat) || empty($toFormat)) {
    echo json_encode(["success" => false, "error" => "Format parameters are required"]);
    exit;
}

function convertCertificate($inputFile, $fromFormat, $toFormat, $pfxPassword = "") {
    try {
        $outputDir = sys_get_temp_dir();
        $outputFile = tempnam($outputDir, 'converted_');

        // Define conversion commands
        $commands = [];

        switch ($fromFormat) {
            case 'pem':
                switch ($toFormat) {
                    case 'der':
                        $commands[] = "openssl x509 -outform der -in $inputFile -out $outputFile";
                        $extension = '.der';
                        break;
                    case 'p7b':
                        $commands[] = "openssl crl2pkcs7 -nocrl -certfile $inputFile -out $outputFile";
                        $extension = '.p7b';
                        break;
                    case 'pfx':
                        // Note: This requires both certificate and private key
                        echo json_encode([
                            "success" => false,
                            "error" => "Converting PEM to PFX requires both certificate and private key files"
                        ]);
                        return;
                        break;
                }
                break;

            case 'der':
                switch ($toFormat) {
                    case 'pem':
                        $commands[] = "openssl x509 -inform der -in $inputFile -out $outputFile";
                        $extension = '.pem';
                        break;
                }
                break;

            case 'p7b':
                switch ($toFormat) {
                    case 'pem':
                        $commands[] = "openssl pkcs7 -print_certs -in $inputFile -out $outputFile";
                        $extension = '.pem';
                        break;
                    case 'pfx':
                        $tempPem = tempnam($outputDir, 'temp_pem_');
                        $commands[] = "openssl pkcs7 -print_certs -in $inputFile -out $tempPem";
                        // Note: This also requires private key
                        echo json_encode([
                            "success" => false,
                            "error" => "Converting P7B to PFX requires a private key file"
                        ]);
                        return;
                        break;
                }
                break;

            case 'pfx':
                switch ($toFormat) {
                    case 'pem':
                        if (empty($pfxPassword)) {
                            echo json_encode([
                                "success" => false,
                                "error" => "PFX password is required for conversion"
                            ]);
                            return;
                        }
                        $commands[] = "openssl pkcs12 -in $inputFile -out $outputFile -nodes -passin pass:$pfxPassword";
                        $extension = '.pem';
                        break;
                }
                break;

            default:
                throw new Exception("Unsupported conversion: $fromFormat to $toFormat");
        }

        // Execute conversion commands
        foreach ($commands as $command) {
            $output = shell_exec($command . " 2>&1");
            if (strpos($output, 'unable to load') !== false ||
                strpos($output, 'error') !== false) {
                throw new Exception("Conversion failed: " . $output);
            }
        }

        // Check if output file was created
        if (!file_exists($outputFile) || filesize($outputFile) == 0) {
            throw new Exception("Conversion failed - no output generated");
        }

        // Generate download filename
        $downloadFilename = "converted_certificate" . $extension;

        // Read converted file content
        $convertedContent = file_get_contents($outputFile);

        // Clean up temp file
        unlink($outputFile);

        // Encode content for download
        $base64Content = base64_encode($convertedContent);

        return [
            "success" => true,
            "filename" => $downloadFilename,
            "content" => $base64Content,
            "size" => formatBytes(strlen($convertedContent)),
            "originalFormat" => strtoupper($fromFormat),
            "convertedFormat" => strtoupper($toFormat)
        ];

    } catch (Exception $e) {
        return [
            "success" => false,
            "error" => $e->getMessage()
        ];
    }
}

function formatBytes($size, $precision = 2) {
    $units = array('B', 'KB', 'MB', 'GB');
    for ($i = 0; $size > 1024 && $i < count($units) - 1; $i++) {
        $size /= 1024;
    }
    return round($size, $precision) . ' ' . $units[$i];
}

// Get uploaded file path
$uploadedFile = $_FILES['certificate']['tmp_name'];

// Execute conversion
$result = convertCertificate($uploadedFile, $fromFormat, $toFormat, $pfxPassword);
echo json_encode($result);
?>

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