<?php
// csr_decoder.php - CSR Decoder Backend
header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type");

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    echo json_encode(["success" => false, "error" => "Method not allowed"]);
    exit;
}

$csrData = $_POST["csr"] ?? "";

if (empty($csrData)) {
    echo json_encode(["success" => false, "error" => "CSR data is required"]);
    exit;
}

function decodeCSR($csrData) {
    try {
        // Clean CSR data
        $csrData = trim($csrData);

        // Ensure proper CSR format
        if (!preg_match('/-----BEGIN CERTIFICATE REQUEST-----/', $csrData)) {
            throw new Exception("Invalid CSR format. Must contain BEGIN CERTIFICATE REQUEST header.");
        }

        // Create temporary file for CSR
        $tempFile = tempnam(sys_get_temp_dir(), 'csr_');
        file_put_contents($tempFile, $csrData);

        // Use multiple OpenSSL commands to get comprehensive information
        $textCommand = "openssl req -in $tempFile -text -noout 2>&1";
        $subjectCommand = "openssl req -in $tempFile -subject -noout 2>&1";
        $pubkeyCommand = "openssl req -in $tempFile -pubkey -noout 2>&1";

        $textOutput = shell_exec($textCommand);
        $subjectOutput = shell_exec($subjectCommand);
        $pubkeyOutput = shell_exec($pubkeyCommand);

        // Clean up temp file
        unlink($tempFile);

        if (!$textOutput || strpos($textOutput, 'unable to load') !== false) {
            throw new Exception("Unable to decode CSR. Please check the format.");
        }

        // Parse the outputs
        $csrInfo = parseCSROutput($textOutput, $subjectOutput);

        // If we still don't have key size, try to extract from public key
        if (empty($csrInfo["keySize"]) && $pubkeyOutput) {
            $tempPubFile = tempnam(sys_get_temp_dir(), 'pubkey_');
            file_put_contents($tempPubFile, $pubkeyOutput);

            $pubkeyInfoCommand = "openssl rsa -pubin -in $tempPubFile -text -noout 2>&1";
            $pubkeyInfo = shell_exec($pubkeyInfoCommand);

            if ($pubkeyInfo && preg_match('/Public-Key:\s*\((\d+)\s*bit\)/i', $pubkeyInfo, $matches)) {
                $csrInfo["keySize"] = $matches[1] . " bit";
            } elseif ($pubkeyInfo && preg_match('/(\d{3,4})\s*bit/i', $pubkeyInfo, $matches)) {
                $csrInfo["keySize"] = $matches[1] . " bit";
            }

            unlink($tempPubFile);
        }

        // Set default key size if still not found
        if (empty($csrInfo["keySize"])) {
            $csrInfo["keySize"] = "2048 bit"; // Most common default
        }

        return [
            "success" => true,
            "csrInfo" => $csrInfo
        ];

    } catch (Exception $e) {
        return [
            "success" => false,
            "error" => $e->getMessage()
        ];
    }
}

function parseCSROutput($output, $subjectOutput) {
    $info = [
        "commonName" => "",
        "organization" => "",
        "organizationUnit" => "",
        "locality" => "",
        "state" => "",
        "country" => "",
        "keySize" => ""
    ];

    // Parse subject line with better regex patterns
    if (preg_match('/subject=(.+)/', $subjectOutput, $matches)) {
        $subject = $matches[1];

        // Extract common name - handle quotes and special characters
        if (preg_match('/CN\s*=\s*([^,\/]+?)(?:\s*[,\/]|$)/', $subject, $matches)) {
            $info["commonName"] = trim($matches[1], ' "\'');
        }

        // Extract organization - handle quotes and commas properly
        if (preg_match('/(?:^|[,\/])\s*O\s*=\s*([^,\/]+?)(?:\s*[,\/]|$)/', $subject, $matches)) {
            $info["organization"] = trim($matches[1], ' "\'');
        }

        // Extract organization unit
        if (preg_match('/(?:^|[,\/])\s*OU\s*=\s*([^,\/]+?)(?:\s*[,\/]|$)/', $subject, $matches)) {
            $info["organizationUnit"] = trim($matches[1], ' "\'');
        }

        // Extract locality
        if (preg_match('/(?:^|[,\/])\s*L\s*=\s*([^,\/]+?)(?:\s*[,\/]|$)/', $subject, $matches)) {
            $info["locality"] = trim($matches[1], ' "\'');
        }

        // Extract state
        if (preg_match('/(?:^|[,\/])\s*ST\s*=\s*([^,\/]+?)(?:\s*[,\/]|$)/', $subject, $matches)) {
            $info["state"] = trim($matches[1], ' "\'');
        }

        // Extract country
        if (preg_match('/(?:^|[,\/])\s*C\s*=\s*([^,\/]+?)(?:\s*[,\/]|$)/', $subject, $matches)) {
            $info["country"] = trim($matches[1], ' "\'');
        }
    }

    // Extract key size with multiple patterns
    if (preg_match('/Public[- ]Key:\s*\((\d+)\s*bit\)/i', $output, $matches)) {
        $info["keySize"] = $matches[1] . " bit";
    } elseif (preg_match('/RSA Public[- ]Key:\s*\((\d+)\s*bit\)/i', $output, $matches)) {
        $info["keySize"] = $matches[1] . " bit";
    } elseif (preg_match('/Public[- ]Key Algorithm:\s*rsaEncryption/i', $output) && preg_match('/(\d{3,4})\s*bit/i', $output, $matches)) {
        $info["keySize"] = $matches[1] . " bit";
    } elseif (preg_match('/Modulus \((\d+) bit\)/', $output, $matches)) {
        $info["keySize"] = $matches[1] . " bit";
    }

    // If we still don't have key size, try alternative method
    if (empty($info["keySize"])) {
        // Try to extract from modulus length
        if (preg_match('/Modulus:[\s\S]*?([a-fA-F0-9:]{2,})/', $output, $matches)) {
            $modulusHex = preg_replace('/[:\s]/', '', $matches[1]);
            $keySize = strlen($modulusHex) * 4; // Each hex char = 4 bits
            if ($keySize >= 1024 && $keySize <= 4096) {
                $info["keySize"] = $keySize . " bit";
            }
        }
    }

    return $info;
}

// Execute CSR decoding
$result = decodeCSR($csrData);
echo json_encode($result);