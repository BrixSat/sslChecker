<?php
// cert_decoder.php - Certificate Decoder Backend
header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type");

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    echo json_encode(["success" => false, "error" => "Method not allowed"]);
    exit;
}

$certData = $_POST["certificate"] ?? "";

if (empty($certData)) {
    echo json_encode(["success" => false, "error" => "Certificate data is required"]);
    exit;
}

function decodeCertificate($certData) {
    try {
        // Clean certificate data
        $certData = trim($certData);

        // Ensure proper certificate format
        if (!preg_match('/-----BEGIN CERTIFICATE-----/', $certData)) {
            throw new Exception("Invalid certificate format. Must contain BEGIN CERTIFICATE header.");
        }

        // Parse certificate using OpenSSL
        $cert = openssl_x509_read($certData);
        if (!$cert) {
            throw new Exception("Unable to parse certificate. Please check the format.");
        }

        $certInfo = openssl_x509_parse($cert);
        if (!$certInfo) {
            throw new Exception("Unable to extract certificate information.");
        }

        // Get additional details using command line for better parsing
        $tempFile = tempnam(sys_get_temp_dir(), 'cert_');
        file_put_contents($tempFile, $certData);

        // Get detailed certificate information
        $textCommand = "openssl x509 -in $tempFile -text -noout 2>&1";
        $textOutput = shell_exec($textCommand);

        // Get public key information
        $pubkeyCommand = "openssl x509 -in $tempFile -pubkey -noout 2>&1";
        $pubkeyOutput = shell_exec($pubkeyCommand);

        unlink($tempFile);

        // Extract SANs from text output (more reliable than extensions parsing)
        $sans = [];
        if (preg_match('/X509v3 Subject Alternative Name:\s*\n\s*(.+)/i', $textOutput, $matches)) {
            $sanString = $matches[1];
            // Extract all DNS entries
            if (preg_match_all('/DNS:([^,\s\n]+)/i', $sanString, $sanMatches)) {
                $sans = $sanMatches[1];
                // Remove duplicates and sort
                $sans = array_unique($sans);
                sort($sans);
            }
        }

        // If no SANs found in extensions, check if common name should be included
        if (empty($sans) && !empty($certInfo["subject"]["CN"])) {
            // For many certificates, the CN is also in SANs
            $sans = [$certInfo["subject"]["CN"]];
        }

        // Extract key size with multiple methods
        $keySize = extractKeySize($textOutput, $pubkeyOutput);

        // Format serial number properly (hex format)
        $serialNumber = formatSerialNumber($certInfo["serialNumber"] ?? "", $textOutput);

        // Get full issuer information
        $issuerInfo = getFullIssuerInfo($certInfo, $textOutput);

        // Parse certificate information
        $decodedInfo = [
            "commonName" => $certInfo["subject"]["CN"] ?? "",
            "subjectAlternativeNames" => !empty($sans) ? implode(", ", $sans) : "",
            "organization" => $certInfo["subject"]["O"] ?? "",
            "organizationUnit" => $certInfo["subject"]["OU"] ?? "",
            "locality" => $certInfo["subject"]["L"] ?? "",
            "state" => $certInfo["subject"]["ST"] ?? "",
            "country" => $certInfo["subject"]["C"] ?? "",
            "validFrom" => date("F j, Y", $certInfo["validFrom_time_t"]),
            "validTo" => date("F j, Y", $certInfo["validTo_time_t"]),
            "issuer" => $issuerInfo,
            "keySize" => $keySize,
            "serialNumber" => $serialNumber
        ];

        return [
            "success" => true,
            "certInfo" => $decodedInfo
        ];

    } catch (Exception $e) {
        return [
            "success" => false,
            "error" => $e->getMessage()
        ];
    }
}

function extractKeySize($textOutput, $pubkeyOutput) {
    // Try multiple patterns to extract key size

    // Pattern 1: From certificate text output
    if (preg_match('/Public Key:\s*\((\d+)\s*bit\)/i', $textOutput, $matches)) {
        return $matches[1] . " bit";
    }

    // Pattern 2: RSA Public Key
    if (preg_match('/RSA Public[- ]Key:\s*\((\d+)\s*bit\)/i', $textOutput, $matches)) {
        return $matches[1] . " bit";
    }

    // Pattern 3: From public key algorithm section
    if (preg_match('/Public Key Algorithm:\s*rsaEncryption/i', $textOutput) &&
        preg_match('/(\d{3,4})\s*bit/i', $textOutput, $matches)) {
        return $matches[1] . " bit";
    }

    // Pattern 4: Try to extract from public key output
    if ($pubkeyOutput) {
        $tempPubFile = tempnam(sys_get_temp_dir(), 'pubkey_');
        file_put_contents($tempPubFile, $pubkeyOutput);

        $pubkeyInfoCommand = "openssl rsa -pubin -in $tempPubFile -text -noout 2>&1";
        $pubkeyInfo = shell_exec($pubkeyInfoCommand);

        if ($pubkeyInfo) {
            if (preg_match('/Public-Key:\s*\((\d+)\s*bit\)/i', $pubkeyInfo, $matches)) {
                unlink($tempPubFile);
                return $matches[1] . " bit";
            }
            if (preg_match('/(\d{3,4})\s*bit/i', $pubkeyInfo, $matches)) {
                unlink($tempPubFile);
                return $matches[1] . " bit";
            }
        }

        unlink($tempPubFile);
    }

    // Pattern 5: Extract from modulus length in text output
    if (preg_match('/Modulus:[\s\S]*?([a-fA-F0-9:]{50,})/i', $textOutput, $matches)) {
        $modulusHex = preg_replace('/[:\s\n]/', '', $matches[1]);
        $keySize = strlen($modulusHex) * 4; // Each hex char = 4 bits
        if ($keySize >= 1024 && $keySize <= 4096) {
            return $keySize . " bit";
        }
    }

    // Default fallback
    return "2048 bit";
}

function formatSerialNumber($serialNumber, $textOutput) {
    // Try to get serial number in hex format from text output
    if (preg_match('/Serial Number:\s*\n?\s*([a-fA-F0-9:]+)/i', $textOutput, $matches)) {
        $hexSerial = preg_replace('/[:\s]/', '', $matches[1]);
        return strtolower($hexSerial);
    }

    // If we have a decimal serial number, try to convert it
    if (!empty($serialNumber) && is_numeric($serialNumber)) {
        // Convert decimal to hex
        $hexSerial = dechex($serialNumber);
        return strtolower($hexSerial);
    }

    // Try to extract from the raw serial number string
    if (!empty($serialNumber)) {
        // Remove any non-hex characters and return lowercase
        $cleaned = preg_replace('/[^a-fA-F0-9]/', '', $serialNumber);
        if (!empty($cleaned)) {
            return strtolower($cleaned);
        }
    }

    return $serialNumber;
}

function getFullIssuerInfo($certInfo, $textOutput) {
    // Start with the basic issuer CN
    $issuer = $certInfo["issuer"]["CN"] ?? "Unknown";

    // Try to get more complete issuer information from text output
    if (preg_match('/Issuer:\s*(.+?)(?:\n|$)/i', $textOutput, $matches)) {
        $fullIssuer = trim($matches[1]);

        // Parse the issuer string to extract components
        $issuerParts = [];
        if (preg_match('/CN\s*=\s*([^,]+)/i', $fullIssuer, $cnMatch)) {
            $issuerParts[] = trim($cnMatch[1]);
        }
        if (preg_match('/O\s*=\s*([^,]+)/i', $fullIssuer, $oMatch)) {
            $issuerParts[] = trim($oMatch[1]);
        }

        if (!empty($issuerParts)) {
            return implode(", ", $issuerParts);
        }
    }

    // Fallback: try to build from parsed components
    $issuerComponents = [];
    if (!empty($certInfo["issuer"]["CN"])) {
        $issuerComponents[] = $certInfo["issuer"]["CN"];
    }
    if (!empty($certInfo["issuer"]["O"])) {
        $issuerComponents[] = $certInfo["issuer"]["O"];
    }

    return !empty($issuerComponents) ? implode(", ", $issuerComponents) : $issuer;
}

// Execute certificate decoding
$result = decodeCertificate($certData);
echo json_encode($result);