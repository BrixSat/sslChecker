<?php
// key_matcher.php - Certificate and Key Matcher Backend
header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type");

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    echo json_encode(["success" => false, "error" => "Method not allowed"]);
    exit;
}

$matchType = $_POST["matchType"] ?? "";
$item1 = $_POST["item1"] ?? "";
$item2 = $_POST["item2"] ?? "";

if (empty($matchType) || empty($item1) || empty($item2)) {
    echo json_encode(["success" => false, "error" => "All fields are required"]);
    exit;
}

function checkCertificateKeyMatch($certificate, $privateKey) {
    try {
        // Create temporary files
        $certFile = tempnam(sys_get_temp_dir(), 'cert_');
        $keyFile = tempnam(sys_get_temp_dir(), 'key_');

        file_put_contents($certFile, $certificate);
        file_put_contents($keyFile, $privateKey);

        // SSL Shopper method: openssl x509 -in certificate.crt -pubkey -noout -outform pem | sha256sum
        $certPubKeyCommand = "openssl x509 -in $certFile -pubkey -noout -outform pem 2>&1";
        $certPubKey = shell_exec($certPubKeyCommand);

        // SSL Shopper method: openssl pkey -in privateKey.key -pubout -outform pem | sha256sum
        $keyPubKeyCommand = "openssl pkey -in $keyFile -pubout -outform pem 2>&1";
        $keyPubKey = shell_exec($keyPubKeyCommand);

        // Clean up temp files
        unlink($certFile);
        unlink($keyFile);

        // Check if we got valid public keys
        if (empty($certPubKey) || empty($keyPubKey)) {
            throw new Exception("Unable to extract public keys");
        }

        // Generate SHA256 hashes exactly like SSL Shopper
        $certHash = hash('sha256', $certPubKey);
        $keyHash = hash('sha256', $keyPubKey);

        $match = ($certHash === $keyHash);

        return [
            "success" => true,
            "match" => $match,
            "certHash" => $certHash,
            "keyHash" => $keyHash,
            "type" => "cert-key"
        ];

    } catch (Exception $e) {
        return [
            "success" => false,
            "error" => $e->getMessage()
        ];
    }
}

function checkCSRCertificateMatch($csr, $certificate) {
    try {
        // Create temporary files
        $csrFile = tempnam(sys_get_temp_dir(), 'csr_');
        $certFile = tempnam(sys_get_temp_dir(), 'cert_');

        file_put_contents($csrFile, $csr);
        file_put_contents($certFile, $certificate);

        // SSL Shopper method: openssl req -in CSR.csr -pubkey -noout -outform pem | sha256sum
        $csrPubKeyCommand = "openssl req -in $csrFile -pubkey -noout -outform pem 2>&1";
        $csrPubKey = shell_exec($csrPubKeyCommand);

        // SSL Shopper method: openssl x509 -in certificate.crt -pubkey -noout -outform pem | sha256sum
        $certPubKeyCommand = "openssl x509 -in $certFile -pubkey -noout -outform pem 2>&1";
        $certPubKey = shell_exec($certPubKeyCommand);

        // Clean up temp files
        unlink($csrFile);
        unlink($certFile);

        // Check if we got valid public keys
        if (empty($csrPubKey) || empty($certPubKey)) {
            throw new Exception("Unable to extract public keys");
        }

        // Generate SHA256 hashes exactly like SSL Shopper
        $csrHash = hash('sha256', $csrPubKey);
        $certHash = hash('sha256', $certPubKey);

        $match = ($csrHash === $certHash);

        return [
            "success" => true,
            "match" => $match,
            "certHash" => $certHash,
            "keyHash" => $csrHash,
            "type" => "csr-cert"
        ];

    } catch (Exception $e) {
        return [
            "success" => false,
            "error" => $e->getMessage()
        ];
    }
}

// Execute matching based on type
if ($matchType === "cert-key") {
    $result = checkCertificateKeyMatch($item1, $item2);
} elseif ($matchType === "csr-cert") {
    $result = checkCSRCertificateMatch($item1, $item2);
} else {
    $result = ["success" => false, "error" => "Invalid match type"];
}

echo json_encode($result);