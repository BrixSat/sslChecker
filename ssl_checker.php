<?php
// ssl_checker.php - SSL Certificate Checker Backend
header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type");

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    echo json_encode(["success" => false, "error" => "Method not allowed"]);
    exit;
}

$hostname = $_POST["hostname"] ?? "";

if (empty($hostname)) {
    echo json_encode(["success" => false, "error" => "Hostname is required"]);
    exit;
}

function checkSSLCertificate($hostname) {
    try {
        // Create SSL context
        $context = stream_context_create([
            "ssl" => [
                "capture_peer_cert" => true,
                "capture_peer_cert_chain" => true,
                "verify_peer" => false,
                "verify_peer_name" => false,
                "allow_self_signed" => true
            ]
        ]);

        // Try to connect to the hostname
        $socket = @stream_socket_client(
            "ssl://{$hostname}:443",
            $errno,
            $errstr,
            30,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if (!$socket) {
            throw new Exception("Unable to connect to {$hostname}:443 - {$errstr}");
        }

        // Get stream context parameters
        $params = stream_context_get_params($socket);
        $cert = $params["options"]["ssl"]["peer_certificate"];
        $chain = $params["options"]["ssl"]["peer_certificate_chain"] ?? [];

        fclose($socket);

        if (!$cert) {
            throw new Exception("No certificate found");
        }

        // Parse main certificate
        $certData = openssl_x509_parse($cert);

        // Get IP address
        $resolvedIP = gethostbyname($hostname);

        // Calculate days until expiry
        $expiryDate = $certData["validTo_time_t"];
        $daysUntilExpiry = floor(($expiryDate - time()) / (24 * 60 * 60));

        // Check if hostname matches
        $hostnameMatch = checkHostnameMatch($hostname, $certData);

        // Get SANs
        $sans = [];
        if (isset($certData["extensions"]["subjectAltName"])) {
            $sanString = $certData["extensions"]["subjectAltName"];
            preg_match_all("/DNS:([^,]+)/", $sanString, $matches);
            $sans = $matches[1];
        }

        // Process certificate chain
        $certificateChain = [];
        $chainValid = true;

        // Add main certificate
        $certificateChain[] = [
            "commonName" => $certData["subject"]["CN"] ?? "Unknown",
            "organization" => $certData["subject"]["O"] ?? "",
            "location" => getLocationString($certData["subject"]),
            "validFrom" => date("F j, Y", $certData["validFrom_time_t"]),
            "validTo" => date("F j, Y", $certData["validTo_time_t"]),
            "serialNumber" => $certData["serialNumber"] ?? "",
            "signatureAlgorithm" => $certData["signatureTypeLN"] ?? "",
            "issuer" => $certData["issuer"]["CN"] ?? "Unknown",
            "isValid" => $daysUntilExpiry > 0
        ];

        // Process intermediate certificates
        foreach ($chain as $intermediateCert) {
            $intermediateData = openssl_x509_parse($intermediateCert);
            $intermediateExpiry = floor(($intermediateData["validTo_time_t"] - time()) / (24 * 60 * 60));

            $certificateChain[] = [
                "commonName" => $intermediateData["subject"]["CN"] ?? "Unknown",
                "organization" => $intermediateData["subject"]["O"] ?? "",
                "location" => getLocationString($intermediateData["subject"]),
                "validFrom" => date("F j, Y", $intermediateData["validFrom_time_t"]),
                "validTo" => date("F j, Y", $intermediateData["validTo_time_t"]),
                "serialNumber" => $intermediateData["serialNumber"] ?? "",
                "signatureAlgorithm" => $intermediateData["signatureTypeLN"] ?? "",
                "issuer" => $intermediateData["issuer"]["CN"] ?? "Unknown",
                "isValid" => $intermediateExpiry > 0
            ];

            if ($intermediateExpiry <= 0) {
                $chainValid = false;
            }
        }

        // Determine if certificate is trusted
        $isTrusted = count($chain) > 0 && $chainValid;

        // Get server type
        $serverType = getServerType($hostname);

        return [
            "success" => true,
            "hostname" => $hostname,
            "resolvedIP" => $resolvedIP,
            "serverType" => $serverType,
            "isValid" => $daysUntilExpiry > 0,
            "isTrusted" => $isTrusted,
            "chainValid" => $chainValid,
            "issuer" => $certData["issuer"]["CN"] ?? "Unknown",
            "commonName" => $certData["subject"]["CN"] ?? "Unknown",
            "sans" => $sans,
            "validFrom" => date("F j, Y", $certData["validFrom_time_t"]),
            "validTo" => date("F j, Y", $certData["validTo_time_t"]),
            "daysUntilExpiry" => $daysUntilExpiry,
            "serialNumber" => $certData["serialNumber"] ?? "",
            "signatureAlgorithm" => $certData["signatureTypeLN"] ?? "",
            "hostnameMatch" => $hostnameMatch,
            "certificateChain" => $certificateChain
        ];

    } catch (Exception $e) {
        return [
            "success" => false,
            "error" => $e->getMessage()
        ];
    }
}

function checkHostnameMatch($hostname, $certData) {
    // Check common name
    $commonName = $certData["subject"]["CN"] ?? "";
    if (matchesHostname($hostname, $commonName)) {
        return true;
    }

    // Check SANs
    if (isset($certData["extensions"]["subjectAltName"])) {
        $sanString = $certData["extensions"]["subjectAltName"];
        preg_match_all("/DNS:([^,]+)/", $sanString, $matches);
        foreach ($matches[1] as $san) {
            if (matchesHostname($hostname, $san)) {
                return true;
            }
        }
    }

    return false;
}

function matchesHostname($hostname, $pattern) {
    // Handle wildcard certificates
    if (strpos($pattern, "*") !== false) {
        $pattern = str_replace("*", ".*", $pattern);
        return preg_match("/^" . $pattern . "$/i", $hostname);
    }

    return strcasecmp($hostname, $pattern) === 0;
}

function getLocationString($subject) {
    $location = [];
    if (isset($subject["L"])) $location[] = $subject["L"];
    if (isset($subject["ST"])) $location[] = $subject["ST"];
    if (isset($subject["C"])) $location[] = $subject["C"];
    return implode(", ", $location);
}

function getServerType($hostname) {
    // Try to get server header
    $headers = @get_headers("https://{$hostname}", 1);
    if ($headers && isset($headers["Server"])) {
        return is_array($headers["Server"]) ? $headers["Server"][0] : $headers["Server"];
    }

    // Try to detect common CDNs/services
    $ip = gethostbyname($hostname);

    // Cloudflare IP ranges (simplified check)
    if (strpos($ip, "104.") === 0 || strpos($ip, "172.") === 0) {
        return "cloudflare";
    }

    return "Unknown";
}

// Execute the SSL check
$result = checkSSLCertificate($hostname);
echo json_encode($result);