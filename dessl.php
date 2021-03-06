<?php

/**
 * deSSL Proxy
 *
 * Because some software screws up big time with TLS/SSL and
 *   ain't nobody got time for that.
 *
 * Essentially, an HTTPS proxy built to deal with TLS/SSL for clients who can't.
 */

include_once "config.php";

/**
 * Generates an HMAC for a given URL
 * @param  string $url The URL used as the message for the HMAC
 * @return string The HMAC for the given URL in raw binary form
 */
function generate_hmac($url) {
    return hash_hmac(DESSL_HMAC_ALGO, $url, DESSL_HMAC_SECRET, true);
}

/**
 * Verifies a given url against a HMAC
 * @param string $hmac The HMAC used to verify authenticity
 * @param string $url The URL to check against the HMAC
 * @return bool TRUE if the URL verifies against the HMAC; FALSE otherwise.
 */
function verify_hmac($hmac, $url) {
    return $hmac === generate_hmac($url);
}

/**
 * Encodes data in base64, with / and + swapped by _ and - respectively.
 * @param string $data The data to be encoded
 * @return string Encoded data in base64.
 */
function base64_urlsafe_encode($data) {
    return strtr(base64_encode($data), '/+', '_-');
}

/**
 * Decodes data in base64 format, with / and + swapped by _ and - respectively.
 * @param string $data The base64 encoded data
 * @return string Decoded data, or FALSE on failure.
 */
function base64_urlsafe_decode($data) {
    return base64_decode(strtr($data, '_-', '/+'));
}

/**
 * Generates a deSSL URL to proxy a given URL
 * @param string $url The URL to proxy
 * @return string A relative URL that proxies the given URL
 */
function generate_proxy_url($url) {
    return '/' . base64_urlsafe_encode(generate_hmac($url) . $url);
}

/**
 * Parses a deSSL URL into its components and verifies the authenticity of the
 * request
 * @param string $proxy_url The URL used to access the deSSL proxy
 * @return string|bool The URL in string form, or 'FALSE' if the decoding or
 *      HMAC verification fails.
 */
function parse_proxy_url($proxy_url) {
    $decoded = base64_urlsafe_decode(trim($proxy_url, '/'));

    $url = FALSE;
    if ($decoded !== FALSE && strlen($decoded) > DESSL_HMAC_LENGTH) {
        $hmac = substr($decoded, 0, DESSL_HMAC_LENGTH);
        $pre_url = substr($decoded, DESSL_HMAC_LENGTH);

        if (verify_hmac($hmac, $pre_url)) {
            $url = $pre_url;
        }
    }

    return $url;
}

/**
 * Fetches the value for a given header field name
 * @param  string $header The header field name
 * @return bool|string The value or FALSE if the $header is not present
 */
function get_request_header($header) {
    $header_key = 'HTTP_' . strtoupper(strtr($header, '-', '_'));

    $value = false;
    if (array_key_exists($header_key, $_SERVER)) {
        $value = $_SERVER[$header_key];
    }

    return $value;
}

/**
 * Fetches the valid HTTP headers in the request for this proxy to use with cURL
 * @return array An array with formatted header field strings
 */
function get_request_headers_curl() {
    $filter_headers = [
        // RFC 7231, 5.1. Controls
        'Cache-Control',
        'Expect',
        'Range',
        'TE',

        // RFC 7231, 5.2. Conditionals
        'If-Match',
        'If-None-Match',
        'If-Modified-Since',
        'If-Unmodified-Since',
        'If-Range',

        // RFC 7231, 5.3. Content Negotiation
        'Accept',
        'Accept-Charset',
        'Accept-Encoding',
        'Accept-Language',

        // RFC 7231, 5.4. Authentication
        'Authorization',
        'Proxy-Authorization'
    ];

    $proxy_headers = [];
    foreach ($filter_headers as $header) {
        if ($req_header = get_request_header($header)) {
            $proxy_headers[] = "${header}: ${req_header}";
        }
    }

    return $proxy_headers;
}

/**
 * Sets the HTTP header for the proxy response. The header fields are filtered
 * before being set so only proper headers are emited.
 * @param int $status The HTTP response status code
 * @param array $headers An key/value array with headers to set
 */
function set_response_headers($status, $headers) {
    $filter_headers = [
        // RFC 7231, 3.1. Representation Metadata
        'Content-Type',
        'Content-Encoding',
        'Content-Language',
        'Content-Location',

        // RFC 7231, 3.2. Payload Semantics
        'Content-Length',
        'Content-Range',
        'Trailer',

        // RFC 7231, 7.1. Control Data
        // Location is missing since it must be rewritten
        'Age',
        'Cache-Control',
        'Expires',
        'Date',
        'Retry-After',
        'Vary',
        'Warning',

        // RFC 7231, 7.2. Validator Header Fields
        'ETag',
        'Last-Modified',

        // RFC 7231, 7.3. Authentication Challenges
        'WWW-Authenticate',
        'Proxy-Authenticate',

        // RFC 7231, 7.4. Response Context
        'Accept-Ranges',
        'Allow',
        'Server'
    ];

    http_response_code($status);

    foreach ($filter_headers as $header) {
        if (array_key_exists($header, $headers)) {
            header("${header}: ${headers[$header]}");
        }
    }

    // Deal with redirections
    if (in_array($status, [301, 302, 303, 307])
        && array_key_exists('Location', $headers)) {
        header('Location: ' . generate_proxy_url($headers['Location']));
    }
}

/**
 * Parses an HTTP Header string
 * @param  string $headers A string of HTTP Headers
 * @return array An key/value array with the fields in the suppied HTTP header
 */
function parse_http_headers($headers) {
    $parsed = [];

    foreach (preg_split('/\r?\n/', $headers) as $field) {
        $field_split = explode(':', $field, 2);
        if (count($field_split) == 2) {
            $parsed[trim($field_split[0])] = trim($field_split[1]);
        }
    }

    return $parsed;
}

/**
 * Fetches a given URL with cURL. If the URL has an HTTPS protocol this fails if
 * the certificate is not valid.
 * @param  string $url The URL to fetch
 * @return array An array with the HTTP response status code, array of HTTP
 *      header fields and reponse body.
 */
function make_curl_request($url) {
    $curl_req = curl_init($url);

    curl_setopt_array($curl_req, [
        CURLOPT_HEADER => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => DESSL_FOLLOW_REDIRECT,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_CAINFO => DESSL_CA_CERT_BUNDLE_PATH,
        CURLOPT_HTTPHEADER => get_request_headers_curl()
    ]);

    // Make request
    $curl_result = curl_exec($curl_req);
    if ($curl_result === FALSE) {
        $curl_error_code = curl_errno($curl_req);
        $curl_error_message = curl_error($curl_req);
        exit_status(500, "cURL error: $curl_error_message ($curl_error_code)");
    }
    $curl_info = curl_getinfo($curl_req);

    // Parse response
    $header_size = $curl_info['header_size'];
    $headers = parse_http_headers(substr($curl_result, 0, $header_size));
    $body = substr($curl_result, $header_size);

    curl_close($curl_req);

    return [$curl_info['http_code'], $headers, $body];
}

/**
 * Exit the proxy with a given status code and HTTP body message.
 * @param  int $status The HTTP status code
 * @param  string $message An optional body for the HTTP response
 */
function exit_status($status, $message = '') {
    http_response_code($status);

    if ($message) {
        print($message);
    }
    exit();
}

/**
 * Print a usage message and exits.
 * @param  array $args The `argv` parameter
 */
function exit_usage($args) {
    error_log("Usage: ${args[0]} <URL>\n");
    exit(1);
}

/**
 * Run the proxy
 */
function proxy_request() {
    $url = parse_proxy_url($_SERVER['REQUEST_URI']);

    // Drop with an HTTP 400 if HMAC doesn't match or if URL cannot be decoded
    if ($url === FALSE) {
        exit_status(400, "Bad format");
    }

    if ($_SERVER['REQUEST_METHOD'] !== 'GET'
        || preg_match('#^https?://#', $url) === 0) {
        exit_status(403, "Method/URL Not Allowed.");
    }

    // Make the request
    list($resp_status, $resp_headers, $resp_body) = make_curl_request($url);

    // Set the HTTP headers and print the body
    set_response_headers($resp_status, $resp_headers);
    print($resp_body);
}


if (php_sapi_name() !== 'cli') {
    // Run this proxy
    proxy_request();
} else {
    // Generate a URL in the CLI
    if ($argc === 1) {
        exit_usage($argv);
    } else {
        print(generate_proxy_url($argv[1]) . "\n");
        exit();
    }
}
