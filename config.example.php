<?php

// A secret to use when generating the HMAC
define('DESSL_HMAC_SECRET', '');

// The hashing algorithm to use with the HMAC function
define('DESSL_HMAC_ALGO', 'sha256');

// Whether cURL should follow redirects
define('DESSL_FOLLOW_REDIRECT', false);

// Path to the file with the certificate(s) to trust
define('DESSL_CA_CERT_BUNDLE_PATH', '/etc/ssl/cert.pem');
