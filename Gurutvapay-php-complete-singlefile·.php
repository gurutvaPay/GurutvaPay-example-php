<?php
/**
 * gurutvapay_full.php
 *
 * Complete single-file PHP SDK + examples for GuruTvapay.
 *
 * Features included in this one file:
 * - GuruTvapayClient: single-file SDK (curl-based, retry/backoff, API-key & OAuth modes)
 * - CLI examples: create-payment, transaction-status, transaction-list
 * - Simple webhook receiver (run with PHP built-in server) that verifies HMAC signature
 * - Helpful comments and usage instructions
 *
 * Usage (CLI):
 *   # create payment
 *   php gurutvapay_full.php create-payment
 *
 *   # transaction status
 *   php gurutvapay_full.php transaction-status ORDER_2024_001
 *
 *   # list transactions
 *   php gurutvapay_full.php transaction-list 50 0
 *
 * Run webhook server (for local testing):
 *   php -S 0.0.0.0:8080 gurutvapay_full.php
 *
 * Then POST to http://localhost:8080/webhook with header X-Signature: sha256=<hex>
 *
 * Configuration via environment variables (recommended):
 *   GURUTVA_ENV (uat|live) - default uat
 *   GURUTVA_API_KEY
 *   GURUTVA_CLIENT_ID
 *   GURUTVA_CLIENT_SECRET
 *   GURUTVA_USERNAME
 *   GURUTVA_PASSWORD
 *   GURUTVA_WEBHOOK_SECRET
 *
 * NOTE: This is intended as a drop-in single-file SDK + examples. For production,
 * move class into a proper PSR-4 package, add unit tests and CI, and avoid running
 * the built-in PHP server publicly.
 */

namespace GuruTvapay;

// -----------------------------
// Exceptions
// -----------------------------
class GuruTvapayException extends \Exception {}
class AuthException extends GuruTvapayException {}
class NotFoundException extends GuruTvapayException {}
class RateLimitException extends GuruTvapayException {}

// -----------------------------
// Client
// -----------------------------
class GuruTvapayClient {
    private $env;
    private $apiKey;
    private $clientId;
    private $clientSecret;
    private $timeout;
    private $maxRetries;
    private $backoffFactor;
    private $root;
    private $token; // ['access_token'=>..., 'expires_at'=>int]

    const DEFAULT_ROOT = 'https://api.gurutvapay.com';
    private static $envPrefixes = [
        'uat' => '/uat_mode',
        'live' => '/live',
    ];

    public function __construct(array $opts = []) {
        $this->env = $opts['env'] ?? 'uat';
        if (!isset(self::$envPrefixes[$this->env])) {
            throw new \InvalidArgumentException("env must be 'uat' or 'live'");
        }
        $this->apiKey = $opts['apiKey'] ?? null;
        $this->clientId = $opts['clientId'] ?? null;
        $this->clientSecret = $opts['clientSecret'] ?? null;
        $this->timeout = $opts['timeout'] ?? 30;
        $this->maxRetries = $opts['maxRetries'] ?? 3;
        $this->backoffFactor = $opts['backoffFactor'] ?? 0.5;
        $this->root = $opts['customRoot'] ?? self::DEFAULT_ROOT;
        $this->token = null;
    }

    // -----------------------------
    // Low-level request helper with retries
    // -----------------------------
    private function httpRequest($method, $url, $headers = [], $params = [], $data = null, $jsonBody = null) {
        $attempt = 0;
        while (true) {
            $attempt += 1;
            $ch = curl_init();
            $finalUrl = $url;
            if (!empty($params)) {
                $finalUrl .= '?' . http_build_query($params);
            }
            curl_setopt($ch, CURLOPT_URL, $finalUrl);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);
            curl_setopt($ch, CURLOPT_FAILONERROR, false);

            $hdrs = [];
            foreach ($headers as $k => $v) {
                $hdrs[] = $k . ': ' . $v;
            }
            // add auth header if available
            $auth = $this->authHeader();
            foreach ($auth as $k => $v) { $hdrs[] = $k . ': ' . $v; }

            if (!empty($jsonBody)) {
                $body = json_encode($jsonBody);
                $hdrs[] = 'Content-Type: application/json';
                curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
            } elseif (is_array($data)) {
                // form-encoded
                $hdrs[] = 'Content-Type: application/x-www-form-urlencoded';
                curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
            }

            if (strtoupper($method) === 'POST') {
                curl_setopt($ch, CURLOPT_POST, true);
            } else {
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, strtoupper($method));
            }

            if (!empty($hdrs)) curl_setopt($ch, CURLOPT_HTTPHEADER, $hdrs);

            $respBody = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $curlErr = curl_error($ch);
            curl_close($ch);

            if ($curlErr) {
                if ($attempt > $this->maxRetries) {
                    throw new GuruTvapayException("HTTP request failed: {$curlErr}");
                }
                $sleep = $this->backoffFactor * pow(2, $attempt - 1);
                usleep((int)($sleep * 1e6));
                continue;
            }

            $decoded = json_decode($respBody, true);

            if ($httpCode >= 200 && $httpCode < 300) {
                return $decoded ?? ['raw' => $respBody];
            }

            if ($httpCode == 401 || $httpCode == 403) {
                throw new AuthException("Authentication failed: {$respBody}");
            }
            if ($httpCode == 404) {
                throw new NotFoundException("Not found: {$url}");
            }
            if ($httpCode == 429) {
                if ($attempt <= $this->maxRetries) {
                    $sleep = $this->backoffFactor * pow(2, $attempt - 1);
                    usleep((int)($sleep * 1e6));
                    continue;
                }
                throw new RateLimitException("Rate limited: {$respBody}");
            }

            if ($httpCode >= 500 && $attempt <= $this->maxRetries) {
                $sleep = $this->backoffFactor * pow(2, $attempt - 1);
                usleep((int)($sleep * 1e6));
                continue;
            }

            throw new GuruTvapayException("HTTP {$httpCode}: {$respBody}");
        }
    }

    // -----------------------------
    // Auth helpers
    // -----------------------------
    private function authHeader() {
        if ($this->apiKey) {
            return ['Authorization' => 'Bearer ' . $this->apiKey];
        }
        if ($this->token && isset($this->token['access_token']) && !$this->isTokenExpired()) {
            return ['Authorization' => 'Bearer ' . $this->token['access_token']];
        }
        return [];
    }

    private function isTokenExpired() {
        if (!$this->token || !isset($this->token['expires_at'])) return true;
        return time() >= ($this->token['expires_at'] - 10);
    }

    public function loginWithPassword($username, $password, $grantType = 'password') {
        if (!$this->clientId || !$this->clientSecret) {
            throw new \InvalidArgumentException('clientId and clientSecret are required for OAuth login');
        }
        $url = $this->root . self::$envPrefixes[$this->env] . '/login';
        $data = [
            'grant_type' => $grantType,
            'username' => $username,
            'password' => $password,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
        ];
        $resp = $this->httpRequest('POST', $url, [], [], $data, null);
        if (!isset($resp['access_token'])) {
            throw new AuthException('Login failed or missing access_token');
        }
        $expiresAt = isset($resp['expires_at']) ? intval($resp['expires_at']) : (time() + intval($resp['expires_in'] ?? 0));
        $this->token = ['access_token' => $resp['access_token'], 'expires_at' => $expiresAt];
        return $this->token;
    }

    // -----------------------------
    // High-level methods
    // -----------------------------
    public function createPayment($amount, $merchantOrderId, $channel, $purpose, array $customer, $expiresIn = null, $metadata = null) {
        $url = self::DEFAULT_ROOT . '/initiate-payment';
        $payload = [
            'amount' => $amount,
            'merchantOrderId' => $merchantOrderId,
            'channel' => $channel,
            'purpose' => $purpose,
            'customer' => $customer,
        ];
        if ($expiresIn !== null) $payload['expires_in'] = $expiresIn;
        if ($metadata !== null) $payload['metadata'] = $metadata;
        return $this->httpRequest('POST', $url, [], [], null, $payload);
    }

    public function transactionStatus($merchantOrderId) {
        $url = $this->root . self::$envPrefixes[$this->env] . '/transaction-status';
        $data = ['merchantOrderId' => $merchantOrderId];
        return $this->httpRequest('POST', $url, [], [], $data, null);
    }

    public function transactionList($limit = 50, $page = 0) {
        $url = $this->root . self::$envPrefixes[$this->env] . '/transaction-list';
        $params = ['limit' => $limit, 'page' => $page];
        return $this->httpRequest('GET', $url, [], $params, null, null);
    }

    // Generic request for advanced use (headers passed here will be merged with auth)
    public function request($method, $pathOrUrl, $headers = [], $params = [], $data = null, $jsonBody = null) {
        $url = $pathOrUrl;
        if (strpos($pathOrUrl, 'http://') !== 0 && strpos($pathOrUrl, 'https://') !== 0) {
            // join root
            if (strpos($pathOrUrl, '/') !== 0) $pathOrUrl = '/' . $pathOrUrl;
            $url = $this->root . $pathOrUrl;
        }
        return $this->httpRequest($method, $url, $headers, $params, $data, $jsonBody);
    }

    // -----------------------------
    // Webhook verification
    // -----------------------------
    public static function verifyWebhook($payloadBytes, $signatureHeader, $secret) {
        $sig = $signatureHeader;
        if (!$sig) return false;
        if (strpos($sig, 'sha256=') === 0) {
            $sig = substr($sig, 7);
        }
        $computed = hash_hmac('sha256', $payloadBytes, $secret);
        if (function_exists('hash_equals')) {
            return hash_equals($computed, $sig);
        }
        return $computed === $sig;
    }
}

// -----------------------------
// CLI & Built-in webserver examples
// -----------------------------
if (php_sapi_name() === 'cli') {
    // CLI mode: run example commands
    $cmd = $argv[1] ?? null;
    // Load config from env
    $cfg = [
        'env' => getenv('GURUTVA_ENV') ?: 'uat',
        'apiKey' => getenv('GURUTVA_API_KEY') ?: null,
        'clientId' => getenv('GURUTVA_CLIENT_ID') ?: null,
        'clientSecret' => getenv('GURUTVA_CLIENT_SECRET') ?: null,
        'timeout' => 30,
    ];
    $client = new GuruTvapayClient($cfg);

    try {
        if ($cmd === 'create-payment') {
            $merchantId = 'ORD' . time();
            $resp = $client->createPayment(100, $merchantId, 'web', 'CLI Payment', [
                'buyer_name' => 'CLI User', 'email' => 'cli@example.com', 'phone' => '9999999999'
            ]);
            echo "Create Payment Response:\n";
            print_r($resp);
        } elseif ($cmd === 'transaction-status') {
            $order = $argv[2] ?? null;
            if (!$order) { echo "Usage: php gurutvapay_full.php transaction-status ORDER_ID\n"; exit(1);} 
            $resp = $client->transactionStatus($order);
            print_r($resp);
        } elseif ($cmd === 'transaction-list') {
            $limit = intval($argv[2] ?? 50);
            $page = intval($argv[3] ?? 0);
            $resp = $client->transactionList($limit, $page);
            print_r($resp);
        } else {
            echo "Usage: php gurutvapay_full.php <command>\n";
            echo "Commands: create-payment | transaction-status ORDER_ID | transaction-list [limit page]" . PHP_EOL;
        }
    } catch (AuthException $e) {
        fwrite(STDERR, "Auth error: " . $e->getMessage() . PHP_EOL);
        exit(2);
    } catch (GuruTvapayException $e) {
        fwrite(STDERR, "Error: " . $e->getMessage() . PHP_EOL);
        exit(3);
    }
    exit(0);
} else {
    // Built-in server mode: simple router for webhook
    $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    if ($path === '/webhook' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $payload = file_get_contents('php://input');
        $sig = $_SERVER['HTTP_X_SIGNATURE'] ?? $_SERVER['HTTP_X_GURUTVAPAY_SIGNATURE'] ?? null;
        $secret = getenv('GURUTVA_WEBHOOK_SECRET') ?: 'changeme';
        if (!\GuruTvapay\GuruTvapayClient::verifyWebhook($payload, $sig, $secret)) {
            http_response_code(401);
            echo 'Invalid signature';
            exit;
        }
        header('Content-Type: application/json');
        $data = json_decode($payload, true);
        // Minimal processing example
        if (isset($data['status']) && $data['status'] === 'success') {
            // TODO: update your DB, send notifications, etc.
            error_log('Payment success: ' . ($data['merchantOrderId'] ?? $data['orderId'] ?? 'unknown'));
        }
        echo json_encode(['ok' => true]);
        exit;
    }

    // Simple info page
    if ($_SERVER['REQUEST_URI'] === '/' || $_SERVER['REQUEST_URI'] === '/index.php') {
        echo "<html><body><h2>GuruTvapay single-file SDK</h2>";
        echo "<p>Use <code>/webhook</code> to POST events. Run <code>php -S 0.0.0.0:8080 gurutvapay_full.php</code></p>";
        echo "</body></html>";
        exit;
    }

    // 404
    http_response_code(404);
    echo 'Not Found';
    exit;
}

// EOF
