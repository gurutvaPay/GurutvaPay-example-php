# GuruTvapay PHP SDK (Single File) — `gurutvapay_full.php`

This README explains how to use the **complete single-file PHP SDK + examples**. The file contains:

* `GuruTvapayClient` class (API-key and OAuth modes)
* Custom exceptions for error handling
* CLI commands (create-payment, transaction-status, transaction-list)
* Built-in server example for webhook verification

---

## Requirements

* PHP 7.4+ (works with PHP 8.x)
* `curl` extension enabled

---

## Installation

1. Download `gurutvapay_full.php` into your project.
2. Configure environment variables for credentials.

Recommended environment variables:

```
GURUTVA_ENV=uat            # or live
GURUTVA_API_KEY=sk_test_xxx
GURUTVA_CLIENT_ID=CLIENT_12345        # optional for OAuth
GURUTVA_CLIENT_SECRET=SECRET_67890    # optional for OAuth
GURUTVA_USERNAME=john@example.com     # optional for OAuth
GURUTVA_PASSWORD=your_password        # optional for OAuth
GURUTVA_WEBHOOK_SECRET=secret123      # used for HMAC verification
```

---

## Usage Modes

### 1. As CLI tool

Run directly from the terminal:

```bash
# Create payment
php gurutvapay_full.php create-payment

# Transaction status
php gurutvapay_full.php transaction-status ORDER_2024_001

# Transaction list (limit, page)
php gurutvapay_full.php transaction-list 50 0
```

### 2. As library in your PHP project

```php
require_once 'gurutvapay_full.php';

use GuruTvapay\GuruTvapayClient;

$client = new GuruTvapayClient([
    'env' => 'uat',
    'apiKey' => getenv('GURUTVA_API_KEY')
]);

$resp = $client->createPayment(100, 'ORD123', 'web', 'Online Payment', [
    'buyer_name' => 'John Doe',
    'email' => 'john@example.com',
    'phone' => '9876543210'
]);

echo $resp['payment_url'];
```

### 3. OAuth (password grant)

```php
$client = new GuruTvapayClient([
    'env' => 'uat',
    'clientId' => getenv('GURUTVA_CLIENT_ID'),
    'clientSecret' => getenv('GURUTVA_CLIENT_SECRET')
]);
$client->loginWithPassword(getenv('GURUTVA_USERNAME'), getenv('GURUTVA_PASSWORD'));
```

---

## Built-in Webhook Server

Run PHP’s built-in webserver:

```bash
php -S 0.0.0.0:8080 gurutvapay_full.php
```

Now POST to `http://localhost:8080/webhook` with header `X-Signature: sha256=<hmac>` and body JSON payload.

Webhook verification uses:

```php
GuruTvapayClient::verifyWebhook($payloadBytes, $signatureHeader, getenv('GURUTVA_WEBHOOK_SECRET'));
```

If verified, it logs/prints success and returns `{"ok":true}`.

---

## Error Handling

SDK throws typed exceptions:

* `AuthException` → authentication issues (401/403)
* `NotFoundException` → not found (404)
* `RateLimitException` → rate limiting (429)
* `GuruTvapayException` → all other errors

Example:

```php
try {
    $resp = $client->createPayment(...);
} catch (AuthException $e) {
    echo "Auth failed: " . $e->getMessage();
} catch (GuruTvapayException $e) {
    echo "Error: " . $e->getMessage();
}
```

---

## Idempotency

For safe retries, add `Idempotency-Key` header with `request()`:

```php
$idemp = bin2hex(random_bytes(16));
$payload = [/* create-payment payload */];
$resp = $client->request('POST', '/initiate-payment', ['Idempotency-Key' => $idemp], [], null, $payload);
```

---

## Testing

* Use **UAT** environment for integration tests.
* Simulate webhooks with `openssl`:

```bash
payload='{"merchantOrderId":"ORD123","status":"success"}'
secret=$GURUTVA_WEBHOOK_SECRET
sig=$(echo -n $payload | openssl dgst -sha256 -hmac "$secret" -hex | sed 's/^.* //')
curl -X POST http://localhost:8080/webhook -H "X-Signature: sha256=$sig" -d "$payload"
```

---

## Security

* Never commit API keys or secrets to Git.
* Keep secrets in environment variables or a secrets manager.
* Always verify webhook signatures.
* Use HTTPS in production.

---

## Next Steps

* Package this into a Composer/Packagist library (PSR-4).
* Add PHPUnit tests and CI/CD pipeline.
* Provide framework integrations (Laravel, Symfony providers).

---

## License

Choose an appropriate license (MIT recommended) for distribution.
