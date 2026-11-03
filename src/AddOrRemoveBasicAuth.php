<?php

declare(strict_types=1);

namespace Sunnysideup\BasicAuthBetter;

use SilverStripe\Control\Director;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Flushable;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\DB;
use SilverStripe\Security\BasicAuth;
use Throwable;

class AddOrRemoveBasicAuth implements Flushable
{
    use Injectable;
    use Configurable;

    private const string START_MARKER = '# START BASIC AUTH PROTECTION - Sunnysideup\BasicAuthBetter';

    private const string END_MARKER = '# END BASIC AUTH PROTECTION - Sunnysideup\BasicAuthBetter';

    private const string HTPASSWD_PATH_MARKER = '# HTPASSWD PATH HERE';

    private const string ADD_HOSTS_MARKER = '# ADD HOSTS HERE';

    private const string SHARED_SECRET_MARKER = '# SHARED SECRET HERE';

    private const string DEV_EXCLUSIONS_MARKER = '# DEV EXCLUSIONS HERE';

    private const string LIST_OF_LEGIT_SITES_MARKER = '# LIST OF LEGIT SITES HERE';

    private const string LIVE_SITE_HOST_MARKER = '# LIVE SITE HOST HERE';

    private const string WWW_REDIRECT_MARKER = '# WWW REDIRECT HERE';

    private const string ENV_SS_SHARED_SECRET_HEADER = 'SS_SHARED_SECRET_HEADER';

    private const string ENV_SS_SHARED_SECRET_VALUE = 'SS_SHARED_SECRET_VALUE';

    private const string DEFAULT_SHARED_SECRET_HEADER = 'X-Origin-Secret';

    private const string SHARED_SECRET_DIRECTIVE_PLACEHOLDER = '##### SHARED SECRET PLACEHOLDER #####';

    private const string SHARED_SECRET_DIRECTIVE_NOT_SET = '# No shared secret configured.';

    private static string $htpasswd_path = '/var/www/html';

    /**
     * e.g. mysite.co.nz (without https!)
     */
    private static string $canonical_url = '';

    /**
     * Hosts that should NOT require login (and also count as legit hosts for canonical redirects).
     *
     * @var array<int, string>
     */
    private static array $excluded_from_basic_auth_hosts = [];

    /**
     * Host suffixes (local dev) that should NOT require login.
     *
     * @var array<int, string>
     */
    private static array $dev_exclusions = [
        '.localhost',
        '.ss4',
        '.ddev.site',
    ];

    /**
     * Sub-domains that are considered legit.
     *
     * @var array<int, string>
     */
    private static array $legit_sub_domains = [];

    /**
     * Optional: additional legit hosts (won't canonical-redirect).
     *
     * @var array<int, string>
     */
    private static array $legit_sites = [];

    /**
     * List of white-listed IP addresses that can bypass shared secret check.
     */
    private static array $shared_secret_whitelisted_ips = [];

    /**
     * @var array<int, string>
     */
    private static array $htaccess_files = [
        'public/.htaccess',
    ];

    /**
     * @var array<int, string>
     */
    private static array $htaccess_lines = [
        '##################### 0. CDN PROTECTION ###################',
        '',
        self::SHARED_SECRET_MARKER,
        '',
        '##################### 1. HEADERS ##########################',
        '',
        '# Force HTTPS in browsers (HSTS) — we do it on a domain by domain basis ',
        'Header always set Strict-Transport-Security "max-age=31536000"',
        '',
        '# Better privacy default than same-origin for most sites',
        'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
        '',
        '# Clickjacking protection (modern)',
        'Header always set Content-Security-Policy "frame-ancestors \'self\'"',
        '',
        '# (Optional legacy fallback for old browsers)',
        'Header always set X-Frame-Options "SAMEORIGIN"',
        '',
        '# Modern replacement for Feature-Policy',
        'Header always set Permissions-Policy "camera=(), microphone=()"',
        '',
        '# Baseline hardening',
        'Header always set X-Content-Type-Options "nosniff"',
        '',
        '# It tells caches (browser, Cloudflare, proxies): This response is different depending on the Accept-Encoding request header.',
        'Header always merge Vary "Accept-Encoding"',
        '',
        '# YOU DONT WANT MultiViews enabled, security risk',
        'Options -MultiViews -Indexes',
        '',
        '##################### 2. CANONICAL REDIRECTS ##############',
        '',
        'RewriteEngine On',
        'SetEnv HTTP_MOD_REWRITE On',
        '',
        self::WWW_REDIRECT_MARKER,
        '',
        '# Canonical redirects',
        '# If local (.ss4, ddev, etc...), do nothing (skip next 3 rules)',
        'RewriteCond %{HTTP_HOST} ' . self::DEV_EXCLUSIONS_MARKER . ' [NC]',
        'RewriteRule ^ - [S=3]',
        '',
        '# 1) Proxy case (header present)',
        'RewriteCond %{HTTP:X-Forwarded-Proto} !^$',
        'RewriteCond %{HTTP:X-Forwarded-Proto} !^https$ [NC]',
        'RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]',
        '',
        '# 2) Direct-to-Apache case (no proxy header)',
        'RewriteCond %{HTTP:X-Forwarded-Proto} ^$',
        'RewriteCond %{HTTPS} !=on',
        'RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]',
        '',
        '# 3) Canonical host',
        'RewriteCond %{HTTP_HOST} !^(' . self::LIST_OF_LEGIT_SITES_MARKER . ')$ [NC]',
        'RewriteRule ^ https://' . self::LIVE_SITE_HOST_MARKER . '%{REQUEST_URI} [R=302,L]',
        '',
        '##################### 3. BASIC AUTH #######################',
        '',
        '# Basic Auth directives',
        self::HTPASSWD_PATH_MARKER,
        'AuthType Basic',
        'AuthName "Please enter your website username and password to access this site."',
        '<RequireAny>',
        '  # Exclusions (no login) - never based on the Host header',
        self::ADD_HOSTS_MARKER,
        '  # Excluded file types (no login)',
        '  Require expr %{REQUEST_URI} =~ m#^/(assets|_resources)/.*\.(png|jpe?g|gif|webp|svg|avif|css|js|woff2?|ttf|otf|eot|pdf|xml|ico)$#i',
        '',
        '  # All other hosts: require login',
        '  Require valid-user',
        '</RequireAny>',
        '',
        '##################### 4. BLOCK BAD FILES ###################',
        '',
        '# Deny access to files',
        '<FilesMatch "(?i)\.(env(\..+)?|ss|yml|yaml|log|sql(\.gz)?|bak|swp|swo|orig|inc|ini|sh)$|^(web\.config|composer\.(json|lock)|package(-lock)?\.json|yarn\.lock|\.ds_store|\.git.*|\.htpasswd)$">',
        '    Require all denied',
        '</FilesMatch>',
        '',
        '# stop people traversing git dir',
        'RewriteRule (^|/)\.git(/|$) - [F,L,NC]',
        '',
        '# Deny access to potentially sensitive files and folders',
        'RewriteRule ^vendor(/|$) - [F,L,NC]',
        'RewriteRule silverstripe-cache(/|$) - [F,L,NC]',
        '',
        '##################### 5. ERROR PAGES #######################',
        '',
        '# Route errors to static pages automatically generated by SilverStripe',
        'ErrorDocument 404 /assets/error-404.html',
        'ErrorDocument 500 /assets/error-500.html',
        '',
        '##################### 6. OTHER MISC ###################',
        '',
        '# Turn off index.php handling requests to the homepage fixes issue in apache >=2.4',
        '<IfModule mod_dir.c>',
        '    DirectoryIndex disabled',
        '    DirectorySlash On',
        '</IfModule>',
        '',
        '# Enable HTTP Basic authentication workaround for PHP running in CGI mode',
        'RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]',
        '',
        '##################### 7. REDIRECT EVERYTHING WITHOUT EXACT FILE MATCH TO INDEX. ###################',
        '',
        '# Process through SilverStripe if no file with the requested name exists.',
        'RewriteCond %{REQUEST_FILENAME} !-f',
        'RewriteRule .* index.php [L]',
        '### SILVERSTRIPE END - THERE SHOULD NO NOTHING AFTER THIS LINE ###',
        '',
    ];

    private static string $default_user_name = 'authorisedusers';

    /**
     * Please set SS_BASIC_AUTH_PASSWORD in the environment.
     */
    private static string $default_password = '';

    /**
     * Client addresses (IP addresses or CIDR ranges) that do NOT have to log in. Never use host names for this: the Host header can be forged.
     * Loopback addresses are always added.
     *
     * @var array<int, string>
     */
    private static array $excluded_from_basic_auth_ips = [];

    /**
     * Also skip login for private network ranges (10/8, 172.16/12, 192.168/16)?
     * Only applied when the .htaccess is generated in dev mode and only if this is switched on:
     * the generated rules are deployed to other servers, where a load balancer could have a private address.
     */
    private static bool $excluded_from_basic_auth_private_ranges_in_dev = false;

    private static bool $debug = false;

    private static bool $disabled = false;

    private bool $needsProtection = true;

    private string $userName = '';

    private string $password = '';

    private string $base = '';

    private string $htpasswdPath = '';

    /**
     * @var array<int, string>
     */
    private array $htaccessPaths = [];

    public static function flush(): void
    {
        /** @var self $instance */
        $instance = Injector::inst()->get(static::class);
        try {
            $instance->initialize();
            $instance->process();
        } catch (Throwable $e) {
            DB::alteration_message(
                sprintf(
                    'Error processing BasicAuth configuration: %s (in %s:%d)',
                    $e->getMessage(),
                    $e->getFile(),
                    $e->getLine()
                ),
                'deleted'
            );
        }
    }

    public function initialize(): void
    {
        $this->base = Director::baseFolder();
        $this->htpasswdPath = $this->resolveHtpasswdPath();
        $this->htaccessPaths = $this->resolveHtaccessPaths();

        // Keep your original behaviour (only protect in SS 'test' env).
        // If you actually meant "non-live", change this to: !Director::isLive()
        $this->needsProtection = Director::isTest();
    }

    public function process(): void
    {
        $disabled = (bool) Config::inst()->get(self::class, 'disabled');

        if ($disabled) {
            $this->deleteHtpasswdFile();
            if (Director::isDev() && Director::is_cli()) {
                $this->updateHtaccessFiles(true);
            }

            return;
        }

        $this->checkBasicAuthConfig();

        if ($this->needsProtection) {
            $this->createHtpasswdFile();
        } else {
            $this->deleteHtpasswdFile();
        }

        if (Director::isDev() && Director::is_cli()) {
            $this->updateHtaccessFiles(false);
        }
        if (Director::is_cli()) {
            $this->updateSharedSecretInHtaccessFiles();
        }
    }

    private function resolveHtpasswdPath(): string
    {
        $configured = (string) $this->config()->get('htpasswd_path');

        if ($configured !== '') {
            return rtrim($configured, '/') . '/.htpasswd';
        }

        return rtrim(Director::baseFolder(), '/') . '/.htpasswd';
    }

    /**
     * @return array<int, string>
     */
    private function resolveHtaccessPaths(): array
    {
        $paths = [];

        foreach ((array) $this->config()->get('htaccess_files') as $file) {
            $paths[] = rtrim($this->base, '/') . '/' . ltrim((string) $file, '/');
        }

        return $paths;
    }

    public function checkBasicAuthConfig(): void
    {
        if ($this->needsProtection) {
            $entireSiteProtected = (bool) Config::inst()->get(BasicAuth::class, 'entire_site_protected');
            $envUsesBasicAuth = $this->isEnvTruthy('SS_USE_BASIC_AUTH');

            if ($entireSiteProtected || $envUsesBasicAuth) {
                $message = implode(PHP_EOL, [
                    '',
                    '',
                    'BasicAuth is enabled elsewhere.',
                    'Remove the BasicAuth::protect_entire_site() call from your _config.php',
                    'or set ' . BasicAuth::class . '.entire_site_protected: false',
                    'and make sure SS_USE_BASIC_AUTH is not truthy in .env.',
                    '',
                    '',
                ]);

                user_error($message, E_USER_WARNING);
            }
        }
    }

    private function createHtpasswdFile(): void
    {
        if (Director::isDev()) {
            $this->logMessage('BasicAuth disabled - in Dev mode - no .htpasswd file created.');
            return;
        }

        $this->userName = $this->firstEnvValue(['SS_BASIC_AUTH_USER', 'SS_BASIC_AUTH_USERNAME']);
        if ($this->userName === '') {
            $this->userName = (string) $this->config()->get('default_user_name');
        }

        $this->password = $this->firstEnvValue(['SS_BASIC_AUTH_PASSWORD']);
        $passwordMissing = $this->password === '';
        if ($passwordMissing) {
            $this->password = bin2hex(random_bytes(24));
        }

        $hash = password_hash($this->password, PASSWORD_BCRYPT);
        if ($hash === false) {
            throw new \RuntimeException('Could not hash BasicAuth password. Please check your .env file.');
        }

        $line = $this->userName . ':' . $hash . PHP_EOL;

        $result = @file_put_contents($this->htpasswdPath, $line, LOCK_EX);
        if ($result === false) {
            throw new \RuntimeException('Could not write .htpasswd file at: ' . $this->htpasswdPath);
        }

        @chmod($this->htpasswdPath, 0640);

        $this->logMessage('.htpasswd file created.');

        if ($passwordMissing) {
            throw new \RuntimeException(PHP_EOL . PHP_EOL . 'Please set SS_BASIC_AUTH_PASSWORD in your .env file. Until then the site is locked for everyone (random password).' . PHP_EOL);
        }
    }

    private function deleteHtpasswdFile(): void
    {
        if ($this->htpasswdPath !== '' && file_exists($this->htpasswdPath)) {
            @unlink($this->htpasswdPath);
            $this->logMessage('.htpasswd file removed.');
        }
    }

    private function updateHtaccessFiles(bool $removeBlock): void
    {
        $liveSiteHost = $this->normaliseHost((string) $this->config()->get('canonical_url'));
        if ($liveSiteHost === '') {
            throw new \RuntimeException(
                PHP_EOL . PHP_EOL . 'Please set ' . self::class . ':canonical_url (e.g. mysite.co.nz) in YAML config. See: vendor/sunnysideup/basic-auth-better/_config/basic-auth-better.yml.example' . PHP_EOL
            );
        }

        $authDirectives = $this->buildHtaccessDirectiveLines($liveSiteHost);

        $authBlock = self::START_MARKER . PHP_EOL
            . implode(PHP_EOL, $authDirectives) . PHP_EOL
            . self::END_MARKER . PHP_EOL;

        $pattern = '/^' . preg_quote(self::START_MARKER, '/') . '.*?^' . preg_quote(self::END_MARKER, '/') . '\R?/ms';

        foreach ($this->htaccessPaths as $htaccessPath) {
            $existing = file_exists($htaccessPath) ? (string) file_get_contents($htaccessPath) : '';

            if ($existing === '' && $removeBlock) {
                continue;
            }

            $updated = $removeBlock
                ? ((string) (preg_replace($pattern, '', $existing) ?? $existing))
                : (str_contains($existing, self::START_MARKER)
                    ? ((string) (preg_replace($pattern, $authBlock, $existing) ?? $existing))
                    : ($authBlock . $existing));

            $result = @file_put_contents($htaccessPath, $updated, LOCK_EX);
            if ($result === false) {
                user_error('Could not write .htaccess file at: ' . $htaccessPath, E_USER_WARNING);
                continue;
            }

            $this->logMessage(
                ($removeBlock ? 'BasicAuth protection removed from: ' : 'BasicAuth protection ensured in: ')
                    . $htaccessPath
            );
        }
    }

    private function updateSharedSecretInHtaccessFiles(): void
    {
        foreach ($this->htaccessPaths as $htaccessPath) {
            $data = file_exists($htaccessPath) ? (string) file_get_contents($htaccessPath) : '';
            if ($data === '') {
                continue;
            }
            if (!str_contains($data, self::SHARED_SECRET_DIRECTIVE_PLACEHOLDER)) {
                continue;
            }
            $newData = str_replace(
                self::SHARED_SECRET_DIRECTIVE_PLACEHOLDER,
                $this->buildSecretDirectiveLines(),
                $data
            );
            if ($newData === $data) {
                continue;
            }
            $result = @file_put_contents($htaccessPath, $newData, LOCK_EX);
            if ($result === false) {
                user_error('BasicAuth could not update shared secret in: ' . $htaccessPath, E_USER_WARNING);
                continue;
            }
            $this->logMessage('BasicAuth updated shared secret in: ' . $htaccessPath);
        }
    }

    /**
     * @return array<int, string>
     */
    private function buildHtaccessDirectiveLines(string $liveSiteHost): array
    {
        $templateLines = (array) $this->config()->get('htaccess_lines');

        $excludedHosts = $this->normaliseList(
            array_merge([$liveSiteHost], (array) $this->config()->get('excluded_from_basic_auth_hosts')),
            fn (string $host): string => $this->normaliseHost($host)
        );

        $devExclusions = $this->normaliseList((array) $this->config()->get('dev_exclusions'));
        $isWwwCanonical = $this->isWwwCanonical($liveSiteHost);
        $legitSites = [];
        if ($isWwwCanonical) {
            $liveHostWithoutWWW = preg_replace('/^www\./i', '', $liveSiteHost);
            $liveHostWithoutWWW = is_string($liveHostWithoutWWW) ? $liveHostWithoutWWW : $liveSiteHost;
        } else {
            $liveHostWithoutWWW = $liveSiteHost;
        }

        foreach ((array) $this->config()->get('legit_sub_domains') as $subDomain) {
            $subDomainString = trim((string) $subDomain);
            if ($subDomainString !== '') {
                $legitSites[] = $subDomainString . '.' . $liveHostWithoutWWW;
            }
        }

        $legitHosts = $this->normaliseList(
            array_merge($excludedHosts, $legitSites, (array) $this->config()->get('legit_sites')),
            fn (string $host): string => $this->normaliseHost($host)
        );

        $sharedSecretLines = $this->buildSecretDirectiveLines();
        $devExclusionsRegex = $this->buildSuffixRegexForRewriteCond($devExclusions);
        $legitSitesRegex = $this->buildExactHostsRegex($legitHosts);

        $outputLines = [];
        $canonicalLines = [];
        if ($isWwwCanonical) {
            $canonicalLines[] = '# Canonical redirect: enforce www';
            $bareHost = preg_replace('#^www\.#', '', $liveSiteHost);
            $canonicalLines[] = 'RewriteCond %{HTTP_HOST} !^www\. [NC]';
            $canonicalLines[] = 'RewriteCond %{HTTP_HOST} ^' . preg_quote($bareHost, '/') . '$ [NC]';
            $canonicalLines[] = 'RewriteRule ^ https://www.' . $bareHost . '%{REQUEST_URI} [R=301,L]';
            $canonicalLines[] = '';
        } else {
            $canonicalLines[] = '# Canonical redirect: enforce non-www';
            $canonicalLines[] = 'RewriteCond %{HTTP_HOST} ^www\.(.+)$ [NC]';
            $canonicalLines[] = 'RewriteRule ^ https://%1%{REQUEST_URI} [R=301,L]';
            $canonicalLines[] = '';
        }

        // foreach ($canonicalLines as $line) {
        //     $outputLines[] = $line;
        // }

        $canonicalLinesString = implode(PHP_EOL, $canonicalLines);
        foreach ($templateLines as $line) {
            $lineString = (string) $line;
            $trimmed = trim($lineString);

            if ($trimmed === self::HTPASSWD_PATH_MARKER) {
                $outputLines[] = 'AuthUserFile ' . $this->htpasswdPath;
                continue;
            }

            if ($trimmed === self::ADD_HOSTS_MARKER) {
                // NEVER authorise based on the Host header: it can be forged by anyone.
                // 1. no .htpasswd file means that this server is not protected (e.g. live, dev): decided by the server, not by the visitor.
                if (! preg_match('#^[A-Za-z0-9_./\-]+$#', $this->htpasswdPath)) {
                    throw new \RuntimeException('The .htpasswd path contains unsupported characters: ' . $this->htpasswdPath);
                }

                $outputLines[] = "  # No login required if there is no .htpasswd file (this site is not protected)";
                $outputLines[] = "  Require expr ! -f '" . $this->htpasswdPath . "'";
                // 2. client address based exclusions
                $outputLines[] = '  # No login required for these client addresses';
                $outputLines[] = '  Require ip ' . implode(' ', $this->getExcludedIps());
                continue;
            }

            $lineString = str_replace(self::SHARED_SECRET_MARKER, $sharedSecretLines, $lineString);
            $lineString = str_replace(self::DEV_EXCLUSIONS_MARKER, $devExclusionsRegex, $lineString);
            $lineString = str_replace(self::LIST_OF_LEGIT_SITES_MARKER, $legitSitesRegex, $lineString);
            $lineString = str_replace(self::LIVE_SITE_HOST_MARKER, $liveSiteHost, $lineString);
            $lineString = str_replace(self::WWW_REDIRECT_MARKER, $canonicalLinesString, $lineString);

            $outputLines[] = $lineString;
        }

        $this->assertNoMarkersRemain($outputLines);

        return $outputLines;
    }

    /**
     * @return array<int, string>
     */
    private function getExcludedIps(): array
    {
        $ips = ['127.0.0.1', '::1'];
        if (Director::isDev() && (bool) $this->config()->get('excluded_from_basic_auth_private_ranges_in_dev')) {
            $ips = array_merge($ips, ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']);
        }

        foreach ((array) $this->config()->get('excluded_from_basic_auth_ips') as $ip) {
            $ip = trim((string) $ip);
            $address = explode('/', $ip, 2)[0];
            if ($ip !== '' && filter_var($address, FILTER_VALIDATE_IP)) {
                $ips[] = $ip;
            } elseif ($ip !== '') {
                user_error('Invalid IP address in excluded_from_basic_auth_ips: ' . $ip, E_USER_WARNING);
            }
        }

        return array_values(array_unique($ips));
    }

    /**
     * @param array<int, mixed> $values
     * @return array<int, string>
     */
    private function normaliseList(array $values, ?callable $normaliser = null): array
    {
        $out = [];

        foreach ($values as $value) {
            $valueString = trim((string) $value);
            if ($valueString === '') {
                continue;
            }

            if ($normaliser !== null) {
                $valueString = trim((string) $normaliser($valueString));
                if ($valueString === '') {
                    continue;
                }
            }

            $out[] = $valueString;
        }

        return array_values(array_unique($out));
    }

    /**
     * @param array<int, string> $suffixes
     */
    private function buildSuffixRegexForRewriteCond(array $suffixes): string
    {
        if ($suffixes === []) {
            return 'a^';
        }

        $escaped = array_map(
            fn (string $suffix): string => preg_quote($suffix, '/'),
            $suffixes
        );

        return '(' . implode('|', $escaped) . ')$';
    }

    /**
     * @param array<int, string> $hosts
     */
    private function buildExactHostsRegex(array $hosts): string
    {
        if ($hosts === []) {
            return 'a^';
        }

        $escaped = array_map(
            fn (string $host): string => preg_quote($host, '/'),
            $hosts
        );

        return implode('|', $escaped);
    }

    /**
     * @param array<int, string> $lines
     */
    private function assertNoMarkersRemain(array $lines): void
    {
        $joined = implode(PHP_EOL, $lines);

        foreach (
            [
                self::HTPASSWD_PATH_MARKER,
                self::ADD_HOSTS_MARKER,
                self::SHARED_SECRET_MARKER,
                self::DEV_EXCLUSIONS_MARKER,
                self::LIST_OF_LEGIT_SITES_MARKER,
                self::LIVE_SITE_HOST_MARKER,
            ] as $marker
        ) {
            if (str_contains($joined, $marker)) {
                throw new \RuntimeException('Unreplaced .htaccess marker found: ' . $marker);
            }
        }
    }

    private function normaliseHost(string $host): string
    {
        $host = trim($host);
        if ($host === '') {
            return '';
        }

        $host = (string) (preg_replace('#^https?://#i', '', $host) ?? $host);
        $host = explode('/', $host, 2)[0];
        //@TODO - add SS_ALLOWED_HOSTS check!!!!
        return strtolower(trim($host));
    }

    private function buildSecretDirectiveLines(): string
    {
        if (Director::isDev()) {
            return self::SHARED_SECRET_DIRECTIVE_PLACEHOLDER;
        }

        $sharedSecretHeader = $this->firstEnvValue([self::ENV_SS_SHARED_SECRET_HEADER]) ?: self::DEFAULT_SHARED_SECRET_HEADER;
        $sharedSecretValue = $this->firstEnvValue([self::ENV_SS_SHARED_SECRET_VALUE]);

        if (!$sharedSecretValue) {
            return self::SHARED_SECRET_DIRECTIVE_NOT_SET;
        }

        $whitelistedIPs = Config::inst()->get(self::class, 'shared_secret_whitelisted_ips') ?? [];
        $whitelistedIPs = array_filter(array_map('trim', $whitelistedIPs));

        $this->validateSharedSecret($sharedSecretHeader, $sharedSecretValue, $whitelistedIPs);

        return implode(
            PHP_EOL,
            [
                "<IfModule mod_rewrite.c>",
                "  RewriteEngine On",
                "",
                "  # Check secret header",
                "  RewriteCond %{HTTP:{$sharedSecretHeader}} !={$sharedSecretValue}",
                ...$this->buildRewriteCondForWhitelistedIPs($whitelistedIPs),
                "",
                "  # Deny access",
                "  RewriteRule ^ - [F]",
                "</IfModule>",
            ]
        );
    }

    private function buildRewriteCondForWhitelistedIPs(array $whitelistedIPs): array
    {
        if ($whitelistedIPs === []) {
            return [];
        }

        $this->logMessage('Shared secret is enabled with whitelisted IPs: ' . implode(', ', $whitelistedIPs));

        $address = count($whitelistedIPs) === 1 ? 'address' : 'addresses';
        $conditions = ["", "  # White-list IP $address"];
        foreach ($whitelistedIPs as $ip) {
            $conditions[] = "  RewriteCond %{REMOTE_ADDR} !={$ip}";
        }
        return $conditions;
    }

    private function validateSharedSecret(string $sharedSecretHeader, string $sharedSecretValue, array $whitelistedIPs): void
    {
        if (!str_starts_with($sharedSecretHeader, 'X-')) {
            throw new \RuntimeException(self::ENV_SS_SHARED_SECRET_HEADER . ' must start with X-');
        }
        if (!preg_match('/^[a-zA-Z0-9-]+$/', $sharedSecretHeader)) {
            throw new \RuntimeException(self::ENV_SS_SHARED_SECRET_HEADER . ' must be alphanumeric and dashes i.e. a-z, A-Z, 0-9, - and MUST NOT contains symbols or spaces');
        }
        if (strlen($sharedSecretValue) < 25) {
            throw new \RuntimeException(self::ENV_SS_SHARED_SECRET_VALUE . ' needs to be at least 25 characters long');
        }
        if (!preg_match('/^[a-zA-Z0-9]+$/', $sharedSecretValue)) {
            throw new \RuntimeException(self::ENV_SS_SHARED_SECRET_VALUE . ' must be alphanumeric i.e. a-z, A-Z, 0-9 and MUST NOT contains symbols or spaces');
        }
        foreach ($whitelistedIPs as $ip) {
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                throw new \RuntimeException('Invalid IP address in shared_secret_whitelisted_ips: ' . $ip);
            }
        }
    }

    /**
     * @param array<int, string> $keys
     */
    private function firstEnvValue(array $keys): string
    {
        foreach ($keys as $key) {
            $value = trim((string) Environment::getEnv($key));
            if ($value !== '') {
                return $value;
            }
        }

        return '';
    }

    private function isEnvTruthy(string $key): bool
    {
        $value = Environment::getEnv($key);
        if ($value === null) {
            return false;
        }

        $valueString = trim((string) $value);
        if ($valueString === '') {
            return false;
        }

        $bool = filter_var($valueString, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);

        return $bool ?? true;
    }

    private function wwwVsNonWww(string $host): string
    {
        $host = trim($host);
        if (str_starts_with(strtolower($host), 'www.')) {
            return substr($host, 4);
        }

        return 'www.' . $host;
    }

    private function logMessage(string $message): void
    {
        if ((bool) $this->config()->get('debug')) {
            DB::alteration_message($message, 'edited');
        }
    }

    private function isWwwCanonical(?string $host = ''): bool
    {
        if (! $host) {
            $host = (string) $this->config()->get('canonical_url') ?? '';
        }

        if ($host === '') {
            user_error('Host is empty.', E_USER_WARNING);
        }

        if (str_starts_with(strtolower($host), 'http')) {
            user_error('Host should not include protocol (http/https): ' . $host, E_USER_WARNING);
        }

        return str_starts_with(strtolower($host), 'www.');
    }
}
