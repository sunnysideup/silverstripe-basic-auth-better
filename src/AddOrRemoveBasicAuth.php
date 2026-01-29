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

class AddOrRemoveBasicAuth implements Flushable
{
    use Injectable;
    use Configurable;

    private const START_MARKER = '# START BASIC AUTH PROTECTION - Sunnysideup\BasicAuthBetter';
    private const END_MARKER = '# END BASIC AUTH PROTECTION - Sunnysideup\BasicAuthBetter';

    private const HTPASSWD_PATH_MARKER = '# HTPASSWD PATH HERE';
    private const ADD_HOSTS_MARKER = '# ADD HOSTS HERE';
    private const DEV_EXCLUSIONS_MARKER = '# DEV EXCLUSIONS HERE';
    private const LIST_OF_LEGIT_SITES_MARKER = '# LIST OF LEGIT SITES HERE';
    private const LIVE_SITE_HOST_MARKER = '# LIVE SITE HOST HERE';

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
        '.ddev',
    ];

    /**
     * Sub-domains that are considered legit.
     *
     * @var array<int, string>
     */
    private static array $legit_sub_domains = [
        'test',
        'dev',
        'staging',
    ];

    /**
     * Optional: additional legit hosts (won't canonical-redirect).
     *
     * @var array<int, string>
     */
    private static array $legit_sites = [];

    /**
     * @var array<int, string>
     */
    private static array $htaccess_files = [
        'public/.htaccess',
        'public/assets/.htaccess',
    ];

    /**
     * @var array<int, string>
     */
    private static array $htaccess_lines = [
        '<IfModule mod_rewrite.c>',
        'RewriteEngine On',
        '',
        '# If local (.ss4, ddev, etc...), do nothing (skip next 2 rules)',
        'RewriteCond %{HTTP_HOST} ' . self::DEV_EXCLUSIONS_MARKER . ' [NC]',
        'RewriteRule ^ - [S=2]',
        '',
        '# 1) Force HTTPS',
        'RewriteCond %{HTTPS} !=on',
        'RewriteCond %{HTTP:X-Forwarded-Proto} !https',
        'RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=302,L]',
        '',
        '# 2) Canonical host',
        'RewriteCond %{HTTP_HOST} !^(' . self::LIST_OF_LEGIT_SITES_MARKER . ')$ [NC]',
        'RewriteRule ^ https://' . self::LIVE_SITE_HOST_MARKER . '%{REQUEST_URI} [R=302,L]',
        '',
        '</IfModule>',
        '',
        self::HTPASSWD_PATH_MARKER,
        'AuthType Basic',
        'AuthName "Please enter your website username and password to access this site."',
        '<RequireAny>',
        '  # Excluded hosts (no login)',
        self::ADD_HOSTS_MARKER,
        '',
        '  # All other hosts: require login',
        '  Require valid-user',
        '</RequireAny>',
    ];

    private static string $default_user_name = 'authorisedusers';
    private static string $default_password = 'only';
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
        $instance->initialize();
        $instance->process();
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
            if (Director::isDev()) {
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

        if (Director::isDev()) {
            $this->updateHtaccessFiles(false);
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
        if ($this->password === '') {
            $this->password = (string) $this->config()->get('default_password');
        }

        if ($this->needsProtection && ($this->userName === '' || $this->password === '')) {
            user_error(PHP_EOL . PHP_EOL . 'Please set SS_BASIC_AUTH_USER and SS_BASIC_AUTH_PASSWORD in your .env file.' . PHP_EOL, E_USER_ERROR);
        }

        $hash = password_hash($this->password, PASSWORD_BCRYPT);
        if ($hash === false) {
            user_error('Could not hash BasicAuth password. Please check your .env file.', E_USER_ERROR);
        }

        $line = $this->userName . ':' . $hash . PHP_EOL;

        $result = @file_put_contents($this->htpasswdPath, $line, LOCK_EX);
        if ($result === false) {
            user_error('Could not write .htpasswd file at: ' . $this->htpasswdPath, E_USER_ERROR);
        }

        @chmod($this->htpasswdPath, 0640);

        $this->logMessage('.htpasswd file created.');
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
            user_error(
                PHP_EOL . PHP_EOL . 'Please set ' . self::class . ':canonical_url (e.g. mysite.co.nz) in YAML config.' . PHP_EOL,
                E_USER_ERROR
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

    /**
     * @return array<int, string>
     */
    private function buildHtaccessDirectiveLines(string $liveSiteHost): array
    {
        $templateLines = (array) $this->config()->get('htaccess_lines');

        $excludedHosts = $this->normaliseList(
            array_merge([$liveSiteHost], (array) $this->config()->get('excluded_from_basic_auth_hosts')),
            fn(string $host): string => $this->normaliseHost($host)
        );

        $devExclusions = $this->normaliseList((array) $this->config()->get('dev_exclusions'));

        $legitSites = [];
        foreach ((array) $this->config()->get('legit_sub_domains') as $subDomain) {
            $subDomainString = trim((string) $subDomain);
            if ($subDomainString !== '') {
                $legitSites[] = $subDomainString . '.' . $liveSiteHost;
            }
        }

        $legitHosts = $this->normaliseList(
            array_merge($excludedHosts, $legitSites, (array) $this->config()->get('legit_sites')),
            fn(string $host): string => $this->normaliseHost($host)
        );

        $devExclusionsRegex = $this->buildSuffixRegexForRewriteCond($devExclusions);
        $legitSitesRegex = $this->buildExactHostsRegex($legitHosts);

        $outputLines = [];

        foreach ($templateLines as $line) {
            $lineString = (string) $line;
            $trimmed = trim($lineString);

            if ($trimmed === self::HTPASSWD_PATH_MARKER) {
                $outputLines[] = 'AuthUserFile ' . $this->htpasswdPath;
                continue;
            }

            if ($trimmed === self::ADD_HOSTS_MARKER) {
                foreach ($excludedHosts as $host) {
                    $safeHost = str_replace('\'', '\\\'', strtolower($host));
                    $outputLines[] = '  Require expr tolower(%{HTTP_HOST}) == \'' . $safeHost . '\'';
                }

                foreach ($devExclusions as $suffix) {
                    $safeSuffixRegex = preg_quote($suffix, '/');
                    $outputLines[] = '  Require expr %{HTTP_HOST} =~ /' . $safeSuffixRegex . '$/i';
                }

                continue;
            }

            $lineString = str_replace(self::DEV_EXCLUSIONS_MARKER, $devExclusionsRegex, $lineString);
            $lineString = str_replace(self::LIST_OF_LEGIT_SITES_MARKER, $legitSitesRegex, $lineString);
            $lineString = str_replace(self::LIVE_SITE_HOST_MARKER, $liveSiteHost, $lineString);

            $outputLines[] = $lineString;
        }

        $this->assertNoMarkersRemain($outputLines);

        return $outputLines;
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
            fn(string $suffix): string => preg_quote($suffix, '/'),
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
            fn(string $host): string => preg_quote($host, '/'),
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
                self::DEV_EXCLUSIONS_MARKER,
                self::LIST_OF_LEGIT_SITES_MARKER,
                self::LIVE_SITE_HOST_MARKER,
            ] as $marker
        ) {
            if (str_contains($joined, $marker)) {
                user_error('Unreplaced .htaccess marker found: ' . $marker, E_USER_ERROR);
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

        return strtolower(trim($host));
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

    private function logMessage(string $message): void
    {
        if ((bool) $this->config()->get('debug')) {
            DB::alteration_message($message, 'edited');
        }
    }
}
