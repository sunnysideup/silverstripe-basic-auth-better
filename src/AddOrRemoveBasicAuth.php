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
     *
     * e.g. mysite.co.nz (without https!)
     * @var string
     */
    private static string $live_site = '';

    private static array $excluded_hosts = [];

    private static array $dev_exclusions = [
        '.localhost',
        '.ss4',
        '.ddev',
    ];

    private static array $htaccess_files = [
        'public/.htaccess',
        'public/assets/.htaccess',
    ];
    private static array $htaccess_lines = [
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
    private bool $needsProtection = true; // should always be true!

    private ?string $userName;
    private ?string $password;
    private string $base;
    private string $htpasswdPath;
    private array $htaccessPaths;
    public static function flush(): void
    {
        /**
         * @var AddOrRemoveBasicAuth $instance
         */
        if (Config::inst()->get(AddOrRemoveBasicAuth::class, 'disabled')) {
            return;
        }
        $instance = Injector::inst()->get(self::class);
        $instance->initialize();
        $instance->process();
    }

    public function initialize(): void
    {
        $this->userName = (string) (Environment::getEnv('SS_BASIC_AUTH_USER')
            ?: Environment::getEnv('SS_BASIC_AUTH_USERNAME')
            ?: $this->config()->default_user_name);

        $this->password = (string) (Environment::getEnv('SS_BASIC_AUTH_PASSWORD')
            ?: $this->config()->default_password);

        $this->base = Director::baseFolder();
        $this->htpasswdPath = $this->base . '/.htpasswd';

        // // Allow "username only" to mean "off"
        // if ($this->userName !== '' && $this->password === '') {
        //     $this->needsProtection = false;
        // }

        $this->htaccessPaths = [];
        foreach ((array) $this->config()->htaccess_files as $htaccessFile) {
            $this->htaccessPaths[] = $this->base . '/' . ltrim((string) $htaccessFile, '/');
        }

        if ($this->needsProtection && ($this->userName === '' || $this->password === '')) {
            user_error(
                "\n\nPlease set SS_BASIC_AUTH_USER and SS_BASIC_AUTH_PASSWORD in your .env file.\n",
                E_USER_ERROR
            );
        }
    }

    public function process(): void
    {
        $this->checkBasicAuthConfig();

        if ($this->needsProtection) {
            $this->createHtpasswdFile();
        } else {
            $this->deleteHtpasswdFile();
        }

        // I’d recommend always ensuring htaccess is correct on flush
        $this->updateHtaccessFiles();
    }
    public function checkBasicAuthConfig(): void
    {
        if ($this->needsProtection && (Config::inst()->get(BasicAuth::class, 'entire_site_protected') || Environment::getEnv('SS_USE_BASIC_AUTH'))) {
            user_error(
                '

BasicAuth is enabled in the config.
Remove the BasicAuth::protect_entire_site() call from your _config.php file
or set ' . BasicAuth::class . ':entire_site_protected: false
and make sure that in your .env file, you do not have SS_USE_BASIC_AUTH set to true.

                ',
                E_USER_WARNING
            );
        }
    }
    private function createHtpasswdFile(): void
    {
        $hash = password_hash($this->password ?? '', PASSWORD_BCRYPT);
        if ($hash === false) {
            user_error('Could not hash BasicAuth password. Please check your .env file.', E_USER_ERROR);
        }
        $line = $this->userName . ':' . $hash . PHP_EOL;
        file_put_contents($this->htpasswdPath, $line, LOCK_EX);
        $this->logMessage('.htpasswd file created.');
    }
    private function deleteHtpasswdFile(): void
    {
        if (file_exists($this->htpasswdPath)) {
            unlink($this->htpasswdPath);
            $this->logMessage('.htpasswd file removed.');
        }
    }

    private function updateHtaccessFiles(): void
    {
        $authDirectives = (array) $this->config()->htaccess_lines;

        foreach ($authDirectives as $index => $line) {
            $trimmedLine = trim((string) $line);

            if ($trimmedLine === self::HTPASSWD_PATH_MARKER) {
                $authDirectives[$index] = 'AuthUserFile ' . $this->htpasswdPath;
                continue;
            }

            if ($trimmedLine === self::ADD_HOSTS_MARKER) {
                $excludedHostsLines = [];

                // Use your module config (since you defined it)
                $excludedHosts = (array) ($this->config()->excluded_hosts ?? []);

                foreach ($excludedHosts as $host) {
                    $host = trim((string) $host);
                    if ($host === '') {
                        continue;
                    }

                    $excludedHostsLines[] =
                        '  Require expr %{HTTP_HOST} == \'' . str_replace('\'', '\\\'', $host) . '\'';
                }
                // Use your module config (since you defined it)
                $devExclusions = (array) ($this->config()->dev_exclusions ?? []);

                foreach ($devExclusions as $suffix) {
                    $suffix = trim((string) $suffix);
                    if ($suffix === '') {
                        continue;
                    }

                    $excludedHostsLines[] =
                        '  Require expr %{HTTP_HOST} =~ /' . preg_quote($suffix, '/') . '$/i';
                }

                array_splice($authDirectives, $index, 1, $excludedHostsLines);
            }
        }

        $authBlock =
            self::START_MARKER . PHP_EOL .
            implode(PHP_EOL, $authDirectives) . PHP_EOL .
            self::END_MARKER . PHP_EOL;

        $pattern =
            '/^' . preg_quote(self::START_MARKER, '/') .
            '.*?^' . preg_quote(self::END_MARKER, '/') .
            '\R?/ms';

        foreach ($this->htaccessPaths as $htaccessPath) {
            $existingContent = file_exists($htaccessPath) ? (string) file_get_contents($htaccessPath) : '';

            if ($this->needsProtection) {
                $updatedContent = str_contains($existingContent, self::START_MARKER)
                    ? (preg_replace($pattern, $authBlock, $existingContent) ?? $existingContent)
                    : ($authBlock . $existingContent);

                file_put_contents($htaccessPath, $updatedContent, LOCK_EX);
                $this->logMessage('BasicAuth protection ensured in: ' . $htaccessPath);
            } else {
                if ($existingContent === '') {
                    continue;
                }

                $updatedContent = preg_replace($pattern, '', $existingContent) ?? $existingContent;
                file_put_contents($htaccessPath, $updatedContent, LOCK_EX);
                $this->logMessage('BasicAuth protection removed from: ' . $htaccessPath);
            }
        }
    }

    private function logMessage(string $message): void
    {
        if ($this->config()->debug) {
            DB::alteration_message($message, 'edited');
        }
    }
}
