<?php

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

    private static $htaccess_files = [
        'public/.htaccess',
        'public/assets/.htaccess',
    ];

    private static $htaccess_lines = [
        'AuthUserFile ',
        'AuthType Basic',
        'AuthName "Please enter your website username and password to access this site."',
        'Require valid-user',
    ];

    private static $debug = false;

    private bool $needsProtection;
    private ?string $userName;
    private ?string $password;
    private string $base;
    private string $htpasswdPath;
    private array $htaccessPaths;

    public static function flush(): void
    {
        $instance = Injector::inst()->get(self::class);
        $instance->initialize();
        $instance->process();
    }

    private function initialize(): void
    {
        $this->needsProtection = Director::isTest();
        $this->userName = Environment::getEnv('SS_BASIC_AUTH_USER');
        $this->password = Environment::getEnv('SS_BASIC_AUTH_PASSWORD');
        $this->base = Director::baseFolder();
        $this->htpasswdPath = $this->base . '/.htpasswd';
        if ($this->userName && !$this->password) {
            $this->needsProtection = false;
        }
        foreach ($this->config()->htaccess_files as $htaccessFile) {
            $this->htaccessPaths[] = $this->base . '/' . $htaccessFile;
        }
        if ($this->needsProtection && ($this->userName && $this->password)) {
            // all is good in the hood
        } else {
            user_error(
                '

Please set SS_BASIC_AUTH_USER and SS_BASIC_AUTH_PASSWORD in your .env file.
To turn this off, you can just set SS_BASIC_AUTH_USER and no SS_BASIC_AUTH_PASSWORD.

                ',
                E_USER_ERROR
            );
        }
    }

    private function process(): void
    {
        $this->checkBasicAuthConfig();

        if ($this->needsProtection) {
            $this->createHtpasswdFile();
        } else {
            $this->deleteHtpasswdFile();
        }

        $this->updateHtaccessFiles();
    }

    private function checkBasicAuthConfig(): void
    {
        if (
            $this->needsProtection &&
            (
                Config::inst()->get(BasicAuth::class, 'entire_site_protected') ||
                Environment::getEnv('SS_USE_BASIC_AUTH')
            )
        ) {
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
        $hashedPassword = password_hash($this->password, PASSWORD_BCRYPT);
        file_put_contents($this->htpasswdPath, $hashedPassword . PHP_EOL);
        $this->logMessage('.htpasswd file created.');
    }

    private function deleteHtpasswdFile(): void
    {
        if (file_exists($this->htpasswdPath)) {
            // unlink($this->htpasswdPath);
            // $this->logMessage('.htpasswd file removed.');
        }
    }
    private function updateHtaccessFiles(): void
    {
        $startMarker = PHP_EOL . PHP_EOL . '# START_BASIC_AUTH';
        $endMarker = '# END_BASIC_AUTH' . PHP_EOL . PHP_EOL;

        $authDirectives = $this->config()->htaccess_lines;
        $authDirectives[0] .= ' ' . $this->htpasswdPath;

        // Combine directives with markers
        $authBlock = implode(PHP_EOL, array_merge([$startMarker], $authDirectives, [$endMarker]));

        foreach ($this->htaccessPaths as $htaccessPath) {
            if (!file_exists($htaccessPath)) {
                if ($this->needsProtection) {
                    file_put_contents($htaccessPath, PHP_EOL . $authBlock . PHP_EOL, FILE_APPEND);
                    $this->logMessage('.htaccess file created: ' . $htaccessPath);
                }
                continue;
            }

            $existingContent = file_get_contents($htaccessPath);

            if ($this->needsProtection) {
                if (!str_contains($existingContent, $startMarker)) {
                    file_put_contents($htaccessPath, PHP_EOL . $authBlock . PHP_EOL . $existingContent);
                    $this->logMessage('Added BasicAuth protection to: ' . $htaccessPath);
                } else {
                    $this->logMessage('BasicAuth protection already present in: ' . $htaccessPath);
                }
            } else {
                // Remove the BasicAuth block if it exists
                $pattern = '/' . preg_quote($startMarker, '/') . '.*?' . preg_quote($endMarker, '/') . '\s*/s';
                $updatedContent = preg_replace($pattern, '', $existingContent);

                if ($updatedContent !== $existingContent) {
                    file_put_contents($htaccessPath, $updatedContent);
                    $this->logMessage('Removed BasicAuth protection from: ' . $htaccessPath);
                } else {
                    $this->logMessage('No BasicAuth protection block found in: ' . $htaccessPath);
                }
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
