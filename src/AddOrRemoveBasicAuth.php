<?php

namespace Sunnysideup\BasicAuthBetter;

use SilverStripe\Control\Director;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Flushable;
use SilverStripe\Security\BasicAuth;

class AddOrRemoveBasicAuth implements Flushable
{

    public static function flush()
    {
        $needsProtection = Director::isTest();
        $userName = Environment::getEnv('SS_BASIC_AUTH_USER');
        $password = Environment::getEnv('SS_BASIC_AUTH_PASSWORD');
        if ($needsProtection) {
            if ((!$userName || !$password)) {
                user_error('Please set SS_BASIC_AUTH_USER and SS_BASIC_AUTH_PASSWORD in your .env file.', E_USER_WARNING);
            }
        }
        if (!Director::isLive()) {
            if (Config::inst()->get(BasicAuth::class, 'entire_site_protected')) {
                user_error(
                    '
                    BasicAuth is enabled in the config.
                    Please remove the BasicAuth::protect_entire_site() call from your _config.php file.
                    Or set ' . BasicAuth::class . ':entire_site_protected: false
                    ',
                    E_USER_WARNING
                );
            }
        }
        $base = Director::baseFolder();
        $htpasswdPath = $base . '/.htpasswd';
        $htaccessPaths = [
            $base . '/public/.htaccess',
            $base . '/public/assets/.htaccess',
        ];
        if ($needsProtection) {
            self::createOrUpdateHtpasswd($htpasswdPath, $userName, $password);
        } else {
            self::removeHtpasswd($htpasswdPath);
        }
        self::updateHtaccessFiles($htaccessPaths, $htpasswdPath, $needsProtection);
    }
    private static function createOrUpdateHtpasswd(string $htpasswdPath, string $userName, string $password)
    {
        $defaultPassword = $userName . ':' . password_hash($password, PASSWORD_BCRYPT);
        file_put_contents($htpasswdPath, $defaultPassword . PHP_EOL);
        echo '.htpasswd file created.' . PHP_EOL;
    }

    private static function removeHtpasswd(string $htpasswdPath)
    {
        if (file_exists($htpasswdPath)) {
            unlink($htpasswdPath);
            echo '.htpasswd file removed.' . PHP_EOL;
        }
    }

    private static function updateHtaccessFiles(array $htaccessPaths, string $htpasswdPath, bool $needsProtection)
    {
        $htaccessLines = [
            'AuthUserFile ' . $htpasswdPath,
            'AuthType Basic',
            'AuthName "Please enter your website username and password to access this site."',
            'Require valid-user',
        ];

        foreach ($htaccessPaths as $htaccessPath) {
            if (!file_exists($htaccessPath)) {
                if ($needsProtection) {
                    file_put_contents($htaccessPath, implode(PHP_EOL, $htaccessLines) . PHP_EOL);
                    echo '.htaccess file ' . $htaccessPath . ' created and updated.' . PHP_EOL;
                }
            } else {
                $existingContent = file_get_contents($htaccessPath);

                if ($needsProtection) {
                    foreach ($htaccessLines as $line) {
                        if (!str_contains($existingContent, $line)) {
                            file_put_contents($htaccessPath, $line . PHP_EOL, FILE_APPEND);
                        } elseif (str_contains($existingContent, '#' . $line)) {
                            $existingContent = str_replace('#' . $line, $line, $existingContent);
                        }
                    }
                    file_put_contents($htaccessPath, $existingContent);
                    echo '.htaccess file updated with protection.' . PHP_EOL;
                } else {
                    $updatedContent = $existingContent;
                    foreach ($htaccessLines as $line) {
                        if (str_contains($existingContent, $line) && !str_contains($existingContent, '#' . $line)) {
                            $updatedContent = str_replace($line, '#' . $line, $updatedContent);
                        }
                    }
                    file_put_contents($htaccessPath, $updatedContent);
                    echo '.htaccess file protection commented out.' . PHP_EOL;
                }
            }
        }
    }
}
