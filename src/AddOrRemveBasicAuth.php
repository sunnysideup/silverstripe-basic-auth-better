<?php

namespace Sunnysideup\BasicAuthBetter;

class AddOrRemveBasicAuth implements Flushable
{
    public static function flush()
    {
        $htpasswdPath = '/container/application/.htpasswd';
        $htaccessPaths = [
            'public/.htaccess',
            'public/assets.htaccess',
        ];


        // Check if .htpasswd file exists, create it if not
        $defaultPassword = 'user:' . password_hash('password123', PASSWORD_BCRYPT);
        file_put_contents($htpasswdPath, $defaultPassword . PHP_EOL);
        echo '.htpasswd file created.' . PHP_EOL;

        // Define the lines to be added
        $htaccessLines = [
            'AuthUserFile ' . $htpasswdPath . '.htpasswd',
            'AuthType Basic',
            'AuthName "My restricted Area"',
            'Require valid-user'
        ];
        foreach ($htaccessPaths as $htaccessPath) {
            // Check if .htaccess file exists, create or append to it
            if (!file_exists($htaccessPath)) {
                file_put_contents($htaccessPath, implode(PHP_EOL, $htaccessLines) . PHP_EOL);
                echo '.htaccess file created and updated.' . PHP_EOL;
            } else {
                $existingContent = file_get_contents($htaccessPath);
                foreach ($htaccessLines as $line) {
                    if (!str_contains($existingContent, $line)) {
                        file_put_contents($htaccessPath, $line . PHP_EOL, FILE_APPEND);
                    }
                }
                echo '.htaccess file updated.' . PHP_EOL;
            }
        }
    }
}
