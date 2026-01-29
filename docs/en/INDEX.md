# tl;dr

Add to .env file:

```.env
SS_BASIC_AUTH_USER=foo
SS_BASIC_AUTH_PASSWORD=bar
```

Add to your yml files:

```yml
Sunnysideup\BasicAuthBetter\AddOrRemoveBasicAuth:
    # must set!
    canonical_url: 'mysite.co.nz'
    htpasswd_path: '/container/application'

    # nice to set, but can also use .env file - which is better but more work...
    default_user_name: 'authorisedusers' # better to set this in .env file!
    default_password: 'only' # better to set this in .env file!

    # optional
    excluded_from_basic_auth_hosts:
        - mysite.co.nz
        
    # only change if you really have to!
    htaccess_files:
        - 'public/.htaccess'
        - 'public/assets/.htaccess'
    htaccess_lines:
        - 'foo'


```

Then just run ?flush=all

If your site is in `test` mode (Director::isTest()), password protection will be added.
If your site is not in `test` mode then password protection will be removed.

You may also need to set:

```.env
SS_USE_BASIC_AUTH=false
```

If you do not want to use it, you can set:

```.env
SS_BASIC_AUTH_USER="anything"
SS_BASIC_AUTH_PASSWORD=""
```

or use the yml options above.
