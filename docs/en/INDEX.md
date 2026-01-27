# tl;dr

Add to .env file:

```.env
SS_BASIC_AUTH_USER=foo
SS_BASIC_AUTH_PASSWORD=bar
```

Add to your yml files:

```yml
Sunnysideup\BasicAuthBetter\AddOrRemoveBasicAuth:
  excluded_hosts:
    - mysite.co.nz
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

or use the yml option above.
