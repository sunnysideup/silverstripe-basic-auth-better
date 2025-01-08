# tl;dr

Add to .env file:

```.env
SS_BASIC_AUTH_USER=foo
SS_BASIC_AUTH_PASSWORD=bar
```

Then just run ?flush=all

If your site is in `test` mode (Director::isTest()), password protection will be added.
If your site is not in `test` mode then password protection will be removed.

