# Caddy OAuth2 authentication plugin

This is a plugin for [Caddy](https://caddyserver.com) which provides login capabilities by deferring to an identity provider to
do the actual authentication work.

An identity provider is something like Google or Facebook. Right now only Google is supported.

Here's a straightforward example, say you want to restrict access to your organisation and you happen to use G Suite:

    mywebsite.fr {
        root /data

        login {
            path /
            login_path /login
            callback_path /oauth2/callback

            allow hd myorganisation.fr

            jwt_secret {$JWT_SECRET}
            google client_id={$GOOGLE_CLIENT_ID} client_secret={$GOOGLE_CLIENT_SECRET}
        }
    }

Now every requests to mywebsite.fr will have to be authenticated.

## Disclaimer

This has not been tested for a long time or in a lot of different scenarios: it's born out of necessity for a personal website and I tested it that way.

Therefore there's no guarantee it will work for your use case or that there won't be bugs.

The options of the `login` directive are not final either: it will probably evolve.

## Installation

The simplest way is to follow [the Caddy documentation](https://github.com/mholt/caddy#build) to build your binary.

Then you just need to import the plugin:

    package main

    import (
            "github.com/mholt/caddy/caddy/caddymain"

            _ "go.rischmann.fr/caddy-login-oauth2"
    )

    func main() {
            caddymain.Run()
    }

And you're done.

## Usage

### Getting credentials from Google

This plugin only supports login via Google. In order to use it you need to create a project on the [Google Console](https://console.developers.google.com).

Once you've configured everything you only need two things: the _client ID_ and the _client secret_.

### Configuring the plugin

As seen in the example above, this plugin introduces the `login` directive to protect a path.

These are all the available options:

* `path` defines the path to protect, for example `/admin`.
* `login_path` defines the path of the login form, for example `/admin/login`.

Note that no _actual_ login is done here: this page is simply a prompt telling the user
that it will be redirected to Google for authentication.

We don't want to forward the user straight to Google without any warning or explanation.

* `callback_path` defines the path of the OAuth2 callback, for example `/admin/oauth2/callback`.

Google will redirect the user to this path once authentication has been performed.

Note that it **must** match the callback you defined in your OAuth2 configuration on the Google Console.

* `allow` and `deny` define ACLs based on the claims in the JWT.

Only two kinds of claims are supported, `sub` and `hd`. Look at the "ACL internals overview" to understand what they are.

You can combine multiple `allow` and `deny` to have complex ACLs, for example:

    allow sub vincent@gmail.com
    deny sub manu@gmail.com
    allow hd rischmann.fr

Note that `allow` takes precedence over `deny`. Also, if a claim doesn't exist it is automically denied (for example if the user is not part of an organization
therefore the `hd` claim doesn't exist).

* `jwt_secret` defines the secret to use as a key for the crpytographic signature of the JWT this plugin will generate.

It's recommended to reference an environment variable and never store the secret in your Caddyfile, like this:

    login {
        ...
        jwt_secret {$JWT_SECRET}
    }

* `google` defines the OAuth2 parameters for Google, the _client ID_ and _client secret_.

They need to be provided as two arguments:

    login {
        ...
        google client_id={$GOOGLE_CLIENT_ID} client_secret={$GOOGLE_CLIENT_SECRET}
    }

As before, it's recommended to use environment variables.

## ACL internals overview

To implement ACLs we must have access to a piece of data identifying the user and we must be able to verify
we wrote it at some point in the past and that it has not been tampered with.
This implies setting a cookie on the users' browser and cryptographically signing it.

The good thing is there's already a standard for that: [JSON Web Token](https://jwt.io/).

I recommend looking at the website to understand how they work but for our goals there are two things to remember:

* A JWT is cryptographically signed, in this case with the `HS256` method therefore a secret key is required.
* A JWT once written makes some _claims_ about the user, i.e the user claims to have some attribute.

The second point is important because that's how you will write ACLs: you _allow_ or _deny_ some claims.

What claims are available are determined by what Google gives us when we fetch the users profile and it boils down to this:

* `sub` which is the email of the user
* `hd` which is the "Hosted Domain" of the organization if any.
