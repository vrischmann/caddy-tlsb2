# caddy-tlsb2

**NOTE**: Caddy changed the way TLS storage works with a new interface [caddytls.ClusterPluginConstructor](https://godoc.org/github.com/mholt/caddy/caddytls#ClusterPluginConstructor).

I plan to update this module in the future. `v1.0.0` is the tag you'll want to use if you're still using Caddy up to `v0.11.1`.

This is an implementation of the [caddytls.Storage](https://github.com/mholt/caddy/blob/master/caddytls/storage.go#L69) interface using Backblaze's B2 Cloud Storage.

## Disclaimer

This has not been tested thoroughly and is not production ready; use at your own risk.

## Prerequisites

First of all you need to have a [B2 Cloud Storage](https://www.backblaze.com/b2/cloud-storage.html) account. Once done you also need to create a bucket to store your data.
I also recommend generating an application key specifically for Caddy.

Once done you should have three things:

 * Account ID or Application Key ID
 * Account Master Key or Application Key
 * Bucket ID

## Installation

You need to compile Caddy yourself to make use of this plugin.

TODO(vincent): document properly.

## Configuration

### B2 credentials

To use B2 you need to add three environment variables so the plugin knows how to access your data:

 * `B2_ACCOUNT_ID`: this is the account id _or_ an application key id.
 * `B2_ACCOUNT_KEY`: this is the account master key _or_ an application key.
 * `B2_BUCKET`: this is the id of the bucket you want to use (_not_ the name).

Make sure to set this correctly when running Caddy.

### Caddy

The Caddy configuration is straightforward:

    foo.bar {
        tls {
            storage b2
        }
    }

and you're done.
