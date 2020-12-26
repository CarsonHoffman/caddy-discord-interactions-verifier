# Caddy Discord Interactions Verifier

If you use the [Caddy web server](https://caddyserver.com/) (which provides features such as automatic TLS management and easy configuration) and are looking to host an endpoint for outgoing webhooks under Discord's recent Interactions feature, you're in luck! This Caddy module automatically verifies the Ed25519 signature in the body, and responds with a 401 before the request ever hits your handler if the signature doesn't match.

## Installation

[Install `xcaddy`](https://github.com/caddyserver/xcaddy#install), then run:

```bash
$ xcaddy build --with github.com/CarsonHoffman/caddy-discord-interactions-verifier
```

This will output an executable named `caddy` in your current directory, which you can use as the server executable, replacing your current Caddy executable if you have one (it might be found at `/usr/bin/caddy`).

## Configuration

This module uses the `discord` Caddyfile directive. The only parameter is the hex representation of your Ed25519 public key (the representation given in the application portal). The following is a dead-simple example of a compatible Caddyfile, where our Ed25519 public key is `45a8bd39e8a146e201c2eb00e955c1484ebe4d87f8246b26dddff06d1728321a`, the endpoint is hosted at the root of `mydomain.com`, and successfully-verified requests are proxied to another server at `localhost:8080`:

```
mydomain.com

route / {
  discord 45a8bd39e8a146e201c2eb00e955c1484ebe4d87f8246b26dddff06d1728321a
  reverse_proxy localhost:8080
}
```

That's the whole configuration! The `discord` directive is all you need to include, and it couldn't be simpler.

---

This module should help you get Discord Interactions up and running if you aren't as familiar with Ed25519 or signature schemes in general. Now go make something cool!