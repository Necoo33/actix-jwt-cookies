# Actix Jwt Cookies

Store your data in encrypted cookies and get it elegantly in actix-web framework.

This crate developed for especially working on actix-web, it helps you to store data more elegantly.

## Guide

Import that crate:

```rust

use actix_jc::ActixJwtCookie;

```

First, you have to initialize an instance:

```rust

// ...

let cookie_builder = ActixJwtCookie::new().cookie_name("your_cookie").jwt_key("your jwt key").permanent();

// ...

```

Then, wrap it via an `Arc` type:

```rust

let cookie_builder = Arc::new(cookie_builder);

```

Then save it some way for reach it on your application, as a global state or hashmap, etc.

later than reaching that instance, create a cookie with `.create()` function:

```rust

// assuming you get the instance with same variable name it declared above:

// it returns a CookieBuilder<'_>, you can continue building cookie more or just finish it with `.finish()` method.

let create_cookie = cookie_builder.create(120); // pass the data which you want to encrypt. The type of that data must implement serde::Serialize and serde::Deserialize traits.

```

Then check and get it if it's exist or not. It takes an argument which has type of `actix_web::HttpRequest`:

```rust

// ...

// assuming you get the instance with a variable named "cookie"

match cookie.check(req) {
    Some(cookie) => cookie, // it returns the encrypted value in the token. In this example, "120" as i32.
    None => () // do something, it means either cookie not exist or malformed. If it is malformed, it prints as a log. In later releases, it will be handled by more idiomatic way.
}

// ...

```
