use std::borrow::Cow;
use std::marker::PhantomData;

use actix_web::cookie::CookieBuilder;
use actix_web::HttpRequest;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use actix_web::cookie::{Cookie, time::Duration};
use serde::{Serialize, Deserialize};

pub struct ActixJwtCookie<T> {
    pub name: Cow<'static, str>,
    pub exist: bool,
    pub expiration: AuthExpiration,
    pub jwt_key: Cow<'static, str>,
    _marker: PhantomData<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claims<T> {
    model: T,
    exp: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthExpiration {
    Permanent,
    Time(Duration),
}

impl<T> ActixJwtCookie<T> where T: Serialize + for<'de> Deserialize<'de> + 'static {
    pub fn new() -> Self {
       Self::default() 
    }

    pub fn cookie_name(mut self, cookie_name: &'static str) -> Self {
        self.name = Cow::Borrowed(cookie_name);
        self
    }

    pub fn expiration(mut self, seconds: i64) -> Self {
        self.expiration = AuthExpiration::Time(Duration::seconds(seconds));
        self
    }

    pub fn permanent(mut self) -> Self {
        self.expiration = AuthExpiration::Permanent;
        self
    }

    pub fn jwt_key(mut self, jwt_key: &'static str) -> Self {
        self.jwt_key = Cow::Borrowed(jwt_key);
        self
    }

    fn create_jwt(&self, model: T) -> String {
        let claims = Claims {
            model,
            exp: 170000000000000,
        };

        match encode(&Header::default(), &claims, &EncodingKey::from_secret(self.jwt_key.as_bytes())) {
            Ok(t) => t,
            Err(err) => {
                println!("Error occurred when encoding jwt: {}", err);
                panic!()
            }
        }
    }

    fn verify_jwt_and_return_value(&self, jwt_token: &str) -> Result<T, jsonwebtoken::errors::Error> {
        let token = match decode::<Claims<T>>(
            jwt_token,
            &DecodingKey::from_secret(self.jwt_key.as_bytes()),
            &Validation::default()
        ) {
            Ok(t) => t,
            Err(err) => {
                println!("Error occurred when decoding jwt: {}", err);
                return Err(err);
            },
        };

        Ok(token.claims.model)
    }

    pub fn exist(&self, req: HttpRequest) -> Option<T> {
        match req.cookie(&self.name) {
            Some(cookie) => {
                match self.verify_jwt_and_return_value(cookie.value()) {
                    Ok(data) => Some(data),
                    Err(error) => {
                        println!("That error occured when we verify the jwt on .check() method: {}", error);

                        None
                    }
                }
            },
            None => None
        } 
    }

    pub fn create(&self, data: T) -> CookieBuilder<'_> {
        let jwt = self.create_jwt(data);

        match self.expiration {
            AuthExpiration::Time(time) => Cookie::build(self.name.clone(), jwt).max_age(time),
            AuthExpiration::Permanent => Cookie::build(self.name.clone(), jwt).permanent()
        }
    }
}

impl<T> Default for ActixJwtCookie<T> where T: Serialize + for<'de> Deserialize<'de> + 'static {
    fn default() -> Self {
        Self {
            name: Cow::Borrowed("actix-jwt-cookie"),
            exist: false,
            expiration: AuthExpiration::Time(Duration::seconds(7200)),
            jwt_key: Cow::Borrowed("stand with palestine!"),
            _marker: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_valid_actix_cookie() {
        let configure_builder = ActixJwtCookie::new().cookie_name("my_cookie").jwt_key("asfasdfas").permanent();

        let build = configure_builder.create(12).finish();

        let create_cookie = CookieBuilder::new("my_cookie", "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJtb2RlbCI6MTIsImV4cCI6MTcwMDAwMDAwMDAwMDAwfQ.MLimFgGj1U8Ds7_QnS_WP3fWwQB3bfkRClAOlU3A1cU").permanent().finish();

        assert_eq!(build.name(), create_cookie.name());
        assert_eq!(build.value(), create_cookie.value());
        assert!(build.expires().is_some());
        assert!(build.max_age().is_some());
    }

    #[test]
    fn test_is_decodes_correct(){
        let decoded_value = match decode::<Claims<i32>>(
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJtb2RlbCI6MTIsImV4cCI6MTcwMDAwMDAwMDAwMDAwfQ.MLimFgGj1U8Ds7_QnS_WP3fWwQB3bfkRClAOlU3A1cU",
            &DecodingKey::from_secret(Cow::Borrowed("asfasdfas").as_bytes()),
            &Validation::default()
        ) {
            Ok(t) => t.claims.model,
            Err(err) => {
                println!("Error occurred when decoding jwt: {}", err);
                
                panic!("{}", err)
            },
        };

        assert_eq!(decoded_value, 12)
    }
}
