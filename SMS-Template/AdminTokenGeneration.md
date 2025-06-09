# How to generate admin token for SMS Template

## Step 1:

get access token of student after login in authService login `/api/login/student`
it will something like this
`eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEiLCJqa3UiOiJodHRwOi8vbG9jYWxob3N0OjUwMDEvLndlbGwta25vd24vandrcy5qc29uIn0.eyJ1c2VySWQiOiI2ODQ2MmY0MGM0MzQxNTQ5Yzk2ODFmM2QiLCJlbWFpbCI6InJhbmRvbTcyOUBleGFtcGxlLmNvbSIsInJvbGUiOiJzdHVkZW50IiwiaWF0IjoxNzQ5NDg3MjYxLCJleHAiOjE3NDk0OTA4NjF9.JhEEhdad-CvdKav9dV8E70umYSnpc9WwXMNde8nUuTGHo9VJFbnI5lceec7irwMajbI2svH7gu-tYUWzd1sevH-jUZGS44qp6cnWjurTaT7bXLWY98OmUvEoIGIp67x7woK0zjTT4rJldHq47JnhV8i4Nc0dH2rV7mOZBVvuEt-Ma0LlSoD7-Rzq_y4NAUDvskciSf7JTRhekQDVF1uwxjmMyToIYfvW3sKXDC4d2qlfZyYYpgN28ti9f4o5I-Vg9ijVbhlO0VR7mPiE9J2LJSu4ltTfxnfwjIdCUhcrQU8k6UPdhDuibONj3-XdImvO3w4g-LXeGEdIC6_4aMEvqg`

## Step 2:

Go to  [JWT.io](https://jwt.io/) and paste the token generated in step 1.

on the right side you'll get a header

```
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "1",
  "jku": "http://localhost:5001/.well-known/jwks.json"
}
```

## Step 3:

Go to Postman Authorization section and chose the `JWT Bearer`
![](https://beta.appflowy.cloud/api/file_storage/07114c05-dcef-47c0-bcbe-bee5ec0aca71/v1/blob/0ac78e18%2Dc777%2D471e%2Db9ba%2D38ca710aef0f/M7ie0qHeQznrF5dJKuh_cFtkrVjNmO9wotBBd5kvjEY=.png)

in header, paste the header from step 2 and paste the private key from authService
in payload paste

```
{
  "iat": 1717940785,
  "exp": 1718582399,
  "roles": "admin"
}
```

send (don't worry, it is supposed to fail)

## Step 4:

then click on code option on the right panel

![](https://beta.appflowy.cloud/api/file_storage/07114c05-dcef-47c0-bcbe-bee5ec0aca71/v1/blob/0ac78e18%2Dc777%2D471e%2Db9ba%2D38ca710aef0f/q8zYI529gDtpJ6LC9gRIKCcP2OSlHPz7l6Rxoqb3QNc=.png)

copy the text after `token=`
Congratulations, you got your admin token.

### NOTE: This is the most inefficient way to generate the token, the proper way would be add an entry in mongo for admin, set a login route for admin in authService and then get the token. But, I'm too lazy at this point to implement it, so you can do you.