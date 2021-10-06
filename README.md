# **Aeiro SSO**

## **Endpoint documentation**

### /api/users/new
This endpoint will create a new user. It expects a JSON body containing the username and the password of the user to create. Example:

    {
        "username": "john",
        "password": "1234"
    }

This will create a new user and return the status code 201 on success.

### /api/users/authenticate
This endpoint is responsible for returning new access tokens and creating new access tokens from a refresh token, after the original access token has expired.

#### **Create a new access token**
A request to create a new access token would look like this:

    {
        "username": "john",
        "password": "1234",
        "client_id": "<client_id>",
        "client_secret": "<client_secret>",
        "scope": "all",
        "response_type: "code"
    }

In this case the server would respond with a 200 response code and a JSON body containing the access token, the refresh token and the expiration date for the access token as a UNIX timestamp.

    {
        "access_token": "<access_token>",
        "refresh_token": "<refresh_token>",
        "expiration": <expiration>,
        "status_code": 201,
        "error": null,
        "success": true
    }

An access token will expire one month after it has been creation.

#### **Use a refresh token to obtain a new access token**
To avoid having to send the user's username and password every time the access token expires, the refresh token is used to obtain a new access token. This can be done by setting the `response_type` field to `refresh`.

    {
        "username": "john",
        "client_id": "<client_id>",
        "refresh_token": "<refresh_token>",
        "response_type": "refresh"
    }

As you can see, here the user's password is not required. This makes it so the application using the API does not have to save the user's password.

The response body from the server would then be identical to the one for obtaining a new access token except the refresh token stays the same.


## **Things that might need to change**

 - Make it so the /api/users/authenticate endpoint requires the user id instead the username
 - The client_secret might be unnecessary in the /api/users/authenticate endpoint when requesting a new access token. Having it be necessary would mean that a desktop application might need to be packaged with the client_secret which would not be very secure.