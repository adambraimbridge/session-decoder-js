# Session Decoder

A simple lib that allows you to decode the uuid from an FT session.

## Warning

The session token holds the UUID but not any information as to the validity of the session - for example if the session was revoked by the FT or expired.

It is therefore unsuitable to use this library for authentication.

Requests that read and write a user's data MUST authenticate directly against the Session API to ensure the session is valid.

For more information:-

- https://github.com/Financial-Times/next-session
- https://github.com/Financial-Times/next-session-client

