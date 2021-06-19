# Lichess OAuth 2.0 PKCE

This is a demo application using Proof Key Code Exchange (https://oauth.net/2/pkce/) to ask for authorization to read the users e-mail address at the chess site Lichess (https://lichess.org/).

Launching the application will start a Web Browser which the user can use to choose to authorize this demo application to read the e-mail address.
This flow can be used to implement applications wanting to use authenticated endpoints of the Lichess API (https://lichess.org/api)

## Run

Make sure to use at least Java 11,

    $ java -version
    openjdk version "11.0.11" 2021-04-20
    OpenJDK Runtime Environment AdoptOpenJDK-11.0.11+9 (build 11.0.11+9)
    OpenJDK 64-Bit Server VM AdoptOpenJDK-11.0.11+9 (build 11.0.11+9, mixed mode)

Run with following command

    $ java LichessPKCE.java

