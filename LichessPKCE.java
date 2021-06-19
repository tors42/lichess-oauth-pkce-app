import java.awt.Desktop;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.Random;
import java.util.stream.Collectors;

import com.sun.net.httpserver.HttpServer;

public class LichessPKCE {

    /**
     * This demo application will launch a Web Browser,
     * where authentication with Lichess can be made,
     * for authorization of this demo application to
     * request the e-mail address of the authenticating
     * Lichess user - and if granted - the e-mail address
     * will be fetched and printed on standard output.
     */
    public static void main(String... args) throws Exception {

        var lichessUri = "https://lichess.org";

        // Setup a local bind address which we will use in redirect_url
        var local = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
        var httpServer = HttpServer.create(local, 0);
        var redirectHost = local.getAddress().getHostAddress();
        var redirectPort = httpServer.getAddress().getPort();

        var code_verifier = generateRandomCodeVerifier();

        var code_challenge_method = "S256";
        var code_challenge = generateCodeChallenge(code_verifier);
        var response_type = "code";
        var client_id = "apptest";
        var redirect_uri = "http://" + redirectHost + ":" + redirectPort;
        var scope = "email:read";
        var state = "foobar";

        var parameters = Map.of(
                "code_challenge_method", code_challenge_method,
                "code_challenge", code_challenge,
                "response_type", response_type,
                "client_id", client_id,
                "redirect_uri", redirect_uri,
                "scope", scope,
                "state", state
                );

        var paramString = parameters.entrySet().stream()
            .map(kv -> kv.getKey() + "=" + kv.getValue())
            .collect(Collectors.joining("&"));

        var frontChannelUrl = URI.create(lichessUri +"/oauth" + "?" + paramString);
        System.out.println("Front Channel URL, all these parameters are non-sensitive:\n" + frontChannelUrl);
        System.out.println("The actual authentication between User and Lichess happens outside of this demo application,");
        System.out.println("i.e in the browser over HTTPS.");

        // Prepare for handling the upcoming redirect,
        // after User has authenticated with Lichess,
        // and granted this demo application permission
        // to fetch the e-mail address.
        var cf = registerRedirectHandler(httpServer, lichessUri, code_verifier, redirect_uri, client_id);


        // Now we let the User authorize with Lichess,
        // using their browser
        if (Desktop.isDesktopSupported()) {
            var desktop = Desktop.getDesktop();
            if (desktop.isSupported(Desktop.Action.BROWSE)) {
                desktop.browse(frontChannelUrl);
            } else {
                System.out.format("%s%n%n%s%n  %s%n%n",
                        "Doh, Desktop.Action.BROWSE not supported...",
                        "Could you manually go to the following URL :) ?",
                        frontChannelUrl);
            }
        } else {
            System.out.format("%s%n%n%s%n  %s%n%n",
                    "Doh, Desktop not supported...",
                    "Could you manually go to the following URL :) ?",
                    frontChannelUrl);
        }

        // Blocking until user has authorized,
        // and we've exchanged the incoming authorization code for an access token
        var access_token = cf.get();

        // Authorization Flow Complete

        // Get that e-mail
        var httpClient = HttpClient.newHttpClient();
        var emailRequest = HttpRequest.newBuilder(URI.create(lichessUri + "/api/account/email"))
            .GET()
            .header("authorization", "Bearer " + access_token)
            .header("accept", "application/json")
            .build();

        var response = httpClient.send(emailRequest, BodyHandlers.ofString());

        var statusCode = response.statusCode();
        var body = response.body();
        var email = parseField("email", body);

        System.out.println("/api/account/email - " + statusCode);
        System.out.println("e-mail: " + email);

        httpServer.stop(0);
    }

    static String generateRandomCodeVerifier() {
        var bytes = new byte[32];
        new Random().nextBytes(bytes);
        var code_verifier = Base64.getUrlEncoder().encodeToString(bytes)
            .replaceAll(  "=",  "")
            .replaceAll("\\+", "-")
            .replaceAll("\\/", "_");

        return code_verifier;
    }

    static String generateCodeChallenge(String code_verifier) {
        var asciiBytes = code_verifier.getBytes(StandardCharsets.US_ASCII);
        MessageDigest md;

        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException nsa_ehhh) {
            throw new RuntimeException(nsa_ehhh);
        }

        var s256bytes = md.digest(asciiBytes);
        var code_challenge = Base64.getUrlEncoder().encodeToString(s256bytes)
            .replaceAll(  "=",  "")
            .replaceAll("\\+", "-")
            .replaceAll("\\/", "_");
        return code_challenge;
    }

    static CompletableFuture<String> registerRedirectHandler(HttpServer httpServer, String lichessUri, String code_verifier, String redirect_uri, String client_id) {
        var cf = new CompletableFuture<String>();
        httpServer.createContext("/",
                (exchange) -> {
                    httpServer.removeContext("/");

                    // The redirect arrives...
                    var query = exchange
                        .getRequestURI()
                        .getQuery();

                    var inparams = Arrays.stream(query.split("&"))
                        .collect(Collectors.toMap(
                                    s -> s.split("=")[0],
                                    s -> s.split("=")[1]
                                    ));

                    var code = inparams.get("code");

                    if (code == null) {
                        exchange.sendResponseHeaders(503, -1);
                        cf.completeExceptionally(new Exception("Authorization Failed"));
                        return;
                    }

                    // We have received meta data from Lichess,
                    // about the fact that the User has authorized us - yay!

                    // Let's respond with a nice HTML page in celebration.
                    var responseBytes = "<html><body><h1>Success, you may close this page</h1></body></html>".getBytes();
                    exchange.sendResponseHeaders(200, responseBytes.length);
                    exchange.getResponseBody().write(responseBytes);


                    // Now,
                    // let's go to Lichess and ask for a token - using the meta data we've received
                    var tokenParameters = Map.of(
                            "code_verifier", code_verifier,
                            "grant_type", "authorization_code",
                            "code", code,
                            "redirect_uri", redirect_uri,
                            "client_id", client_id
                            );

                    var tokenParamsString = tokenParameters.entrySet().stream()
                        .map(kv -> kv.getKey() + "=" + kv.getValue())
                        .collect(Collectors.joining("&"));

                    var httpClient = HttpClient.newHttpClient();
                    var tokenRequest = HttpRequest.newBuilder(URI.create(lichessUri + "/api/token"))
                        .POST(BodyPublishers.ofString(tokenParamsString))
                        .header("content-type", "application/x-www-form-urlencoded")
                        .build();

                    try {
                        var response = httpClient.send(tokenRequest, BodyHandlers.ofString());
                        var statusCode = response.statusCode();
                        var body = response.body();

                        System.out.println("/api/token - " + statusCode);
                        var access_token = parseField("access_token", body);

                        if (access_token == null) {
                            System.out.println("Body: " + body);
                            cf.completeExceptionally(new Exception("Authorization Failed"));
                            return;
                        }

                        // Ok, we have successfully retrieved a token which we can use
                        // to fetch the e-mail address
                        cf.complete(access_token);

                    } catch (Exception e) {
                        e.printStackTrace();
                    }
        });
        httpServer.start();
        return cf;
    }

    // Light-weight fragile "json" ""parser""...
    static String parseField(String field, String body) {
        try {
            int start = body.indexOf(field) + field.length() + 3;
            int stop = body.indexOf("\"", start);
            var field_value = body.substring(start, stop);
            return field_value;
        } catch (Exception e){
            return null;
        }
    }

}
