package io.pathguard.backend.hostedgithub;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.springframework.stereotype.Component;

@Component
public class PublicGithubClient {
    private static final int MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER).build();
    private final ObjectMapper mapper;

    public PublicGithubClient(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public JsonNode repository(String repository) {
        return get("/repos/" + repository);
    }

    public JsonNode runs(String repository) {
        return get("/repos/" + repository + "/actions/runs?per_page=50&page=1");
    }

    private JsonNode get(String path) {
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create("https://api.github.com" + path))
                    .timeout(Duration.ofSeconds(15))
                    .header("Accept", "application/vnd.github+json")
                    .header("User-Agent", "PathGuard-Hosted-GitHub/1")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .GET().build();
            HttpResponse<InputStream> response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream stream = response.body()) {
                if (response.statusCode() != 200) {
                    throw new GithubSourceException("GITHUB_HTTP_" + response.statusCode());
                }
                byte[] bytes = stream.readNBytes(MAX_RESPONSE_BYTES + 1);
                if (bytes.length > MAX_RESPONSE_BYTES) {
                    throw new GithubSourceException("GITHUB_RESPONSE_TOO_LARGE");
                }
                return mapper.readTree(bytes);
            }
        } catch (GithubSourceException exception) {
            throw exception;
        } catch (Exception exception) {
            if (exception instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new GithubSourceException("GITHUB_UNAVAILABLE");
        }
    }

    public static class GithubSourceException extends RuntimeException {
        public GithubSourceException(String code) { super(code); }
    }
}
