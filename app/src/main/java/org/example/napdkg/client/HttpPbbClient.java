// src/main/java/org/example/pvss/HttpPbbClient.java
package org.example.napdkg.client;

import java.io.IOException;
import java.lang.reflect.Type;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

public class HttpPbbClient implements PbbClient {

    private final HttpClient client = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1).build();
    private final URI base;
    private final Gson gson = new Gson();

    public HttpPbbClient(String baseUrl) {
        this.base = URI.create(baseUrl.endsWith("/") ? baseUrl : baseUrl + "/");
    }

    @Override
    public void publishAll(String topic, Object[] msgs) throws Exception {
        for (Object m : msgs)
            publish(topic, m);
    }

    @Override
    public void publish(String topic, Object bean) throws IOException, InterruptedException {
        String body = gson.toJson(bean);
        URI uri = base.resolve(topic);
        HttpRequest req = HttpRequest.newBuilder(uri)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() >= 400) {
            throw new IOException("publish “" + topic + "” failed: "
                    + resp.statusCode() + " / " + resp.body());
        }
    }

    @Override
    public <T> List<T> fetch(String topic, Class<T> clazz)
            throws IOException, InterruptedException {
        URI uri = base.resolve(topic);
        HttpRequest req = HttpRequest.newBuilder(uri).GET().build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() >= 400) {
            throw new IOException("fetch “" + topic + "” failed: "
                    + resp.statusCode() + " / " + resp.body());
        }
        Type listType = TypeToken.getParameterized(List.class, clazz).getType();
        return gson.fromJson(resp.body(), listType);
    }

    @Override
    public void delete(String topic, String id) throws IOException, InterruptedException {
        URI uri = base.resolve(topic + "/" + id);
        // log.info("[HTTP DELETE] DELETE " + uri);
        HttpRequest req = HttpRequest.newBuilder(uri)
                .DELETE()
                .build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        // log.info("[HTTP DELETE] RESP code = " + resp.statusCode());
        // log.info("[HTTP DELETE] RESP body = " + resp.body());
        if (resp.statusCode() >= 400) {
            throw new IOException("delete \"" + topic + "/" + id
                    + "\" failed: " + resp.statusCode() + " / " + resp.body());
        }
    }

}
