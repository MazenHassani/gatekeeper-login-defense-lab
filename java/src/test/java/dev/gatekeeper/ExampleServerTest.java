package dev.gatekeeper;

import static org.junit.jupiter.api.Assertions.*;
import dev.gatekeeper.example.ExampleServer;
import java.net.*;
import java.net.http.*;
import java.nio.file.Path;
import java.time.Duration;
import org.junit.jupiter.api.*;

class ExampleServerTest {
    ExampleServer app;
    HttpClient client;
    @BeforeEach void start() throws Exception {
        app=new ExampleServer(0,Path.of("example"));app.start();
        client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    }
    @AfterEach void stop(){client.close();app.close();}
    HttpResponse<String> login(String user,String password,String origin,String xff)throws Exception{
        var builder=HttpRequest.newBuilder(URI.create(app.origin()+"/login")).timeout(Duration.ofSeconds(5))
            .header("Origin",origin).header("Content-Type","application/x-www-form-urlencoded");
        if(xff!=null)builder.header("X-Forwarded-For",xff);
        return client.send(builder.POST(HttpRequest.BodyPublishers.ofString("username="+user+"&password="+password)).build(),HttpResponse.BodyHandlers.ofString());
    }
    String metrics()throws Exception{return client.send(HttpRequest.newBuilder(URI.create(app.origin()+"/api/metrics")).build(),HttpResponse.BodyHandlers.ofString()).body();}
    @Test void applicationVerifiesAndDoesNotCreateSession()throws Exception{
        var response=login("demo","local-example-only",app.origin(),null);
        assertEquals(200,response.statusCode());assertEquals("{\"authenticated\":true}",response.body());
        assertTrue(response.headers().firstValue("Set-Cookie").isEmpty());
        assertTrue(metrics().contains("\"successes\":1"));
    }
    @Test void unknownAccountAndWrongPasswordHaveSameGenericResponse()throws Exception{
        var wrong=login("demo","wrong",app.origin(),null);var unknown=login("unknown","wrong",app.origin(),null);
        assertEquals(401,wrong.statusCode());assertEquals(wrong.statusCode(),unknown.statusCode());assertEquals(wrong.body(),unknown.body());
    }
    @Test void forgedForwardingDoesNotBypassAndCorrectPasswordCanBeLimited()throws Exception{
        for(int i=0;i<3;i++)assertEquals(401,login("demo","wrong",app.origin(),"198.51.100."+i).statusCode());
        var limited=login("demo","local-example-only",app.origin(),"203.0.113.42");
        assertEquals(429,limited.statusCode());assertTrue(metrics().contains("\"admitted\":3"));
        assertTrue(metrics().contains("\"failures\":3"));
    }
    @Test void crossOriginAndOversizedBodiesRejectedBeforeGate()throws Exception{
        assertEquals(403,login("demo","local-example-only","https://untrusted.invalid",null).statusCode());
        assertEquals(413,login("demo","x".repeat(513),app.origin(),null).statusCode());
        assertTrue(metrics().contains("\"evaluated\":0"));
    }
    @Test void uiAssetsAndMetricsAvailable()throws Exception{
        for(String path:new String[]{"/","/app.js","/style.css","/metrics"}){
            var response=client.send(HttpRequest.newBuilder(URI.create(app.origin()+path)).build(),HttpResponse.BodyHandlers.ofString());
            assertEquals(200,response.statusCode());assertFalse(response.body().isEmpty());
            assertTrue(response.headers().firstValue("Content-Security-Policy").isPresent());
        }
    }
}
