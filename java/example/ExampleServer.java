package dev.gatekeeper.example;

import com.sun.net.httpserver.*;
import dev.gatekeeper.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/** Loopback-only example application. Gatekeeper never receives a password. */
public final class ExampleServer implements AutoCloseable {
    private final HttpServer server;
    private final ExecutorService executor=new ThreadPoolExecutor(8,8,0,TimeUnit.MILLISECONDS,new ArrayBlockingQueue<>(16),new ThreadPoolExecutor.AbortPolicy());
    private final Gatekeeper gate;
    private final Path assets;
    private final String origin;
    private static final byte[] SALT="example-only-fixed-salt".getBytes(StandardCharsets.UTF_8);
    private static final byte[] HASH=hash("local-example-only".toCharArray());
    public ExampleServer(int port,Path assets) throws IOException {
        this.assets=assets;
        gate=new Gatekeeper(new Policy(20,3,Duration.ofSeconds(60),2,Policy.Mode.ENFORCE),new BoundedMemoryStore(1000));
        server=HttpServer.create(new InetSocketAddress(InetAddress.getByName("127.0.0.1"),port),16);
        origin="http://127.0.0.1:"+server.getAddress().getPort();
        server.setExecutor(executor);server.createContext("/",this::handle);
    }
    public void start(){server.start();}
    public String origin(){return origin;}
    @Override public void close(){server.stop(0);executor.shutdownNow();}
    private void handle(HttpExchange request) throws IOException {
        try(request){
            String host=origin.substring("http://".length());
            if(!host.equals(request.getRequestHeaders().getFirst("Host"))){send(request,403,"application/json","{\"error\":\"Unavailable\"}");return;}
            String path=request.getRequestURI().getPath();
            if(request.getRequestMethod().equals("GET")){
                if(path.equals("/api/metrics")){send(request,200,"application/json",metricsJson());return;}
                if(path.equals("/metrics")){send(request,200,"text/plain; version=0.0.4",prometheus());return;}
                String file=switch(path){case "/"->"index.html";case "/app.js"->"app.js";case "/style.css"->"style.css";default->null;};
                if(file!=null){send(request,200,file.endsWith("html")?"text/html":file.endsWith("js")?"text/javascript":"text/css",Files.readString(assets.resolve(file)));return;}
            }
            if(!path.equals("/login")||!request.getRequestMethod().equals("POST")){send(request,404,"application/json","{}");return;}
            if(!origin.equals(request.getRequestHeaders().getFirst("Origin"))){send(request,403,"application/json","{\"error\":\"Unavailable\"}");return;}
            byte[] bytes=request.getRequestBody().readNBytes(513);
            if(bytes.length>512){send(request,413,"application/json","{\"error\":\"Unavailable\"}");return;}
            Map<String,String> form=new HashMap<>();
            try{
                for(String part:new String(bytes,StandardCharsets.UTF_8).split("&")){
                    String[] pair=part.split("=",2);
                    if(pair.length!=2)throw new IllegalArgumentException();
                    String key=URLDecoder.decode(pair[0],StandardCharsets.UTF_8);
                    if(!Set.of("username","password").contains(key)||form.containsKey(key))throw new IllegalArgumentException();
                    form.put(key,URLDecoder.decode(pair[1],StandardCharsets.UTF_8));
                }
            }catch(IllegalArgumentException e){send(request,400,"application/json","{\"error\":\"Unavailable\"}");return;}
            String account=form.getOrDefault("username","").strip().toLowerCase(Locale.ROOT);
            String password=form.getOrDefault("password","");
            if(account.length()>64||password.length()>128){send(request,400,"application/json","{\"error\":\"Unavailable\"}");return;}
            // No trusted proxies here. XFF and client-supplied fingerprint/device fields are ignored/rejected.
            InetAddress source=ClientAddress.resolve(request.getRemoteAddress().getAddress(),
                request.getRequestHeaders().getFirst("X-Forwarded-For"),Set.of());
            try(var attempt=gate.admit(source,account)){
                if(!attempt.allowed()){
                    request.getResponseHeaders().set("Retry-After","60");
                    send(request,429,"application/json","{\"error\":\"Authentication temporarily unavailable\"}");return;
                }
                char[] chars=password.toCharArray();
                boolean valid;
                try{
                    // Always do the same dummy verification for unknown users. Demo user only, no database.
                    byte[] candidate=hash(chars);
                    valid=MessageDigest.isEqual(HASH,candidate)&&account.equals("demo");
                    Arrays.fill(candidate,(byte)0);
                }finally{Arrays.fill(chars,'\0');}
                attempt.complete(valid?Gatekeeper.Outcome.SUCCESS:Gatekeeper.Outcome.INVALID_CREDENTIALS);
                send(request,valid?200:401,"application/json",valid?"{\"authenticated\":true}":"{\"error\":\"Authentication failed\"}");
            }
        }catch(RuntimeException e){/* Example does not log bodies, passwords or identities. */}
    }
    private static byte[] hash(char[] password){
        PBEKeySpec spec=new PBEKeySpec(password,SALT,210_000,256);
        try{return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();}
        catch(GeneralSecurityException e){throw new IllegalStateException(e);}finally{spec.clearPassword();}
    }
    private String metricsJson(){
        var m=gate.metrics();
        return "{\"evaluated\":"+m.evaluated()+",\"admitted\":"+m.admitted()+",\"denied\":"+m.denied()
            +",\"successes\":"+m.successes()+",\"failures\":"+m.credentialFailures()+",\"busy\":"+m.busy()
            +",\"inFlight\":"+m.inFlight()+",\"storeErrors\":"+m.storeErrors()+"}";
    }
    private String prometheus(){
        var m=gate.metrics();
        return "# TYPE gatekeeper_evaluated_total counter\ngatekeeper_evaluated_total "+m.evaluated()
            +"\n# TYPE gatekeeper_admitted_total counter\ngatekeeper_admitted_total "+m.admitted()
            +"\n# TYPE gatekeeper_policy_denied_total counter\ngatekeeper_policy_denied_total "+m.policyDenied()
            +"\n# TYPE gatekeeper_store_errors_total counter\ngatekeeper_store_errors_total "+m.storeErrors()
            +"\n# TYPE gatekeeper_busy_total counter\ngatekeeper_busy_total "+m.busy()
            +"\n# TYPE gatekeeper_in_flight gauge\ngatekeeper_in_flight "+m.inFlight()+"\n";
    }
    private static void send(HttpExchange request,int status,String type,String content)throws IOException{
        byte[] bytes=content.getBytes(StandardCharsets.UTF_8);
        var h=request.getResponseHeaders();h.set("Content-Type",type+"; charset=utf-8");h.set("Cache-Control","no-store");
        h.set("X-Content-Type-Options","nosniff");h.set("Content-Security-Policy","default-src 'self'; frame-ancestors 'none'");
        request.sendResponseHeaders(status,bytes.length);request.getResponseBody().write(bytes);
    }
    public static void main(String[] args)throws Exception{
        var app=new ExampleServer(8766,Path.of(args.length==0?"example":args[0]));
        Runtime.getRuntime().addShutdownHook(new Thread(app::close));app.start();
        System.out.println("Gatekeeper Java example: "+app.origin());
    }
}
