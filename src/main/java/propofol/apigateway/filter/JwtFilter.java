package propofol.apigateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.Key;

@Component
@Slf4j
public class JwtFilter extends AbstractGatewayFilterFactory<JwtFilter.Config> {

    Environment env;
    private Key key;

    public JwtFilter(Environment env) {
        super(Config.class);
        this.env = env;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            HttpHeaders headers = request.getHeaders();
            if(!headers.containsKey(HttpHeaders.AUTHORIZATION)){
                return onError(exchange, "No Jwt Token", HttpStatus.UNAUTHORIZED);
            }

            String authorization = headers.get(HttpHeaders.AUTHORIZATION).get(0);
            String token = authorization.replace("Bearer ", "");

            if(!isValid(token, exchange)){
                return onError(exchange, "Not Validate Jwt Token", HttpStatus.UNAUTHORIZED);
            }

            return chain.filter(exchange);
        });
    }

    private boolean isValid(String token, ServerWebExchange exchange) {
        String subject = null;

        String secretKey = env.getProperty("token.secret");
        byte[] bytes = secretKey.getBytes(StandardCharsets.UTF_8);
        key = Keys.hmacShaKeyFor(bytes);

        JwtParser jwtParser = Jwts.parserBuilder().setSigningKey(key).build();
        Claims claims = jwtParser.parseClaimsJws(token).getBody();
        subject = claims.getSubject();

        if(subject == null) return false;

        return true;
    }

    private Mono<Void> onError(ServerWebExchange exchange, String errorMessage, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        try {
            byte[] bytes = errorMessage.getBytes(StandardCharsets.UTF_8);
            response.setStatusCode(httpStatus);
            DataBuffer dataBuffer = response.bufferFactory().wrap(bytes);
            return response.writeWith(Flux.just(dataBuffer));
        }catch (Exception e){
            response.setStatusCode(httpStatus);
            return response.setComplete();
        }
    }

    static class Config{
    }
}
