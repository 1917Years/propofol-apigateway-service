package propofol.apigateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
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
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import propofol.apigateway.filter.dto.ResponseDto;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.Key;

@Slf4j
@Component
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

            HttpHeaders headers = request.getHeaders();
            if(!headers.containsKey(HttpHeaders.AUTHORIZATION)){
                return onError(exchange, "No Jwt Token", HttpStatus.UNAUTHORIZED);
            }

            String authorization = headers.get(HttpHeaders.AUTHORIZATION).get(0);
            String token = authorization.replace("Bearer ", "");

            String message = isValid(token, headers);
            if(StringUtils.hasText(message)){
                return onError(exchange, message, HttpStatus.BAD_REQUEST);
            }

            return chain.filter(exchange);
        });
    }

    private String isValid(String token, HttpHeaders headers) {
        String secretKey = env.getProperty("token.secret");
        byte[] bytes = secretKey.getBytes(StandardCharsets.UTF_8);
        key = Keys.hmacShaKeyFor(bytes);

        JwtParser jwtParser = Jwts.parserBuilder().setSigningKey(key).build();

        String subject = null;

        // 토큰 유효 기간 확인
        try{
            Claims claims = jwtParser.parseClaimsJws(token).getBody();
            subject = claims.getSubject();
        }catch (Exception e){
            if(e instanceof ExpiredJwtException){
                return "Please RefreshToken.";
            }
        }

        if(!StringUtils.hasText(subject)) return "Not Validate Jwt Token";

        return null;
    }

    private Mono<Void> onError(ServerWebExchange exchange, String errorMessage, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        try {
            response.setStatusCode(httpStatus);
            response.getHeaders().set("Content-Type", MediaType.APPLICATION_JSON_VALUE);
            ResponseDto<String> responseDto =
                    new ResponseDto<>(httpStatus.value(), "fail", "api-gateway 오류", errorMessage);
            ObjectMapper objectMapper = new ObjectMapper();
            byte[] bytes = objectMapper.writeValueAsBytes(responseDto);
            DataBuffer dataBuffer = response.bufferFactory().wrap(bytes);
            return response.writeWith(Flux.just(dataBuffer));
        }catch (Exception e){
            response.setStatusCode(httpStatus);
            return response.setComplete();
        }
    }

    public static class Config{
    }
}
