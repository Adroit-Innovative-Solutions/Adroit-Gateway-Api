package io.datquad.ApiGateway.filter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

@Component
public class LoginCookieFilter extends AbstractGatewayFilterFactory<LoginCookieFilter.Config> {

    private static final Logger logger = LoggerFactory.getLogger(LoginCookieFilter.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    public LoginCookieFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpResponse originalResponse = exchange.getResponse();

            // Decorate response to capture the body
            ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {
                @Override
                public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                    if (body instanceof Flux) {
                        Flux<? extends DataBuffer> fluxBody = (Flux<? extends DataBuffer>) body;

                        // Join the body content buffers
                        return DataBufferUtils.join(fluxBody)
                                .flatMap(dataBuffer -> {
                                    // Read response body as string
                                    byte[] content = new byte[dataBuffer.readableByteCount()];
                                    dataBuffer.read(content);
                                    DataBufferUtils.release(dataBuffer);
                                    String responseBody = new String(content, StandardCharsets.UTF_8);

                                    logger.debug("Login response body: {}", responseBody);

                                    try {
                                        JsonNode jsonNode = objectMapper.readTree(responseBody);

                                        // If token present in response body, set cookie
                                        if (jsonNode.has("payload") && jsonNode.get("payload").has("token")) {
                                            String token = jsonNode.get("payload").get("token").asText();
                                            logger.info("Setting HttpOnly cookie for successful login");

                                            ResponseCookie authCookie = ResponseCookie.from("authToken", token)
                                                    .httpOnly(true)
                                                    .secure(false) // Set to true in production with HTTPS
                                                    .path("/")
                                                    .maxAge(Duration.ofHours(1))
                                                    .sameSite("Lax")
                                                    .build();

                                            getHeaders().add(HttpHeaders.SET_COOKIE, authCookie.toString());
                                        }
                                    } catch (Exception e) {
                                        logger.error("Error parsing login response body: {}", e.getMessage());
                                    }

                                    // Write the original response body back to client
                                    byte[] uppedContent = responseBody.getBytes(StandardCharsets.UTF_8);
                                    getHeaders().setContentLength(uppedContent.length);
                                    return super.writeWith(Mono.just(bufferFactory().wrap(uppedContent)));
                                });
                    }
                    // if body is not Flux - just write it normally
                    return super.writeWith(body);
                }
            };

            // Continue the filter chain with the decorated response
            return chain.filter(exchange.mutate().response(decoratedResponse).build());
        };
    }

    public static class Config {
        // Configuration properties if needed
    }
}
