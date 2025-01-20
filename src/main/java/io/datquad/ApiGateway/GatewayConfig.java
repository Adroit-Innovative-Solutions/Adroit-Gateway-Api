package io.datquad.ApiGateway;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

@Configuration
public class GatewayConfig {

    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration config = new CorsConfiguration();

        
       config.addAllowedOrigin("http://192.168.0.140:3000");


        // Allow all methods (GET, POST, etc.)
        config.addAllowedMethod("*");

        // Allow all headers
        config.addAllowedHeader("*");

        // Enable credentials (cookies, etc.)
        config.setAllowCredentials(true);

        // Map this configuration to all endpoints
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return new CorsWebFilter(source);
    }
}
