package com.anonymous.security.uaa.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

/**
 * @author Aiden
 * @date 2020/5/7
 * @version 1.0
 **/
@Configuration
public class TokenConfig {

//    @Bean
//    public TokenStore tokenStore() {
//        return new InMemoryTokenStore();
//    }

    private String SIGNING_KEY = "uaa123";

    /**
     * JWT令牌存储方案
     * @return
     */
    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        // 对称密钥，资源服务器使用该密钥来验证
        converter.setSigningKey(SIGNING_KEY);
        return converter;

    }

}
