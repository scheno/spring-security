package com.anonymous.security.uaa.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.*;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import javax.annotation.Resource;
import java.util.Arrays;


/**
 * @author Aiden
 * @date 2020/5/9
 * @version 1.0
 * 授权服务配置
 **/
@Configuration
@EnableAuthorizationServer
public class AuthorizationServer extends AuthorizationServerConfigurerAdapter {

    /**
     * Token存储实现，默认InMemory
     */
    @Resource
    TokenStore tokenStore;

    /**
     * 客户端详情配置
     */
    @Resource
    ClientDetailsService clientDetailsService;

    @Resource
    AuthorizationCodeServices authorizationCodeServices;

    @Resource
    AuthenticationManager authenticationManager;

    @Autowired
    JwtAccessTokenConverter accessTokenConverter;

    /**
     * 令牌管理
     * @return
     */
    @Bean
    public AuthorizationServerTokenServices tokenServices() {
        DefaultTokenServices tokenServices = new DefaultTokenServices();
        tokenServices.setClientDetailsService(clientDetailsService);
        tokenServices.setSupportRefreshToken(true);
        tokenServices.setTokenStore(tokenStore);

        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(accessTokenConverter));
        tokenServices.setTokenEnhancer(tokenEnhancerChain);

        // 令牌默认有效期2小时
        tokenServices.setAccessTokenValiditySeconds(7200);
        // 刷新令牌默认有效期3天
        tokenServices.setRefreshTokenValiditySeconds(259200);
        return tokenServices;
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security
                .tokenKeyAccess("permitAll()")
                .checkTokenAccess("permitAll()")
                .allowFormAuthenticationForClients();

    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        // 使用in-memory存储客户端信息
        clients.inMemory()
                // 客户端ID
                .withClient("c1")
                // 客户端安全码
                .secret(new BCryptPasswordEncoder().encode("secret"))
                .resourceIds("res1")
                // 该客户端允许的授权类型authorization_code,password,client_credentials,implicit,refresh_token
                .authorizedGrantTypes("authorization_code", "password","client_credentials","implicit","refresh_token")
                // 允许的授权范围
                .scopes("all")
                .autoApprove(false)
                // 加上验证回调地址
                .redirectUris("http://www.baidu.com");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .authenticationManager(authenticationManager)
                .authorizationCodeServices(authorizationCodeServices)
                .tokenServices(tokenServices())
                .allowedTokenEndpointRequestMethods(HttpMethod.POST);
    }

    @Bean
    public AuthorizationCodeServices authorizationCodeServices() {
        return new InMemoryAuthorizationCodeServices();
    }
}
