package com.example;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


//-> curl -u demo:demo http://localhost:8989/uaa/oauth/token -d grant_type=password -d username=user -d password=password
//{"access_token":"2c94da27-5dc1-4fc4-b807-7ff1577c7012","token_type":"bearer","expires_in":43199,"scope":"openid"}/Users/aclement
//-> curl http://localhost:8989/uaa/userinfo -H 'Authorization: Bearer 2c94da27-5dc1-4fc4-b807-7ff1577c7012'
//{"details":{"remoteAddress":"127.0.0.1","sessionId":null,"tokenValue":"2c94da27-5dc1-4fc4-b807-7ff1577c7012","tokenType":"Bearer","decodedDetails":null},"authorities":[{"authority":"ROLE_ADMIN"},{"authority":"ROLE_USER"}],"authenticated":true,"userAuthentication":{"details":{"grant_type":"password","username":"user"},"authorities":[{"authority":"ROLE_ADMIN"},{"authority":"ROLE_USER"}],"authenticated":true,"principal":{"password":null,"username":"user","authorities":[{"authority":"ROLE_ADMIN"},{"authority":"ROLE_USER"}],"accountNonExpired":true,"accountNonLocked":true,"credentialsNonExpired":true,"enabled":true},"credentials":null,"name":"user"},"oauth2Request":{"clientId":"demo","scope":["openid"],"requestParameters":{"grant_type":"password","username":"user"},"resourceIds":[],"authorities":[{"authority":"ROLE_USER"}],"approved":true,"refresh":false,"redirectUri":null,"responseTypes":[],"extensions":{},"grantType":"password","refreshTokenRequest":null},"credentials":"","principal":{"password":null,"username":"user","authorities":[{"authority":"ROLE_ADMIN"},{"authority":"ROLE_USER"}],"accountNonExpired":true,"accountNonLocked":true,"credentialsNonExpired":true,"enabled":true},"clientOnly":false,"name":"user"}/Users/aclement

//@Configuration
//@ComponentScan
//@EnableAutoConfiguration
@RestController
//@EnableResourceServer
@SpringBootApplication
@EnableAuthorizationServer // [1]
public class SecurityServerApplication {

	@RequestMapping(path="/userinfo", method=org.springframework.web.bind.annotation.RequestMethod.GET)
	Object userinfo(Authentication authentication) {
		return authentication;
	}
	
//	private static final String RESOURCE_ID = "blog_resource";

	public static void main(String[] args) {
		SpringApplication.run(SecurityServerApplication.class, args);
	}
//}

		
@Configuration
@EnableAuthorizationServer
static class OAuth2AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
	
	@Autowired
	AuthenticationManager authenticationManager;
	
    @Override
    public void configure(final AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
    }
    
    @Override
    public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {// @formatter:off
		clients.inMemory()
			.withClient("demo").secret("demo")
			.authorizedGrantTypes("password","authorization_code","client_credentials")
			.scopes("read","p-config-server.12345.read").autoApprove(true)
			;
//				security.oauth2.client.client-id=demo
//				security.oauth2.client.client-secret=demo
//				security.oauth2.client.scope=read
//				security.oauth2.client.authorized-grant-types=password,authorization_code, client_credentials
//				security.user.name=foobar
//				security.user.password=password
//				.jdbc(dataSource())
//				.inMemory().withClient("sampleClientId").authorizedGrantTypes("implicit")
//				.scopes("read", "write", "foo", "bar").autoApprove(false).accessTokenValiditySeconds(3600)
//
//				.and().withClient("fooClientIdPassword").secret("secret")
//				.authorizedGrantTypes("password", "authorization_code", "refresh_token").scopes("foo", "read", "write")
//				.accessTokenValiditySeconds(3600) // 1 hour
//				.refreshTokenValiditySeconds(2592000) // 30 days
//
//				.and().withClient("barClientIdPassword").secret("secret")
//				.authorizedGrantTypes("password", "authorization_code", "refresh_token").scopes("bar", "read", "write")
//				.accessTokenValiditySeconds(3600) // 1 hour
//				.refreshTokenValiditySeconds(2592000) // 30 days
//		;
	} // @formatter:on
    
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.tokenStore(tokenStore())
                 .accessTokenConverter(accessTokenConverter())
                 .authenticationManager(authenticationManager);
    }
    
    @Bean
    public TokenEnhancer tokenEnhancer() {
    	return new SimpleEnhancer();
    }
    
    static class SimpleEnhancer implements TokenEnhancer {

		@Override
		public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
			accessToken.getAdditionalInformation().put("iss", "wibble");
			return accessToken;
		}
    	
    }
 
    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }
 
    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setAccessTokenConverter(new MyAccessTokenConverter());
        converter.setSigningKey("999");
        converter.setVerifierKey("999");
        return converter;
    }
    
    static class MyAccessTokenConverter extends DefaultAccessTokenConverter {
    	public Map<String, ?> convertAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
    		Map<String,Object> result = (Map<String, Object>) super.convertAccessToken(token, authentication);
    		result.put("iss", "http://localhost:8989/uaa/oauth/token");
    		return result;
    	}
   }
 
    @Bean
    @Primary
    public DefaultTokenServices tokenServices() {
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore());
        defaultTokenServices.setSupportRefreshToken(true);
        return defaultTokenServices;
    }
}

//	@Configuration
//	protected static class OAuth2Config extends AuthorizationServerConfigurerAdapter {
//
//		@Autowired
//		private AuthenticationManager authenticationManager;
//
//		@Override // [2]
//		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
//			endpoints.authenticationManager(authenticationManager);
//		}
//
//		@Override // [3]
//		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
//			// @formatter:off
//			clients.inMemory().withClient("client-with-registered-redirect").authorizedGrantTypes("authorization_code")
//					.authorities("ROLE_CLIENT").scopes("read", "trust").resourceIds(RESOURCE_ID)
//					.redirectUris("http://anywhere?key=value").secret("secret123").and()
//					.withClient("my-client-with-secret").authorizedGrantTypes("client_credentials", "password")
//					.authorities("ROLE_CLIENT").scopes("read").resourceIds(RESOURCE_ID).secret("secret");
//			// @formatter:on
//		}
//	}
}

//@Configuration
//@EnableAuthorizationServer
// class OAuth2AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
//    @Override
//    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
//        endpoints.tokenStore(tokenStore())
//                 .accessTokenConverter(accessTokenConverter())
//                 .authenticationManager(authenticationManager);
//    }
// 
//    @Bean
//    public TokenStore tokenStore() {
//        return new JwtTokenStore(accessTokenConverter());
//    }
// 
//    @Bean
//    public JwtAccessTokenConverter accessTokenConverter() {
//        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
//        converter.setSigningKey("123");
//        return converter;
//    }
// 
//    @Bean
//    @Primary
//    public DefaultTokenServices tokenServices() {
//        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
//        defaultTokenServices.setTokenStore(tokenStore());
//        defaultTokenServices.setSupportRefreshToken(true);
//        return defaultTokenServices;
//    }
//}