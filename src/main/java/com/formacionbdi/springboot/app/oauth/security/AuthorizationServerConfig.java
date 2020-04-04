package com.formacionbdi.springboot.app.oauth.security;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

/*Clase del servidor de configuracion, que se encargara de todos los procesos de 
 * login por el lado de OAuth2, todo lo que tiene que ver con el token, el proceso de 
 * autenticacion, generar y validarlo; todo utilizando el authenticationManager() que 
 * se configuro en SpringSecurityConfig, con todos los usuarios, los roles que se obtienen 
 * atraves del UserDetailsService implementado con el cliente Http, con feign, mediante APIrest.*/

@RefreshScope
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
	
	@Autowired
	private Environment env;

	@Autowired
	private BCryptPasswordEncoder passwordEncoder;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private InfoAdicionalToken infoAdicionalToken;

	/*Aca se configura los permisos que van ha tenr nuestros endpoints del servidor de autorizacion
	 * de OAuth2 para generar el token y para validar el token*/
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		//tokenKeyAccess, endpoint, para generar el token, para autenticarnos con la ruta: /oauth/token
		security.tokenKeyAccess("permitAll()")
		/*permite validar el token. isAuthenticated(), metodo de spring security que nos permite saber
		 * que el cliente este autenticado*/
		.checkTokenAccess("isAuthenticated()");
		
	}

	/*aca se registran los clientes(puede ser un de Angular, otro Android, React), el standard OAuth es proporcionar mayor seguridad no
	 * solamente nos autenticamos con los usuarios de nuestro backend sino tambien con las 
	 * credenciales de la aplicacion cliente que se va comunicar con nuestro backend, podria decir
	 * que tiene doble autenticacion*/
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		/*frontendapp, representa el identificador de nuestra aplicacion, luego la contraseña*/
		//se invoca la clave frondapp
		clients.inMemory().withClient(env.getProperty("config.security.oauth.client.id"))
		.secret(passwordEncoder.encode(env.getProperty("config.security.oauth.client.secret")))
		//alcanse de la aplicacion, con respecto a escritura y lectura
		.scopes("read","write")
		/*como se va obtener el token, password cuando se requiere de usuario y contraseña,
		 * refresh_token, permite tener un token de acceso removado antes de que caduque el token actual*/
		.authorizedGrantTypes("password", "refresh_token")
		//tiempo de valides del token
		.accessTokenValiditySeconds(3600)
		.refreshTokenValiditySeconds(3600);
	}

	/*aca es donde se configura el authenticationManager y tambien tokenStorage que tiene que
	 * ser del tipo JWT, tambien el accessTokenConverter que se encarga de guardar los datos 
	 * del usuario en el token, o cualquier informacion adicional, que se le conoce como claims. 
	 * El accessTokenConverter por detras se encarga de tomar estos valores del usuario y convertirlos
	 * en el token codificados en base64*/
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {

		/*unir el accessTokenConverter, con la nueva informacion*/
		TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
		tokenEnhancerChain.setTokenEnhancers(Arrays.asList(infoAdicionalToken, accessTokenConverter()));
		
		
		endpoints.authenticationManager(authenticationManager)
		//componente que se encarga de guardar, generar el token con los datos de accessTokenConverter
		.tokenStore(tokenStore())
		.accessTokenConverter(accessTokenConverter())
		.tokenEnhancer(tokenEnhancerChain);
	}

	@Bean
	public JwtTokenStore tokenStore() {
		/*para que JwtTokenStore pueda crear el token y almacenarlo necesitamos el componente
		 * que se encarga de convertir el token accessTokenConverter()*/
		return new JwtTokenStore(accessTokenConverter());
	}

	@Bean
	public JwtAccessTokenConverter accessTokenConverter() {
		JwtAccessTokenConverter tokenConverter = new JwtAccessTokenConverter();
		/*codigo secreto para validar la firma*/
		tokenConverter.setSigningKey(env.getProperty("config.security.oauth.jwt.key"));
		
		return tokenConverter;
	}
	
	
	
}
