package com.security.springsecdemo.jwt;

import static org.springframework.security.config.Customizer.withDefaults;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class JwtSecurityConfiguration {

	// Use the following to allow CORS calls from specified domains globally
	// use @CrossOrigin on every end-poits for fine grained control
	@Bean
	public WebMvcConfigurer corsConfigurer() {
		return new WebMvcConfigurer() {

			public void addCorsMappings(CorsRegistry registry) {
				registry.addMapping("/**").allowedMethods("HEAD", "GET", "PUT", "POST", "DELETE", "PATCH")
						.allowedOrigins("http://localhost:3000").allowedOrigins("http://localhost:4000");
			}
		};
	}

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

		// All requests will be authenticated
		http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());

		// comment out the following for disabling form validation
		// http.formLogin(withDefaults());

		// disable sessions as we are building a pure REST app
		http.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

		// Keep the simple basic auth enabled
		http.httpBasic(withDefaults());

		// Disable CSRF
		http.csrf(csrf -> csrf.disable());

		// To allow h2-console to render its UI by talking to this app with HTML Frames
		http.headers(headers -> headers.frameOptions(frameOptionsConfig -> frameOptionsConfig.disable()));

		http.oauth2ResourceServer((oauth2) -> oauth2.jwt(withDefaults()));

		return http.build();
	}

	// Uncomment the following code if, the user data needs to be stored in DB.

//	@Bean
//	public DataSource dataSource() {
//		return new EmbeddedDatabaseBuilder().setType(EmbeddedDatabaseType.H2)
//				.addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION).build();
//	}
//
//	@Bean
//	public UserDetailsService userDetailService(DataSource dataSource) {
//
//		var user = User.withUsername("in28minutes")
//				// .password("{noop}dummy")
//				.password("dummy").passwordEncoder(str -> passwordEncoder().encode(str)).roles("USER").build();
//
//		var admin = User.withUsername("admin")
//				// .password("{noop}dummy")
//				.password("dummy").passwordEncoder(str -> passwordEncoder().encode(str)).roles("ADMIN", "USER").build();
//
//		var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
//		jdbcUserDetailsManager.createUser(user);
//		jdbcUserDetailsManager.createUser(admin);
//
//		return jdbcUserDetailsManager;
//	}

	// Use this if the Data storage is using a hashing algorithm if not the entered
	// password and
	// hashed password in DB wont match

//		@Bean
//		public BCryptPasswordEncoder passwordEncoder() {
//			return new BCryptPasswordEncoder();
//		}

	
	
	
	// Use the following to set master user/pass for retrieving JWT token

	@Bean
	public UserDetailsService userDetailService() {

		var user = User.withUsername("theuser").password("{noop}thepass")
				// .roles("ADMIN")
				.build();

		return new InMemoryUserDetailsManager(user);
	}

	@Bean
	public KeyPair keyPair() {
		try {
			var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			return keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	@Bean
	public RSAKey rsaKey(KeyPair keyPair) {

		return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic()).privateKey(keyPair.getPrivate())
				.keyID(UUID.randomUUID().toString()).build();
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
		var jwkSet = new JWKSet(rsaKey);

		return (jwkSelector, context) -> jwkSelector.select(jwkSet);

	}

	@Bean
	public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
		return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();

	}

	@Bean
	public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
		return new NimbusJwtEncoder(jwkSource);
	}
}
