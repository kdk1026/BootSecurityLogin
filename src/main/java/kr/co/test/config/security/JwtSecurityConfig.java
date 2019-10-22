package kr.co.test.config.security;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import kr.co.test.common.RestCorsConfig;
import kr.co.test.common.security.UserAuthenticationProvider;
import kr.co.test.common.security.entryPoint.RestUserAuthenticationEntryPoint;
import kr.co.test.common.security.filter.JwtAuthenticationApiFilter;
import kr.co.test.common.security.filter.JwtAuthenticationWebFilter;
import kr.co.test.common.security.handler.RestAccessDeniedHandler;
import kr.co.test.service.jwt.JwtTokenProvider;

/**
 * <pre>
 * 개정이력
 * -----------------------------------
 * 2019. 10. 22. 김대광	최초작성
 * </pre>
 *
 *
 * @author 김대광
 */
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class JwtSecurityConfig {

	private static final String LOGIN_PAGE = "/jwt/login";
	private static final String LOGIN_URI = LOGIN_PAGE + "/auth";
	private static final String LOGIN_API_URI = "/api/jwt/login/auth";
	private static final String REFRESH_TOKEN_URI = "/api/jwt/refresh";

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Autowired
	private UserAuthenticationProvider userAuthenticationProvider;

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider( this.userAuthenticationProvider );
	}

	// TODO : 미구현
	@Order(3)
	@Configuration
	public static class FormLoginWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

		public FormLoginWebSecurityConfigurerAdapter() {
			super();
		}

		@Autowired @Qualifier("accountDataScource")
        private DataSource accountDataScource;

		@Autowired
		private JwtTokenProvider jwtTokenProvider;

		@Override
		public void configure(WebSecurity web) throws Exception {
			web.ignoring()
				.antMatchers("/mdb/**", "/js/**", "/webjars/**", "/console/**", LOGIN_PAGE, LOGIN_URI);
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.antMatcher("/jwt/**")
				.authorizeRequests()
				.anyRequest().authenticated()

				.and()
				.headers()
				.cacheControl()
				.and()
				.contentTypeOptions()
				.and()
				.httpStrictTransportSecurity()
					.includeSubDomains(true)
					.maxAgeInSeconds(31536000)
				.and()
				.frameOptions().sameOrigin()
				.xssProtection().block(false)

				.and().and()
				.csrf().disable()

				.formLogin().disable()
				.logout().disable()

				.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS);

			JwtAuthenticationWebFilter jwtAuthFilter = new JwtAuthenticationWebFilter(jwtTokenProvider);

			http.addFilterBefore( jwtAuthFilter, UsernamePasswordAuthenticationFilter.class );
		}

		@Bean
		public PersistentTokenRepository persistentTokenRepository() {
			JdbcTokenRepositoryImpl db = new JdbcTokenRepositoryImpl();
			db.setDataSource(accountDataScource);
			return db;
		}

	}

	@Order(4)
	@Configuration
	public static class ApiWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

		public ApiWebSecurityConfigurationAdapter() {
			super();
		}

		@Autowired
		private JwtTokenProvider jwtTokenProvider;

		@Override
		public void configure(WebSecurity web) throws Exception {
			web.ignoring()
				.antMatchers(LOGIN_API_URI, REFRESH_TOKEN_URI);
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.antMatcher("/api/jwt/**")
				.authorizeRequests()
				.anyRequest().authenticated()

				.and()
				.headers()
				.cacheControl()
				.and()
				.contentTypeOptions()
				.and()
				.httpStrictTransportSecurity()
					.includeSubDomains(true)
					.maxAgeInSeconds(31536000)
				.and()
				.frameOptions().deny()
				.xssProtection().block(false)

				.and().and()
				.csrf().disable()

				.formLogin().disable()

				.logout()
				.logoutUrl("/api/jwt/logout")

				.and()
				.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)

				.and()
				.exceptionHandling()
				.authenticationEntryPoint(new RestUserAuthenticationEntryPoint())
				.accessDeniedHandler(new RestAccessDeniedHandler())

				.and()
				.cors().configurationSource(RestCorsConfig.configurationSource());

				JwtAuthenticationApiFilter jwtAuthFilter = new JwtAuthenticationApiFilter(jwtTokenProvider);

				http.addFilterBefore( jwtAuthFilter, UsernamePasswordAuthenticationFilter.class );
		}

	}

}
