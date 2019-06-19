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
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import kr.co.test.common.RestCorsConfig;
import kr.co.test.common.security.UserAuthenticationProvider;
import kr.co.test.common.security.entryPoint.RestUserAuthenticationEntryPoint;
import kr.co.test.common.security.handler.LoginFailureHandler;
import kr.co.test.common.security.handler.RestAccessDeniedHandler;
import kr.co.test.common.security.handler.RestSessionLoginFaiureHandler;
import kr.co.test.common.security.handler.RestSessionLoginSuccessHandler;

/**
 * <pre>
 * 개정이력
 * -----------------------------------
 * 2019. 3. 31. 김대광	최초작성
 * </pre>
 * 
 * <pre>
 * Spring 설정은 Scan 패키지 외에 있어도 동작하나 Security는 아님...
 * DataSource Bean 이름도 가져오기 못하므로 Scan 패키지에서 처리
 * </pre>
 * @author 김대광
 */
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SessionSecurityConfig {

	private static final String LOGIN_PAGE = "/session/login";
	private static final String LOGIN_URI = LOGIN_PAGE + "/auth";
	private static final String LOGIN_API_URI = "/api/session/login/auth";
	
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
	
	@Order(1)
	@Configuration
	public static class FormLoginWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
		
		public FormLoginWebSecurityConfigurerAdapter() {
			super();
		}

		@Autowired @Qualifier("accountDataScource")
        private DataSource accountDataScource;
		
		@Override
		public void configure(WebSecurity web) throws Exception {
			web.ignoring()
				.antMatchers("/mdb/**", "/js/**", "/webjars/**", "/console/**");
		}
		
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.authorizeRequests()
				.antMatchers("/**", LOGIN_PAGE).permitAll();
			
			http.antMatcher("/session/**")
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
				.csrf()
				
				.and()
				.formLogin()
				.loginPage(LOGIN_PAGE)
				.loginProcessingUrl(LOGIN_URI)
				.defaultSuccessUrl("/session/main")
				.usernameParameter("id").passwordParameter("pw")
				.failureHandler(new LoginFailureHandler("/session/login?error"))
				
				.and()
				.logout()
				.logoutUrl("/session/logout")
				.logoutSuccessUrl(LOGIN_PAGE)			
			
				.and()
				.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.NEVER)
				.invalidSessionUrl(LOGIN_PAGE+"?invalid")
				.sessionFixation().none()
				.maximumSessions(1)
					.maxSessionsPreventsLogin(true);
			
			http.rememberMe()
				.rememberMeParameter("remember-me")
				.key("steady")
				.tokenValiditySeconds(24*60*60)	// 86400
				.tokenRepository( this.persistentTokenRepository() );
		}
		
		@Bean
		public PersistentTokenRepository persistentTokenRepository() {
			JdbcTokenRepositoryImpl db = new JdbcTokenRepositoryImpl();
			db.setDataSource(accountDataScource);
			return db;
		}
		
	}
	
	@Order(2)
	@Configuration
	public static class ApiWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {
		
		public ApiWebSecurityConfigurationAdapter() {
			super();
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.authorizeRequests()
				.antMatchers(LOGIN_API_URI).permitAll();
			
			http.antMatcher("/api/session/**")
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
				
				.formLogin()
				.loginProcessingUrl(LOGIN_API_URI)
				.usernameParameter("id").passwordParameter("pw")
				.successHandler(new RestSessionLoginSuccessHandler())
				.failureHandler(new RestSessionLoginFaiureHandler())
				
				.and()
				.logout()
				.logoutUrl("/api/session/logout")
			
				.and()
				.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
				.sessionFixation().none()
				
				.and()
				.exceptionHandling()
				.authenticationEntryPoint(new RestUserAuthenticationEntryPoint())
				.accessDeniedHandler(new RestAccessDeniedHandler())
			
				.and()
				.cors().configurationSource(RestCorsConfig.configurationSource());
		}
		
	}
	
}
