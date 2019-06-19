package kr.co.test.common;

import javax.servlet.http.HttpServletRequest;

import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

/**
 * <pre>
 * 개정이력
 * -----------------------------------
 * 2019. 4. 7. 김대광	최초작성
 * </pre>
 * 
 *
 * @since Spring 4.2
 * @author 김대광
 */
public class RestCorsConfig {

	public static CorsConfigurationSource configurationSource() {
		return new CorsConfigurationSource() {

			@Override
			public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
				CorsConfiguration cors = new CorsConfiguration();
				cors.addAllowedOrigin("*");
				cors.addAllowedMethod("POST, GET");
				cors.setMaxAge(3600L);
				cors.addAllowedHeader("Content-Type, Accept, x-requested-with, Authorization");
				return cors;
			}
		};
	}
	
}
