package kr.co.test.config.servlet;

import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import kr.co.test.config.servlet.listener.LoginSessionListener;

/**
 * <pre>
 * 개정이력
 * -----------------------------------
 * 2019. 4. 1. 김대광	최초작성
 * </pre>
 * 
 *
 * @author 김대광
 */
@Configuration
public class WebConfig {

	@Bean
	public ServletListenerRegistrationBean<LoginSessionListener> sessionCountListener() {
	   ServletListenerRegistrationBean<LoginSessionListener> listenerRegBean = new ServletListenerRegistrationBean<>();
	   listenerRegBean.setListener(new LoginSessionListener());
	   return listenerRegBean;
	}
	
}
