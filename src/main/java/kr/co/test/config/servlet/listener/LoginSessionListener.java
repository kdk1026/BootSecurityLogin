package kr.co.test.config.servlet.listener;

import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

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
public class LoginSessionListener implements HttpSessionListener {

	@Override
	public void sessionCreated(HttpSessionEvent event) {
		event.getSession().setMaxInactiveInterval(5*60);
	}

	@Override
	public void sessionDestroyed(HttpSessionEvent event) {
		//
	}
	
}
