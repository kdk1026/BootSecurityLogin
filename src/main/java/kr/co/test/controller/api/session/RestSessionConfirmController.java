package kr.co.test.controller.api.session;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import common.LogDeclare;
import common.util.map.ParamMap;
import kr.co.test.config.mvc.resolver.ParamCollector;
import kr.co.test.service.session.RestSessionConfirmService;

/**
 * <pre>
 * 개정이력
 * -----------------------------------
 * 2019. 4. 8. 김대광	최초작성
 * </pre>
 * 
 * @author 김대광
 */
@RestController
@RequestMapping("api/session")
public class RestSessionConfirmController extends LogDeclare {
	
	@Autowired
	private RestSessionConfirmService restSessionConfirmService;

	@PostMapping("/confirm")
	public ParamMap confirm(ParamCollector paramCollector) {
		return restSessionConfirmService.processConfirm(paramCollector);
	}
	
}
