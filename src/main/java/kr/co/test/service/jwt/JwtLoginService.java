package kr.co.test.service.jwt;

import java.util.Properties;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;

import common.ResponseCodeEnum;
import common.util.sessioncookie.CookieUtilVer2;
import kr.co.test.common.Constants;
import kr.co.test.common.mvc.service.CommonService;
import kr.co.test.common.security.web.model.AuthenticatedUser;
import kr.co.test.common.security.web.service.UserService;
import kr.co.test.config.mvc.resolver.ParamCollector;
import kr.co.test.model.ResultVo;

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
@Service
public class JwtLoginService extends CommonService {

	@Value("#{common}")
	private Properties commProp;

	@Autowired
	private UserService userService;

	@Autowired
	private JwtTokenProvider jwtTokenProvider;

	/**
	 * <pre>
	 * JWT 로그인 처리
	 *  - Web 전용
	 *  - 쿠키 기반
	 *    : Web의 경우, 서버에서 forwad 및 redirect 시키므로 단독 JWT 사용 못함
	 * </pre>
	 * @param paramCollector
	 * @param response
	 * @return
	 * @throws Exception
	 */
	public ResultVo processLogin(ParamCollector paramCollector, HttpServletResponse response) throws Exception {
		ResultVo resultVo = new ResultVo();

		resultVo.setRes_cd(ResponseCodeEnum.LOGIN_INVALID.getCode());
		resultVo.setRes_msg(ResponseCodeEnum.LOGIN_INVALID.getMessage());

		//--------------------------------------------------
		// 아이디로 계정 정보 조회
		//--------------------------------------------------
		String username = paramCollector.getString(Constants.Auth.USERNAME);

		AuthenticatedUser user = (AuthenticatedUser) userService.loadUserByUsername(username);

		//--------------------------------------------------
		// 계정 유무 확인
		//--------------------------------------------------
		if ( user == null ) {
			return resultVo;
		}

		/*
		 * 로그인 프로세스 추가 고려 사항
		 *  - 비밀번호 N회 오류, 일정기간 미사용에 의한 계정 잠금 및 안내
		 *  - 비밀번호 변경 주기 경과 안내
		 *    > 관리자 사이트는 해당 없으나, 일반적으로 권고 규칙에 의거해 최소 6개월, 규칙보다 짧은 3개월 등은 해당 없음
		 *    > 사고/신고에 의한 점검 등으로 위반에 해당 시, 과태료
		 */

		//--------------------------------------------------
		// 비밀번호 일치 여부 확인
		//--------------------------------------------------
		if ( !BCrypt.checkpw(paramCollector.getString(Constants.Auth.PASWORD), user.getPw()) ) {
			return resultVo;
		}

		String sAutoLogin = "N";
		if ( paramCollector.containsKey("login_chk") && "on".equals(paramCollector.getString("login_chk")) ) {
			sAutoLogin = "Y";
		}

		//--------------------------------------------------
		// JWT 토큰 생성
		//--------------------------------------------------
		String sAccessToken = jwtTokenProvider.generateAccessToken(user, "");

		String sSessionExpireSecond = commProp.getProperty("session.expire.second");

		//--------------------------------------------------
		// 자동 로그인 선택 시, 만료기간 7일 설정
		//--------------------------------------------------
		if ( "Y".equals(sAutoLogin) ) {
			sSessionExpireSecond = commProp.getProperty("auto.login.cookie.expire.second");
		}

		int nExpireSecond = Integer.parseInt(sSessionExpireSecond);

		//--------------------------------------------------
		// JWT 토큰 쿠키 생성
		//--------------------------------------------------
		CookieUtilVer2.addCookie(response, Constants.Jwt.ACCESS_TOKEN, sAccessToken, nExpireSecond, false, false, "");

		resultVo.setRes_cd(ResponseCodeEnum.SUCCESS.getCode());
		resultVo.setRes_msg(ResponseCodeEnum.SUCCESS.getMessage());

		return resultVo;
	}

	/**
	 * <pre>
	 * JWT 로그아웃 처리
	 *  - Web 전용
	 *  - 쿠키 기반이므로 쿠키만 제거
	 * </pre>
	 * @param response
	 */
	public void processLogout(HttpServletResponse response) {
		CookieUtilVer2.removeCookie(response, Constants.Jwt.ACCESS_TOKEN);
	}

	/**
	 * 자동 로그아웃 처리를 위한 만료시간 가져오기
	 * @return
	 */
	public int getSessionExpireSecond() {
		int nExpireSecond = 0;

		try {
			String sSessionExpireSecond = commProp.getProperty("session.expire.second");
			nExpireSecond = Integer.parseInt(sSessionExpireSecond);

		} catch (Exception e) {
			logger.error("", e);
		}

		return nExpireSecond;
	}

	/**
	 * <pre>
	 * Spring 4 이후부터는 Security logout도 post만 가능
	 * Thymeleaf 에서 변수 생성 후, 전달 방법 모르므로...
	 * </pre>
	 * @return
	 */
	public String getLogoutUri() {
		return "/jwt/logout";
	}

}
