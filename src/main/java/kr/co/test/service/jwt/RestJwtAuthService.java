package kr.co.test.service.jwt;

import java.util.Date;
import java.util.Properties;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import common.LogDeclare;
import common.ResponseCodeEnum;
import common.util.date.Jsr310DateUtil;
import common.util.map.ResultSetMap;
import kr.co.test.common.Constants;
import kr.co.test.common.security.web.model.AuthenticatedUser;
import kr.co.test.common.security.web.service.UserService;
import kr.co.test.config.mvc.resolver.ParamCollector;
import kr.co.test.service.jwt.JwtTokenProvider.JwtToken;

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
public class RestJwtAuthService extends LogDeclare {

	@Autowired
	private UserService userService;

	@Autowired
	private BCryptPasswordEncoder passwordEncoder;

	@Autowired
	private JwtTokenProvider jwtTokenProvider;

	@Value("#{common}")
	private Properties jwtProp;

	public ResultSetMap processAuthByUsername(ParamCollector paramCollector) {
		ResultSetMap resMap = new ResultSetMap();

		String sDeviceId = paramCollector.getHeardMap().getString(Constants.IsApp.DEVICE_ID_KEY);
		String username = paramCollector.getString(Constants.Auth.USERNAME);
        String password = paramCollector.getString(Constants.Auth.PASWORD);
        // XXX : 비밀번호 구간 암호화 시, 복호화 처리

		AuthenticatedUser user = null;

		try {
			user = (AuthenticatedUser) userService.loadUserByUsername(username);

			if (user == null) {
				throw new RuntimeException("계정정보 없음");
			}

        	if ( !passwordEncoder.matches(password, user.getPassword()) ) {
        		throw new BadCredentialsException("비밀번호 불일치");
        	}

        	if ( user.getLock() == 0 ) {
        		resMap.put(Constants.RES.RES_CD, ResponseCodeEnum.ACCESS_DENIED.getCode());
    			resMap.put(Constants.RES.RES_MSG, ResponseCodeEnum.ACCESS_DENIED.getMessage());
    			return resMap;
        	}

        	JwtToken jwtToken = jwtTokenProvider.generateToken(user, sDeviceId);

        	String sAccessToken = jwtToken.accessToken;
        	Date date = jwtTokenProvider.getExpirationFromJwt(sAccessToken);

    		resMap.put("token_type", jwtProp.getProperty("jwt.token.type"));
    		resMap.put("access_token", jwtToken.accessToken);
    		resMap.put("expires_in", (date.getTime() / 1000));
    		resMap.put("refresh_token", jwtToken.refreshToken);

    		resMap.put(Constants.RES.RES_CD, ResponseCodeEnum.SUCCESS.getCode());
    		resMap.put(Constants.RES.RES_MSG, ResponseCodeEnum.SUCCESS.getMessage());

		} catch (Exception e) {
			logger.error("", e);
			resMap.put(Constants.RES.RES_CD, ResponseCodeEnum.LOGIN_INVALID.getCode());
			resMap.put(Constants.RES.RES_MSG, ResponseCodeEnum.LOGIN_INVALID.getMessage());
		}

		return resMap;
	}

	public ResultSetMap processRefresh(ParamCollector paramCollector) {
		ResultSetMap resMap = new ResultSetMap();

		String sDeviceId = paramCollector.getHeardMap().getString(Constants.IsApp.DEVICE_ID_KEY);
		String sGrantType = paramCollector.getString("grant_type");
		String sRefreshToken = paramCollector.getString("refresh_token");

		// 1. 파라미터 유효성 체크
		if ( !"refresh_token".equals(sGrantType) || StringUtils.isEmpty(sRefreshToken) ) {
			resMap.put(Constants.RES.RES_CD, ResponseCodeEnum.ACCESS_TOEKN_INVALID.getCode());
			resMap.put(Constants.RES.RES_MSG, ResponseCodeEnum.ACCESS_TOEKN_INVALID.getMessage());
			return resMap;
		}

		try {
			// 2. 토큰 유효성 검증
			switch ( jwtTokenProvider.isValidateJwtToken(sRefreshToken) ) {
			case 0:
				resMap.put(Constants.RES.RES_CD, ResponseCodeEnum.ACCESS_TOEKN_INVALID.getCode());
				resMap.put(Constants.RES.RES_MSG, ResponseCodeEnum.ACCESS_TOEKN_INVALID.getMessage());
				break;
			case 2:
				resMap.put(Constants.RES.RES_CD, ResponseCodeEnum.ACCESS_TOKEN_EXPIRED.getCode());
				resMap.put(Constants.RES.RES_MSG, ResponseCodeEnum.ACCESS_TOKEN_EXPIRED.getMessage());
				break;

			default:
				break;
			}

			if ( resMap.isEmpty() ) {
				// 3. 토큰에서 로그인 정보 추출
				AuthenticatedUser user = jwtTokenProvider.getAuthUserFromJwt(sRefreshToken);

				// 4. 토큰 갱신
				// 4.1. Access 토큰 갱신
				JwtToken jwtToken = new JwtToken();
	        	jwtToken.accessToken = jwtTokenProvider.generateAccessToken(user, sDeviceId);

	        	Date date = jwtTokenProvider.getExpirationFromJwt(sRefreshToken);

				resMap.put("token_type", jwtProp.getProperty("jwt.token.type"));
				resMap.put("access_token", jwtToken.accessToken);
				resMap.put("expires_in", (date.getTime() / 1000));

				// 4.2. Refresh 토큰 갱신 조건 검증
	    		String sExpireDate = Jsr310DateUtil.Convert.getDateToString(date);
	    		int nGap = Jsr310DateUtil.GetDateInterval.intervalDays(sExpireDate);

				if (nGap >= -7 && nGap <= 0) {
					// 4.2.1. 충족 시, Refresh 토큰 갱신 응답
					jwtToken.refreshToken = jwtTokenProvider.generateRefreshToken(user, sDeviceId);
					resMap.put("refresh_token", jwtToken.refreshToken);
				} else {
					// 4.2.2. 미충족 시, 파라미터 응답
					resMap.put("refresh_token", sRefreshToken);
				}

	    		resMap.put(Constants.RES.RES_CD, ResponseCodeEnum.SUCCESS.getCode());
	    		resMap.put(Constants.RES.RES_MSG, ResponseCodeEnum.SUCCESS.getMessage());
			}

		} catch (Exception e) {
			logger.error("", e);
			resMap.put(Constants.RES.RES_CD, ResponseCodeEnum.ERROR.getCode());
			resMap.put(Constants.RES.RES_MSG, ResponseCodeEnum.ERROR.getMessage());
		}

		return resMap;
	}

}
