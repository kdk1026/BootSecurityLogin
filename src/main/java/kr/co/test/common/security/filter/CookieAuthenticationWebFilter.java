package kr.co.test.common.security.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Properties;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import common.util.crypto.AesCryptoUtil;
import common.util.json.JacksonUtil;
import common.util.properties.PropertiesUtil;
import common.util.sessioncookie.CookieUtilVer2;
import kr.co.test.common.Constants;
import kr.co.test.common.security.web.model.AuthenticatedUser;

/**
 * <pre>
 * 개정이력
 * -----------------------------------
 * 2019. 10. 23. 김대광	최초작성
 * </pre>
 *
 *
 * @author 김대광
 */
public class CookieAuthenticationWebFilter extends OncePerRequestFilter {

	private static final String LOGIN_PAGE = "/cookie/login";

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		// 1. 쿠키에서 로그인 정보 가져오기
		String sEncryptedUser = CookieUtilVer2.getCookieValue(request, Constants.Auth.LOGIN_COOKIE);

		if ( StringUtils.isEmpty(sEncryptedUser) ) {
			response.sendRedirect(LOGIN_PAGE);
			return;

		} else {
			Properties commProp = PropertiesUtil.getPropertiesClasspath("common.properties");

			String sDecryptedUser = AesCryptoUtil.aesDecrypt(commProp.getProperty("cookie.secret.key"), AesCryptoUtil.AES_CBC_PKCS5PADDING, sEncryptedUser);

			// 2. 쿠키에서 로그인 정보 추출
			LinkedHashMap<String, Object> dataMap = (LinkedHashMap<String, Object>) JacksonUtil.converterJsonStrToMap(sDecryptedUser);

			AuthenticatedUser authUser = new AuthenticatedUser();
			authUser.setId( String.valueOf(dataMap.get("id")) );
			authUser.setLast_login_dt( String.valueOf(dataMap.get("last_login_dt")) );
			authUser.setLast_pwd_upd_dt( String.valueOf(dataMap.get("last_pwd_upd_dt")) );
			authUser.setName( String.valueOf(dataMap.get("name")) );

			List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();

			@SuppressWarnings("unchecked")
			List<LinkedHashMap<String, Object>> authList = (List<LinkedHashMap<String, Object>>) dataMap.get("authorities");
			for (LinkedHashMap<String, Object> map : authList) {
				authorities.add(new SimpleGrantedAuthority( String.valueOf(map.get("authority")) ));
			}

			authUser.setAuthorities(authorities);

			UsernamePasswordAuthenticationToken authentication
				= new UsernamePasswordAuthenticationToken(authUser, null, authUser.getAuthorities());

			authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

			SecurityContextHolder.getContext().setAuthentication(authentication);
		}

		filterChain.doFilter(request, response);
	}

}
