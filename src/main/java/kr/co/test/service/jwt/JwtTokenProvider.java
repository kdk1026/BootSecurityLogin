package kr.co.test.service.jwt;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import common.LogDeclare;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import kr.co.test.common.security.web.model.AuthenticatedUser;

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
@Component
public class JwtTokenProvider extends LogDeclare {

	@Value("#{common}")
	private Properties jwtProp;

	public static class JwtToken {
		public String accessToken;
		public String refreshToken;
	}

	private static class JwtConstants {
		public static final String NAME = "name";
		public static final String ACCESS_TOKEN = "AccessToken";
		public static final String REFRESH_TOKEN = "RefreshToken";
		public static final String SCOPE = "scope";
	}

// ------------------------------------------------------------------------
// 토큰 생성
// ------------------------------------------------------------------------
	/**
	 * JWT 토큰 생성
	 * @param user
	 * @param deviceId
	 * @return
	 * @throws Exception
	 */
	public JwtToken generateToken(AuthenticatedUser user, String deviceId) throws Exception {
		JwtToken jwtToken = new JwtToken();
		jwtToken.accessToken = this.generateAccessToken(user, deviceId);
		jwtToken.refreshToken = this.generateRefreshToken(user, deviceId);
		return jwtToken;
	}

	/**
	 * Access 토큰 생성
	 * @param user
	 * @param deviceId
	 * @return
	 * @throws Exception
	 */
	public String generateAccessToken(AuthenticatedUser user, String deviceId) throws Exception {
		// deviceId 유무로 Web, API 판단
		String sExpireMin = "";
		if ( !StringUtils.isEmpty(deviceId) ) {
			sExpireMin = jwtProp.getProperty("jwt.access.expire.minute");
		} else {
			sExpireMin = jwtProp.getProperty("jwt.web.access.expire.hour");
		}

		JwtBuilder builder = Jwts.builder();
		builder.setId(user.getUsername())
	 		.setIssuedAt(new Date())
	 		.setSubject(JwtConstants.ACCESS_TOKEN)
	 		.setIssuer(jwtProp.getProperty("jwt.issuer"))
	 		.signWith(SignatureAlgorithm.HS256, jwtProp.getProperty("jwt.secret.key"))
	 		.setExpiration( this.getExpirationTime(sExpireMin) );

	 	builder.claim("name", user.getName());
	 	builder.claim("last_pwd_upd_dt", user.getLast_pwd_upd_dt());
	 	builder.claim("last_login_dt", user.getLast_login_dt());

		List<String> listAuthority = new ArrayList<String>();
		List<GrantedAuthority> authorities = (List<GrantedAuthority>) user.getAuthorities();
		for (GrantedAuthority auth : authorities) {
			listAuthority.add(auth.getAuthority());
		}
	 	builder.claim(JwtConstants.SCOPE, listAuthority);

	 	if ( !StringUtils.isEmpty(deviceId) ) {
	 		builder.claim("device_id", deviceId);
	 	}

	 	return builder.compact();
	}

	/**
	 * Refresh 토큰 생성
	 * @param user
	 * @param deviceId
	 * @return
	 * @throws Exception
	 */
	public String generateRefreshToken(AuthenticatedUser user, String deviceId) throws Exception {
		JwtBuilder builder = Jwts.builder();
		builder.setId(user.getUsername())
		.setIssuedAt(new Date())
		.setSubject(JwtConstants.REFRESH_TOKEN)
		.setIssuer(jwtProp.getProperty("jwt.issuer"))
		.signWith(SignatureAlgorithm.HS256, jwtProp.getProperty("jwt.secret.key"))
		.setExpiration( this.getExpirationTime(jwtProp.getProperty("jwt.refresh.expire.minute")) );

	 	builder.claim("name", user.getName());
	 	builder.claim("last_pwd_upd_dt", user.getLast_pwd_upd_dt());
	 	builder.claim("last_login_dt", user.getLast_login_dt());

		List<String> listAuthority = new ArrayList<String>();
		List<GrantedAuthority> authorities = (List<GrantedAuthority>) user.getAuthorities();
		for (GrantedAuthority auth : authorities) {
			listAuthority.add(auth.getAuthority());
		}
	 	builder.claim(JwtConstants.SCOPE, listAuthority);

	 	if ( !StringUtils.isEmpty(deviceId) ) {
	 		builder.claim("device_id", deviceId);
	 	}

		return builder.compact();
	}

	/**
	 * 만료일 계산
	 * @param sExpireIn
	 * @return
	 */
	private Date getExpirationTime(String sExpireIn) {
		int nExpireIn = Integer.parseInt(sExpireIn);
		LocalDateTime localDateTime = LocalDateTime.now().plusHours(nExpireIn);
    	return Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
    }

// ------------------------------------------------------------------------
// 토큰 가져오기
// -----------------------------------------------------------------------
	/**
	 * 헤더에서 JWT 토큰 추출
	 * @param request
	 * @return
	 */
	public String getTokenFromReqHeader(HttpServletRequest request) {
		String sToken = null;
		String sBearer = request.getHeader(jwtProp.getProperty("jwt.header"));
		if ( sBearer.startsWith(jwtProp.getProperty("jwt.token.type")) ) {
			sToken = sBearer.substring(jwtProp.getProperty("jwt.token.type").length());
		}
		return sToken;
	}

	/**
	 * JWT 토큰 유효성 검증
	 * @param token
	 * @return (0: false, 1: true, 2: expired)
	 */
	public int isValidateJwtToken(String token) {
		try {
			Jwts.parser().setSigningKey(jwtProp.getProperty("jwt.secret.key")).parseClaimsJws(token);
			return 1;

		} catch (SignatureException e) {
			logger.error("Invalid JWT signature");

		} catch (MalformedJwtException e) {
			logger.error("Invalid JWT token");

		} catch (ExpiredJwtException ex) {
			logger.error("Expired JWT token");
			return 2;

		} catch (UnsupportedJwtException ex) {
			logger.error("Unsupported JWT token");

		} catch (IllegalArgumentException ex) {
			logger.error("JWT claims string is empty.");
		}

		return 0;
	}

	/**
	 * JWT 토큰에서 만료일 가져오기
	 * @param token
	 * @return
	 * @throws Exception
	 */
	public Date getExpirationFromJwt(String token) throws Exception {
		Claims claims = Jwts.parser()
				.setSigningKey(jwtProp.getProperty("jwt.secret.key"))
				.parseClaimsJws(token)
				.getBody();

		return claims.getExpiration();
	}

// ------------------------------------------------------------------------
// 토큰에서 로그인 정보 추출
// ------------------------------------------------------------------------
	/**
	 * JWT 토큰에서 로그인 정보 가져오기
	 * @param token
	 * @return
	 */
	public AuthenticatedUser getAuthUserFromJwt(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(jwtProp.getProperty("jwt.secret.key"))
                .parseClaimsJws(token)
                .getBody();

        AuthenticatedUser user = new AuthenticatedUser();
        user.setId(claims.getId());
        user.setName(claims.get(JwtConstants.NAME).toString());
        user.setLast_pwd_upd_dt(claims.get("last_pwd_upd_dt").toString());
        user.setLast_login_dt(claims.get("last_login_dt").toString());

        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        @SuppressWarnings("unchecked")
		List<String> listAuthority = (List<String>) claims.get(JwtConstants.SCOPE);
        for (String role : listAuthority) {
        	authorities.add(new SimpleGrantedAuthority(role));
        }
        user.setAuthorities(authorities);

        return user;
	}

}
