package org.sid.secservice.filters;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.sid.secservice.JWTUtil;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JwtAuthentificationFilter extends UsernamePasswordAuthenticationFilter{
	

	/**
	 * cette class contient deux méthodes
	 * 1- attemptAuthentification : elle est utiliser au moment ou un user saisi username an pwd par 
	 * la suite je vais les récuperer 
	 * elle retourne un objet de type Authentification il contient le usernae et pwd saisi par le user
	 * 2- successAuthentification : si l'autentification passe càd c reussi si à ce moment qu'on va utiliser une library 
	 * pour generer les tokens
	 */
	
	private AuthenticationManager authenticationManager;
	
	
	public JwtAuthentificationFilter(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("attemptAuthentication");
		String username=request.getParameter("username");
		String password=request.getParameter("password");
		System.out.println(username);
		System.out.println(password);
		UsernamePasswordAuthenticationToken authenticationToken=new UsernamePasswordAuthenticationToken(username, password);
		
		//maintenant je vais dire lancé moi le process d'authentification
		return authenticationManager.authenticate(authenticationToken);	
	}
	
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {

		System.out.println("successfulAuthentication");
		User user=(User) authResult.getPrincipal();
		Algorithm algorithm = Algorithm.HMAC256(JWTUtil.SECRET);
		String jwtAccesToken=JWT.create()
				.withSubject(user.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis()+JWTUtil.EXPIRE_ACCESS_TOKEN))
				.withIssuer(request.getRequestURL().toString())
				.withClaim("roles", user.getAuthorities().stream().map(a->a.getAuthority()).collect(Collectors.toList()))
				.sign(algorithm);
		
		String jwtRefreshToken=JWT.create()
				.withSubject(user.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis()+JWTUtil.EXPIRE_REFRESH_TOKEN))
				.withIssuer(request.getRequestURL().toString())
				.sign(algorithm);
		
		Map<String, String> idToken = new HashMap<>();
		idToken.put("access-token", jwtAccesToken);
		idToken.put("refresh-token", jwtRefreshToken);
		
		//indiquer au corp que les données contients du json
		response.setContentType("application/json");
		
		//cette fois on l'envois sous format json
		new ObjectMapper().writeValue(response.getOutputStream(), idToken);
		//response.setHeader("Authorization", idToken);
	}
}
