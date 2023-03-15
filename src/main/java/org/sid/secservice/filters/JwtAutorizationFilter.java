package org.sid.secservice.filters;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.sid.secservice.JWTUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

public class JwtAutorizationFilter extends OncePerRequestFilter{

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		//verifier si on demande pas le refresh token pour apsser le filtre
		//if faut la faire pour login
		if(request.getServletPath().equals("/users/refreshToken")) {
			filterChain.doFilter(request, response);
		}else {
			// filtrer chaque request et lire l'objet authirization du header
			String authorizationToken=request.getHeader(JWTUtil.AUTH_HEADER);
			
			if(authorizationToken!=null && authorizationToken.startsWith(JWTUtil.PREFIX)) {
				try {
					String jwt=authorizationToken.substring(JWTUtil.PREFIX.length());
					Algorithm algorithm=Algorithm.HMAC256(JWTUtil.SECRET);
					//creer un verificateur
					JWTVerifier jwtVerifier=JWT.require(algorithm).build();
					//verifier le token
					DecodedJWT decodedJWT=jwtVerifier.verify(jwt);
					//si il est bon je vais recuperer les données tels que user and roles etc
					String username=decodedJWT.getSubject();
					String[] roles=decodedJWT.getClaim("roles").asArray(String.class);
					Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
					for (String role : roles) {
						grantedAuthorities.add(new SimpleGrantedAuthority(role));
					}
					UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken=
							new UsernamePasswordAuthenticationToken(username,null,grantedAuthorities);
					
					SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
					//Maintenant je lui dire de passer au filtre suivant apres les verification
					filterChain.doFilter(request, response);
				} catch (Exception e) {
					response.setHeader("error-massage",e.getMessage());
					response.sendError(403);
				}
				
				
			}else {
				filterChain.doFilter(request, response);
			}
		}
	
		
	}

}
