package org.sid.secservice.controllers;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.management.RuntimeErrorException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.sid.secservice.JWTUtil;
import org.sid.secservice.entities.AppRole;
import org.sid.secservice.entities.AppUser;
import org.sid.secservice.services.AccountService;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.Data;

@RestController
@RequestMapping("/users")
public class AccountRestController {

	private AccountService accountService;
	
	public AccountRestController(AccountService accountService) {
		this.accountService = accountService;
	}
	
	@GetMapping
	@PostAuthorize("hasAuthority('USER')")
	public List<AppUser> getAppUsers(){
		return accountService.listUsers();
	}
	
	@PostMapping
	@PostAuthorize("hasAuthority('ADMIN')")
	public AppUser addAppUser(@RequestBody AppUser appUser) {
		return accountService.addNewUser(appUser);
	}
	
	@PostMapping("/roles")
	@PostAuthorize("hasAuthority('ADMIN')")
	public AppRole addAppRole(@RequestBody AppRole appRole) {
		return accountService.addNewRole(appRole);
	}
	
	@PostAuthorize("hasAuthority('ADMIN')")
	@PostMapping("/rolestouser")
	public void addRoleToUser(@RequestBody RoleUserForm  roleUserForm) {
		this.accountService.AddRoleToUser(roleUserForm.getUsername(), roleUserForm.getRoleName());
	}
	
	
	//consulter le profile de l'utilisateur authentifié
	@GetMapping("/profiles")
	public AppUser profile(Principal principal) {
		return accountService.loadUserByUsername(principal.getName());
	}
	//faire le refresh token si le token access et perimé
	@GetMapping("/refreshToken")
	public Map<String, String> refreshToken(HttpServletRequest httpServletRequest,HttpServletResponse httpServletResponse) throws Exception{
		String authorizationToken = httpServletRequest.getHeader(JWTUtil.AUTH_HEADER);
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
				AppUser appUser = accountService.loadUserByUsername(username);
				String jwtAccesToken=JWT.create()
						.withSubject(appUser.getUsername())
						.withExpiresAt(new Date(System.currentTimeMillis()+JWTUtil.EXPIRE_ACCESS_TOKEN))
						.withIssuer(httpServletRequest.getRequestURL().toString())
						.withClaim("roles", appUser.getAppRoles().stream().map(a->a.getRoleName()).collect(Collectors.toList()))
						.sign(algorithm);
				
				Map<String, String> idToken = new HashMap<>();
				idToken.put("access-token", jwtAccesToken);
				idToken.put("refresh-token", jwt);
				 return idToken;
				//indiquer au corp que les données contients du json
				//httpServletResponse.setContentType("application/json");
				
				//cette fois on l'envois sous format json
				//new ObjectMapper().writeValue(httpServletResponse.getOutputStream(), idToken);
				//response.setHeader("Authorization", idToken);
			} catch (Exception e) {
				httpServletResponse.setHeader("error-massage",e.getMessage());
				httpServletResponse.sendError(403);
				return null;
			}
			
			
		}else {
			throw new RuntimeException("refresh token required");
		}
	}
}

@Data
class RoleUserForm{
	private String username;
	private String roleName;
}
