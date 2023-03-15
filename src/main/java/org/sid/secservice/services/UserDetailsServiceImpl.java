package org.sid.secservice.services;

import java.util.ArrayList;
import java.util.Collection;

import org.sid.secservice.entities.AppUser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


@Service
public class UserDetailsServiceImpl implements UserDetailsService{
	
	private AccountService accountService;
	

	public UserDetailsServiceImpl(AccountService accountService) {
		this.accountService = accountService;
	}


	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		//quand l'utilsateur saisi un username je vais dire à spring ou il va chercher l'utilsateur
		AppUser appUser = accountService.loadUserByUsername(username);
		
		//convertir la collection des roles vers la collection de grantedAuthority de User spring
		Collection<GrantedAuthority> authorities = new ArrayList<>();
		appUser.getAppRoles().forEach(r->{
			authorities.add(new SimpleGrantedAuthority(r.getRoleName()));
		});
		
		return new User(appUser.getUsername(),appUser.getPassword(),authorities);
	}
	

}
