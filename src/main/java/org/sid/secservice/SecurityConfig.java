package org.sid.secservice;



import org.sid.secservice.filters.JwtAuthentificationFilter;
import org.sid.secservice.filters.JwtAutorizationFilter;
import org.sid.secservice.services.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig{
	
	private UserDetailsServiceImpl userDetailsServiceImpl;
	
	
	
	public SecurityConfig(UserDetailsServiceImpl userDetailsServiceImpl) {
		this.userDetailsServiceImpl = userDetailsServiceImpl;
	}

	@Autowired
	public void configure(AuthenticationManagerBuilder auth) throws Exception{
		//Après la creation de userdetailserviceIml
		auth.userDetailsService(userDetailsServiceImpl);
		
	}
	
	@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        
		//disactiver csrf pour les sessiona fin d'acceder a h2-console
		http.csrf().disable();
		
		//Ici je vais dire à spring d'utilser l'authentificaton stateless 
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		
		// disactiver la protection contre les frames afin d'acceder a h2-console uniquement
		http.headers().frameOptions().disable();
		
		//autoriser l'acces sans la securité de spring boot
		//http.authorizeHttpRequests().anyRequest().permitAll();
		//activer l'authentification statefull c à d via login standard
		//http.formLogin();
		
		//Autoriser l'acces aux url selectionne sans la sécurité
	    http.authorizeRequests().antMatchers("/h2-console/**","/users/refreshToken/**").permitAll();
		
		//tester queleques autorisations la première solution
		//http.authorizeRequests().antMatchers(HttpMethod.POST,"/users/**").hasAuthority("ADMIN");
		//http.authorizeRequests().antMatchers(HttpMethod.GET,"/users/**").hasAuthority("USER");
		
		
		//obliger l'authentification
		http.authorizeRequests().anyRequest().authenticated();
		http.addFilter(new JwtAuthentificationFilter(authenticationManagerBean(http.getSharedObject(AuthenticationConfiguration.class))));
        http.addFilterBefore(new JwtAutorizationFilter(), UsernamePasswordAuthenticationFilter.class);
		return http.build();
    }
	
	@Bean
	public AuthenticationManager authenticationManagerBean(AuthenticationConfiguration authenticationConfiguration) throws Exception {
	    return authenticationConfiguration.getAuthenticationManager();
	}
}
