package org.sid.secservice;

import java.util.ArrayList;

import javax.management.relation.Role;

import org.sid.secservice.entities.AppRole;
import org.sid.secservice.entities.AppUser;
import org.sid.secservice.services.AccountService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled = true)//activer les security avec les annotations sur les methode
public class SecServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecServiceApplication.class, args);
	}
	
	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
		//bcrypt est plus puissant que md5
		//il utilise un hashage pas la cryptographie donc il est asymtrique
	}
	
	@Bean
	CommandLineRunner start(AccountService accountService) {
		return args->{
			
			accountService.addNewRole(new AppRole(null, "USER"));
			accountService.addNewRole(new AppRole(null, "ADMIN"));
			accountService.addNewRole(new AppRole(null, "CUSTOMER_MANAGER"));
			accountService.addNewRole(new AppRole(null, "PRODUCT_MANAGER"));
			accountService.addNewRole(new AppRole(null, "BILLS_MANAGER"));
			
			accountService.addNewUser(new AppUser(null, "admin", "1234", new ArrayList<>()));
			accountService.addNewUser(new AppUser(null, "user1", "1234", new ArrayList<>()));
			accountService.addNewUser(new AppUser(null, "user2", "1234", new ArrayList<>()));
			accountService.addNewUser(new AppUser(null, "user3", "1234", new ArrayList<>()));
			accountService.addNewUser(new AppUser(null, "user4", "1234", new ArrayList<>()));
			
			accountService.AddRoleToUser("user1", "USER");
			accountService.AddRoleToUser("admin", "USER");
			accountService.AddRoleToUser("admin", "ADMIN");
			accountService.AddRoleToUser("user2", "USER");
			accountService.AddRoleToUser("user2", "CUSTOMER_MANAGER");
			accountService.AddRoleToUser("user3", "USER");
			accountService.AddRoleToUser("user3", "PRODUCT_MANAGER");
			accountService.AddRoleToUser("user4", "USER");
			accountService.AddRoleToUser("user4", "BILLS_MANAGER");
			
			
		};
	}

}
