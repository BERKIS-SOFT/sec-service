package org.sid.secservice.services;

import java.util.List;

import javax.transaction.Transactional;

import org.sid.secservice.entities.AppRole;
import org.sid.secservice.entities.AppUser;
import org.sid.secservice.repository.AppRoleRepository;
import org.sid.secservice.repository.AppUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@Transactional
public class AccountServiceImpl implements AccountService{
	
	 private AppUserRepository appUserRepository;
	 private AppRoleRepository appRoleRepository;
	 private PasswordEncoder passwordEncoder;
	 

	public AccountServiceImpl(AppUserRepository appUserRepository, AppRoleRepository appRoleRepository,PasswordEncoder passwordEncoder) {
		this.appUserRepository = appUserRepository;
		this.appRoleRepository = appRoleRepository;
		this.passwordEncoder=passwordEncoder;
	}

	@Override
	public AppUser addNewUser(AppUser appUser) {
		appUser.setPassword(passwordEncoder.encode(appUser.getPassword()));
		appUserRepository.save(appUser);
		return appUser;
	}

	@Override
	public AppRole addNewRole(AppRole appRole) {
		appRoleRepository.save(appRole);
		return appRole;
	}

	@Override
	public void AddRoleToUser(String username, String roleName) {
		AppUser appUser = appUserRepository.findByUsername(username);
		AppRole appRole = appRoleRepository.findByRoleName(roleName);
		appUser.getAppRoles().add(appRole);
	}

	@Override
	public AppUser loadUserByUsername(String username) {
		AppUser appUser = appUserRepository.findByUsername(username);
		return appUser;
	}

	@Override
	public List<AppUser> listUsers() {
		List<AppUser> appUsers = appUserRepository.findAll();
		return appUsers;
	}

}
