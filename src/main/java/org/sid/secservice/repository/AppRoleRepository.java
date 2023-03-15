package org.sid.secservice.repository;

import org.sid.secservice.entities.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AppRoleRepository extends JpaRepository<AppRole, Long>{
	AppRole findByRoleName(String roleName);
}
