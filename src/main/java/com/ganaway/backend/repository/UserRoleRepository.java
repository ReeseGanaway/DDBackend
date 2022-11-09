package com.ganaway.backend.repository;

import com.ganaway.backend.model.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;

public interface
UserRoleRepository extends JpaRepository<UserRole, Long> {


        UserRole findByName(String Name);
}

