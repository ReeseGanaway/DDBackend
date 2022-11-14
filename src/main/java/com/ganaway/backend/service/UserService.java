package com.ganaway.backend.service;

import com.ganaway.backend.model.User;
import com.ganaway.backend.model.UserRole;

import java.util.List;

public interface UserService {
    User saveUser(User user);
    UserRole saveRole(UserRole role);
    void setUserRole(String username, String roleName);
    User getUser(String username);
    List<User>getUsers();

}
