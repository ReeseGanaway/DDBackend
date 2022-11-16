package com.ganaway.backend.service;

import com.ganaway.backend.model.User;
import com.ganaway.backend.model.UserRole;
import com.ganaway.backend.repository.UserRepository;
import com.ganaway.backend.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Service @RequiredArgsConstructor @Transactional @Slf4j
public class UserServiceImplementation implements UserService, UserDetailsService {

    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public User saveUser(User user) {
        log.info("Saving new user {} to the database", user.getUsername());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    @Override
    public User signup(User user) {
        log.info("Saving new user {} to the database", user.getUsername());
        User usernameTaken = userRepository.findByUsername(user.getUsername());
        Optional<User> emailTaken = userRepository.findByEmail(user.getEmail());
        if(emailTaken.isPresent()){
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email already exists!");
        }
        if(usernameTaken != null){
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username already exists!");
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        UserRole userRole = userRoleRepository.findByName("USER");
        user.getUserRoles().add(userRole);
        return userRepository.save(user);
    }



    @Override
    public UserRole saveRole(UserRole role) {
        log.info("Saving new userRole {} to the database", role.getName());
        return userRoleRepository.save(role);
    }

    @Override
    public void setUserRole(String username, String roleName) {
        log.info("Adding new userRole {} to user {}", roleName, username);
        User user = userRepository.findByUsername(username);
        UserRole userRole = userRoleRepository.findByName(roleName);
        user.getUserRoles().add(userRole);
    }

    @Override
    public User getUser(String username) {
        log.info("Fetching user {} from the database",username);
        return userRepository.findByUsername(username);
    }

    @Override
    public List<User> getUsers() {
        log.info("Fetching all users");
        return userRepository.findAll();
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if(user == null){
            log.error("User {} not found in database", username);
            throw new UsernameNotFoundException("User not found in database");
        } else{
            log.error("User {} was found in database", username);
        }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getUserRoles().forEach(role -> {authorities.add(new SimpleGrantedAuthority(role.getName()));
        });
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);
    }
}
