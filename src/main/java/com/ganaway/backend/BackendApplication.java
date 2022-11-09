package com.ganaway.backend;

import com.ganaway.backend.model.User;
import com.ganaway.backend.model.UserRole;
import com.ganaway.backend.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.HashSet;

@SpringBootApplication
public class BackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(BackendApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(UserService userService){
		return args -> {
			userService.saveRole(new UserRole(null, "USER"));
			userService.saveRole(new UserRole(null, "MANAGER"));
			userService.saveRole(new UserRole(null, "ADMIN"));
			userService.saveRole(new UserRole(null, "SUPER_ADMIN"));

			userService.saveUser(new User(null, "uzumaki", "uzu1", "u@gmail.com", new ArrayList<>(), new HashSet<>()));
			userService.saveUser(new User(null, "uchiha", "uch1", "uch@gmail.com", new ArrayList<>(), new HashSet<>()));
			userService.saveUser(new User(null, "hatake", "hat1", "h@gmail.com", new ArrayList<>(), new HashSet<>()));
			userService.saveUser(new User(null, "haruno", "har1", "har@gmail.com", new ArrayList<>(), new HashSet<>()));


			userService.setUserRole("uzumaki", "USER");
			userService.setUserRole("uzumaki", "MANAGER");
			userService.setUserRole("uchiha", "MANAGER");
			userService.setUserRole("hatake", "ADMIN");
			userService.setUserRole("haruno", "SUPER_ADMIN");
			userService.setUserRole("haruno", "ADMIN");
			userService.setUserRole("haruno", "USER");

		};
	}

}
