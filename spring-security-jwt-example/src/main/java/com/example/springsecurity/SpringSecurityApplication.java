package com.example.springsecurity;

import com.example.springsecurity.entity.Role;
import com.example.springsecurity.entity.User;
import com.example.springsecurity.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class SpringSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(UserService userService) {
		return args -> {
			userService.saveRole(new Role(null, "ROLE_USER"));
			userService.saveRole(new Role(null, "ROLE_MANAGER"));
			userService.saveRole(new Role(null, "ROLE_ADMIN"));
			userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

			userService.saveUser(new User(null, "eoguddl1", "nicenicnic1@gmail.com", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "eoguddl2", "nicenicnic12@gmail.com", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "eoguddl3", "nicenicnic123@gmail.com", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "eoguddl4", "nicenicnic1234@gmail.com", "1234", new ArrayList<>()));

			userService.addRoleToUser("nicenicnic1@gmail.com", "ROLE_USER");
			userService.addRoleToUser("nicenicnic1@gmail.com", "ROLE_MANAGER");
			userService.addRoleToUser("nicenicnic12@gmail.com", "ROLE_MANAGER");
			userService.addRoleToUser("nicenicnic123@gmail.com", "ROLE_ADMIN");
			userService.addRoleToUser("nicenicnic1234@gmail.com", "ROLE_SUPER_ADMIN");
			userService.addRoleToUser("nicenicnic1234@gmail.com", "ROLE_ADMIN");
			userService.addRoleToUser("nicenicnic1234@gmail.com", "ROLE_USER");
		};
	}
}