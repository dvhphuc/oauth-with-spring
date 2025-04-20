package org.java17.oauthbyspring.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/users")
public class UserController {

    public record User(String id, String name, String email) {
    }

    @GetMapping
    public User getUserInfo() {
        return new User("1", "John Doe", "john.doe@example.com");
    }
}
