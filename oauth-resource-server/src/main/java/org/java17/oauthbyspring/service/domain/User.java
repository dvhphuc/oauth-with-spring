package org.java17.oauthbyspring.service.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;

@Data
public class User {
    private Long id;
    private String username;
    @JsonIgnore
    private String password;
}
