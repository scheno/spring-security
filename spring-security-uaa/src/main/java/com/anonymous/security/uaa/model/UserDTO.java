package com.anonymous.security.uaa.model;

import lombok.Data;

/**
 * @author Aiden
 * @date 2020/5/7
 * @version 1.0
 **/
@Data
public class UserDTO {
    private String id;
    private String username;
    private String password;
    private String fullname;
    private String mobile;
}
