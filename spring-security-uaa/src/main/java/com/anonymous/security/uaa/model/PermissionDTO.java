package com.anonymous.security.uaa.model;

import lombok.Data;

/**
 * @author Aiden
 * @date 2020/5/7
 * @version 1.0
 **/
@Data
public class PermissionDTO {

    private String id;
    private String code;
    private String description;
    private String url;
}
