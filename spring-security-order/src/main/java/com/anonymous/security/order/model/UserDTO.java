package com.anonymous.security.order.model;

import lombok.Data;

/**
 * @author Aiden
 * @date 2020/5/7
 */
@Data
public class UserDTO {

    /**
     * 用户id
     */
    private String id;
    /**
     * 用户名
     */
    private String username;

    /**
     * 手机号
     */
    private String mobile;

    /**
     * 姓名
     */
    private String fullname;

}
